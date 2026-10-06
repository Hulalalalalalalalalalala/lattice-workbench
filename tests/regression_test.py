#!/usr/bin/env python3
"""Automatic regression tests for the documented ``messagetag`` contract.

The point of these tests is to make any small change in *file reading* or in
*key interpretation* visibly break something. Expected tags therefore never
come from the program under test's own output; they rest on two independent
bases:

1. Published HMAC-SHA-256 vectors from RFC 4231 (section 4), which pre-date
   this project entirely. These include keys longer than the 64-byte SHA-256
   block size.
2. Values recomputed here with the Python standard-library ``hmac`` module
   (an implementation unrelated to the program/OpenSSL). Those computed
   values are additionally compared to hard-coded constants so that a
   fixture recipe can no longer be silently altered to match a broken
   implementation.

Two file-reading end conditions get dedicated coverage:

- Messages of exactly N * 65536 bytes (the read chunk size): the trailing
  zero-byte read at EOF is normal termination, and the tag must match the
  independently computed HMAC of every byte, so neither dropping nor
  doubling the final chunk -- nor reporting the clean end as a failure --
  can pass.
- A read error after a non-empty prefix has already been read, injected
  with the LD_PRELOAD shim in tests/read_fault_shim.cpp (built by CMake,
  or compiled on the fly as a fallback): the run must exit 1 with empty
  stdout and a read-error message, never a partial-message result. Both
  ``tag`` and ``verify`` are checked this way.

Result *output* gets the same treatment: computing the right tag (or a
passing comparison) is not success unless the complete result line has
actually been written to stdout. A second LD_PRELOAD shim
(tests/write_fault_shim.cpp) forces standard output to accept a chosen
number of bytes and then fail (EPIPE/ENOSPC/EIO), and a real pipe whose
read end is closed (filled to capacity first, so the writer blocks and is
woken with EPIPE rather than racing the close) proves the process exits 1
instead of dying from SIGPIPE. Both commands must then show one
"standard output write failed" line on stderr and must not leak the key,
the supplied tag or the recomputed tag, print usage, or exit 0 on the
strength of the residual prefix already delivered.

Recoverable output conditions are pinned separately, because they are
*not* failures. The same shim also has a scripted mode that returns
EINTR for a finite number of write(2) calls and/or accepts only partial
byte counts, before (or interleaved with) calls that go through
normally; the tag run must still exit 0 with exactly the correct 64-hex
line plus one newline, and a passed verification with exactly "OK\\n",
with empty stderr in either case. The interruption must be covered both
before the first byte and after a non-empty prefix -- and in particular
after the whole 64-character tag (or "OK") is already out with only the
trailing newline left: the command must neither end early nor replay the
accepted prefix on recovery. A permanent EPIPE/ENOSPC/EIO that arrives
only after such a recoverable stretch keeps the failure contract above
(exactly the prefix actually delivered, one output-write diagnostic).

The ``verify`` suite additionally pins: success prints exactly ``OK\\n``;
a tag that fails to authenticate gives exit 3 with empty stdout and a
diagnostic that neither names a cause nor leaks the recomputed tag, a
matching prefix or the key; the supplied tag must be exactly 64 hex
characters (the ``tag`` output with its trailing newline removed, no new
encapsulation); and parameter format is checked before the file is opened.

Usage:

    python3 tests/regression_test.py /path/to/messagetag \
        [/path/to/libread_fault_shim.so] \
        [/path/to/libwrite_fault_shim.so]
"""

import hashlib
import hmac as py_hmac
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

# ---------------------------------------------------------------------------
# Fixture recipes
# ---------------------------------------------------------------------------

LARGE_LEN = 2 * 65536 + 123          # > 64 KiB and not a multiple of 64 KiB
LARGE_KEY_HEX = "0123456789abcdef" * 4   # 32-byte key

READ_CHUNK = 65536                   # the program's documented read chunk


def large_bytes():
    """131195 bytes whose value depends on every position: two whole 64 KiB
    read chunks plus a 123-byte tail. Dropping, repeating or reordering any
    byte changes the tag."""
    return bytes((i * 31 + 7) % 256 for i in range(LARGE_LEN))


def stream_bytes(n):
    """First n bytes of a position-dependent byte stream (distinct recipe
    from large_bytes). Used for messages whose length is an exact multiple
    of the 64 KiB read chunk, plus one-byte-off neighbours."""
    return bytes((i * 17 + 5) % 256 for i in range(n))


# ---------------------------------------------------------------------------
# Hard-coded expected tags
#
# RFC 4231 vectors are copied verbatim from the RFC and are the primary
# published anchor. The remaining constants were generated independently with
# Python's hmac/hashlib; every constant is re-derived at runtime below (see
# check_constants_match_recipes) so a typo here fails the suite rather than
# silently weakening it.
# ---------------------------------------------------------------------------

RFC_4231_VECTORS = [
    # Case 1: normal key, normal message.
    ("0b" * 20, b"Hi There",
     "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
    # Case 2.
    ("4a656665", b"what do ya want for nothing?",
     "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
    # Case 6: 131-byte key (> 64-byte block size); key must be hashed first.
    ("aa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First",
     "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
    # Case 7: same over-long key plus over-block-size data.
    ("aa" * 131,
     b"This is a test using a larger than block-size key and a larger than "
     b"block-size data. The key needs to be hashed before being used by the "
     b"HMAC algorithm.",
     "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
]

# (fixture name, key hex as given on the command line, message bytes, tag)
PROJECT_VECTORS = [
    ("empty",         "0b" * 20, b"",
     "999a901219f032cd497cadb5e6051e97b6a29ab297bd6ae722bd6062a2f59542"),
    # README worked example: key bytes 00 01, "hello\n".
    ("hello_lf",      "0001", b"hello\n",
     "307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11a77b4d5d"),
    # Same key, message WITHOUT trailing newline: a different, fixed tag.
    ("hello",         "0001", b"hello",
     "ee44e44a606a62df24b198d7130faa42a53e2aa5db4133210fd7c657aa7bb6ab"),
    ("hello_crlf",    "0001", b"hello\r\n",
     "b8e1328429ccfe61593045c02ebbe9f7234262a956c65c83d2b97bfeca15419f"),
    ("hello_cr",      "0001", b"hello\r",
     "b8e574d37a35bbc33ea484e2b055f2bb2ab2fc3f33eaf22b8c33b6c794955397"),
    # A NUL byte in the middle; the bytes after it must authenticate too.
    ("nul",           "0001", b"\x00bytes-after-nul",
     "50da50e788e0ecda4126d1ac5752a88c0ab5fc4ce1dda87cb7d32fa34fd5c5f6"),
    ("nul_truncated", "0001", b"\x00bytes-after-nu",
     "f2a323782bd9b42cb149e211618ef6c91ddadf3ae6452b4a68911e28fac4245b"),
    ("nul_upperword", "0001", b"\x00bytes-after-NUL",
     "a77ff5a06480bb067ed9f5fe4dcfb7f8edb58e3094f7ac7176f6f8702a7f40f2"),
    ("lf_in_middle",  "0001", b"a\nb",
     "8d369e59af6d8f1ecfc881674718a6c3b6ce6e3af4c823b25bb6840163efc0cc"),
    ("cr_in_middle",  "0001", b"a\rb",
     "85d4d36b627d8ae2c32d93af7de75ee232fd4395816c9773acf744b07f884ab3"),
    # Over-long key (65 bytes) that STARTS with a zero byte: exercises the
    # "hash the key" path while proving that leading zero key bytes survive
    # both hex decoding and key normalization.
    ("empty",         "00" + "ab" * 64, b"",
     "fcf1b92de29141015920abdc2be4fc826b16d17b5092435df4c90ea286cbae4f"),
    ("nul",           "00" + "ab" * 64, b"\x00bytes-after-nul",
     "a149b17e873c5fe3710bb41edb28f8151cc78977712647f259a5ede51624416c"),
    # Upper/lower-case hex representation of the same key bytes.
    ("hello",         "DEADBEEF", b"hello",
     "297a715da8a2b93f287fd5e6e7d4764bc3e899df7556d58889a4f986656c8009"),
    # Whole large file and targeted mutations of it.
    ("large",         LARGE_KEY_HEX, large_bytes(),
     "d524cb7fca18676b75e28f2bb79b9a80718ecc589328bc2288192439f3e090d7"),
    ("large_prefix",  LARGE_KEY_HEX, large_bytes()[:-1],
     "01d094d78b378d3aaa0d883c95ac843c41adfca1a2c4e9fb6ee66f5ca394444f"),
    ("large_lastbyte", LARGE_KEY_HEX,
     large_bytes()[:-1] + bytes([large_bytes()[-1] ^ 0x01]),
     "8de6798693c8afd4e1fa56b1248779a1d9ed16684e47a14d74fe4982a016f393"),
]

# large_mid: flip a byte inside the second 64 KiB chunk (offset 70000).
_mid_msg = bytearray(large_bytes())
_mid_msg[70000] ^= 0xFF
PROJECT_VECTORS.append(
    ("large_mid", LARGE_KEY_HEX, bytes(_mid_msg),
     "4b27ce3500f1809311e794fd10e2e4afc4278ebd11435835746a13f7fb41aa2f"))

# Messages whose length is an exact multiple of the 64 KiB read chunk: the
# final read returns 0 bytes at EOF, which is normal termination, not a
# read failure, and the last full chunk must be authenticated exactly once
# (neither dropped nor fed twice). The one-byte-off neighbours pin the
# boundary from both sides. All tags computed independently with Python's
# hmac/hashlib and re-derived at runtime by test_00.
PROJECT_VECTORS += [
    ("block1",       LARGE_KEY_HEX, stream_bytes(1 * READ_CHUNK),
     "1a7f32684b691064982eb67a0c0d175f11a13d95f8e75185f425c7d7a2b77d66"),
    ("block2",       LARGE_KEY_HEX, stream_bytes(2 * READ_CHUNK),
     "f6f09c1fe5588e2f7c0196783cbe145c1f4f2fbeba87b156816cda9f90f6e154"),
    ("block3",       LARGE_KEY_HEX, stream_bytes(3 * READ_CHUNK),
     "2ee751a6f10074ad024989f42bd8f08bcbf90447226503731f194923344891da"),
    ("block1_minus", LARGE_KEY_HEX, stream_bytes(READ_CHUNK - 1),
     "8d20c29e4606cd0d0aa115b507c7ebb9912354ec44d6793b2a4112237cdb8c0e"),
    ("block1_plus",  LARGE_KEY_HEX, stream_bytes(READ_CHUNK + 1),
     "df45b0a2bfba857c7aaee155f1f5677d2e506b6f008774caf3e5d88f940ec9cf"),
]

TAG_RE = re.compile(rb"\A[0-9a-f]{64}\n\Z")


def expected_hmac(key_hex, message):
    return py_hmac.new(bytes.fromhex(key_hex), message,
                       hashlib.sha256).hexdigest()


def find_fault_shim(shim_path, exe, tmpdir, src_name, lib_names):
    """Locate (or, as a fallback, build) an LD_PRELOAD fault shim.

    ``src_name`` is the source file next to this script (e.g.
    read_fault_shim.cpp) and ``lib_names`` are the built shared-object
    names to look for beside the executable. Returns None when no shim is
    available; the caller then skips loudly instead of silently losing
    coverage. Shared by the tag and verify suites so both commands prove
    they refuse to produce a result from a partially read message, and
    that a partially written result is a failure rather than success."""
    candidates = []
    if shim_path:
        candidates.append(shim_path)
    exe_dir = os.path.dirname(exe)
    candidates += [os.path.join(exe_dir, name) for name in lib_names]
    for path in candidates:
        if os.path.isfile(path):
            return path
    # Direct invocation without a CMake build of the shim: compile it
    # from next to this script if a C++ compiler is available.
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), src_name)
    compiler = shutil.which("c++") or shutil.which("g++") \
        or shutil.which("clang++")
    if os.path.isfile(src) and compiler:
        out = os.path.join(tmpdir, lib_names[0])
        built = subprocess.run(
            [compiler, "-shared", "-fPIC", "-O2", "-o", out, src,
             "-ldl"], capture_output=True)
        if built.returncode == 0 and os.path.isfile(out):
            return out
    return None


def find_read_fault_shim(shim_path, exe, tmpdir):
    """The read shim used to exercise "open succeeded, partial content
    read, then the read failed"."""
    return find_fault_shim(
        shim_path, exe, tmpdir, "read_fault_shim.cpp",
        ["libread_fault_shim.so", "read_fault_shim.so"])


def find_write_fault_shim(shim_path, exe, tmpdir):
    """The write shim used to exercise "some result bytes delivered, then
    the standard-output write failed", including mid-line failure."""
    return find_fault_shim(
        shim_path, exe, tmpdir, "write_fault_shim.cpp",
        ["libwrite_fault_shim.so", "write_fault_shim.so"])


# errno values the write-fault shim is driven with, covering the three
# situations the contract names: a closed downstream pipe, an exhausted
# target, and a device-level I/O error.
FAULT_EPIPE = 32
FAULT_ENOSPC = 28
FAULT_EIO = 5

WRITE_FAIL_MARKER = b"standard output write failed"
USAGE_MARKER = b"Usage: messagetag"


def run_with_write_fault(argv, shim, after, fail_errno=FAULT_EPIPE):
    """Run the full command ``argv`` (argv[0] is the messagetag path) with
    standard output forced to accept exactly ``after`` bytes and then fail
    with ``fail_errno`` (via the write-fault shim). The diagnostic
    messagetag then emits goes to stderr, which the shim leaves alone, so it
    is still observable."""
    env = dict(os.environ)
    env["LD_PRELOAD"] = shim
    env["MESSAGETAG_WRITE_FAULT_FD"] = "1"
    env["MESSAGETAG_WRITE_FAULT_AFTER"] = str(after)
    env["MESSAGETAG_WRITE_FAULT_ERRNO"] = str(fail_errno)
    return subprocess.run(argv, capture_output=True, env=env)


def run_with_write_script(argv, shim, script):
    """Run ``argv`` under the write-fault shim in scripted mode: ``script``
    is a comma-separated list with one event per write(2) call on stdout --
    "eintr" (the call returns -1/EINTR without delivering a byte),
    "short:<n>" (the call accepts at most n bytes), "pass" (pass through to
    the real write), "fail:<errno>" (sticky permanent failure). When the
    script is exhausted, later writes pass through, which models a writer
    that is temporarily difficult (interrupted, accepting partial counts)
    and then recovers. Bytes always flow through the real write() in their
    original order, so a correct continue/retry loop delivers the line
    exactly once."""
    env = dict(os.environ)
    env["LD_PRELOAD"] = shim
    env["MESSAGETAG_WRITE_FAULT_FD"] = "1"
    env["MESSAGETAG_WRITE_FAULT_SCRIPT"] = script
    # SCRIPT must take precedence; make sure no stale legacy settings leak
    # in from the surrounding environment.
    env.pop("MESSAGETAG_WRITE_FAULT_AFTER", None)
    env.pop("MESSAGETAG_WRITE_FAULT_ERRNO", None)
    return subprocess.run(argv, capture_output=True, env=env)


def assert_stdout_write_failure(case, result, full_line, after,
                                secret_hexes=(), label=""):
    """The shared contract for a result that could not be fully written:

    - exit code 1 (never 0, and never death by SIGPIPE -> a negative code);
    - exactly the delivered prefix on stdout -- strictly shorter than the
      whole line, with no trailing newline, so it cannot read as a complete
      tag or as "OK";
    - exactly one stderr line that names the output-write failure, with no
      usage text and no echo of the key, supplied tag or recomputed tag.
    """
    case.assertEqual(
        result.returncode, 1,
        f"{label}: an incomplete result output must exit 1, got "
        f"{result.returncode}; stdout={result.stdout!r} "
        f"stderr={result.stderr!r}")
    case.assertEqual(
        result.stdout, full_line[:after],
        f"{label}: only the accepted prefix may be present (no restart or "
        f"retransmission), got {result.stdout!r}")
    case.assertLess(
        len(result.stdout), len(full_line),
        f"{label}: residual bytes must be shorter than the full line")
    case.assertFalse(
        result.stdout.endswith(b"\n"),
        f"{label}: residual output must not carry the trailing newline that "
        f"would make it look complete: {result.stdout!r}")
    case.assertNotRegex(
        result.stdout, TAG_RE,
        f"{label}: residual bytes must not look like a complete tag")
    case.assertEqual(
        result.stderr.count(b"\n"), 1,
        f"{label}: exactly one stderr line, got {result.stderr!r}")
    lower = result.stderr.lower()
    case.assertIn(WRITE_FAIL_MARKER, lower,
                  f"{label}: diagnostic must name the output-write failure")
    case.assertNotIn(USAGE_MARKER, result.stderr,
                     f"{label}: no usage text may accompany the failure")
    case.assertNotRegex(
        result.stderr, rb"(?i)[0-9a-f]{64}",
        f"{label}: stderr must not contain a recomputed/echoed tag")
    for secret in secret_hexes:
        if secret:
            case.assertNotIn(secret.lower().encode(), lower,
                             f"{label}: secret material must not be echoed")


def run_with_closed_stdout(argv):
    """Run the full command ``argv`` (argv[0] is the messagetag path) with
    stdout aimed at a pipe that is (a) filled to capacity while still
    blocking, then (b) has its only read end closed while the writer is
    blocked. The result write therefore wakes up with
    EPIPE: a program relying on the default disposition dies from SIGPIPE
    (negative return code), whereas the required behaviour is exit 1 with a
    diagnostic. Filling first is what makes this deterministic -- an empty
    65-byte line otherwise fits in the pipe buffer and the process can exit
    0 before noticing the close."""
    r, w = os.pipe()
    try:
        # Fill from the parent without blocking; stop as soon as the pipe
        # holds all it can. The write end is restored to blocking mode
        # before the child inherits it (O_NONBLOCK is shared across dups).
        os.set_blocking(w, False)
        filler = b"x" * 65536
        while True:
            try:
                if os.write(w, filler) == 0:
                    break
            except BlockingIOError:
                break
        os.set_blocking(w, True)
        proc = subprocess.Popen(argv, stdout=w, stderr=subprocess.PIPE)
    finally:
        # The child has its own dup of the write end; release the parent's
        # copy and, crucially, the only read end. The child's blocked write
        # then wakes with EPIPE (rather than waiting for a reader that will
        # never come).
        os.close(w)
        os.close(r)
    try:
        try:
            _, stderr = proc.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise AssertionError("child blocked instead of handling EPIPE")
        return proc.returncode, stderr
    finally:
        if proc.poll() is None:
            proc.kill()


def assert_closed_pipe_failure(case, rc, stderr, secret_hexes=(), label=""):
    """A closed downstream pipe must end as an ordinary exit-1 write
    failure, not signal termination and not success."""
    case.assertEqual(
        rc, 1,
        f"{label}: closed pipe must give exit 1, not signal death or 0; "
        f"rc={rc}")
    case.assertEqual(stderr.count(b"\n"), 1,
                     f"{label}: one stderr line, got {stderr!r}")
    case.assertIn(WRITE_FAIL_MARKER, stderr.lower())
    case.assertNotIn(USAGE_MARKER, stderr)
    case.assertNotRegex(stderr, rb"(?i)[0-9a-f]{64}")
    for secret in secret_hexes:
        if secret:
            case.assertNotIn(secret.lower().encode(), stderr.lower())


class TagRegression(unittest.TestCase):
    exe = None
    tmpdir = None
    shim_path = None   # optional CLI argument: read-fault shim
    shim = None
    write_shim_path = None  # optional CLI argument: write-fault shim
    write_shim = None

    @classmethod
    def setUpClass(cls):
        if not cls.exe or not os.path.isfile(cls.exe):
            raise RuntimeError("messagetag executable not found: %r" % cls.exe)
        cls.tmpdir = tempfile.mkdtemp(prefix="messagetag-regress-")
        # Materialize every named fixture exactly once from its recipe.
        fixtures = {}
        for name, _key, message, _tag in PROJECT_VECTORS:
            fixtures.setdefault(name, message)
        # Same content under different paths (different name and directory
        # depth) for the path-independence check.
        fixtures["hello_lf_copy"] = b"hello\n"
        for rel, data in fixtures.items():
            path = os.path.join(cls.tmpdir, rel + ".bin")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(data)
        os.makedirs(os.path.join(cls.tmpdir, "sub", "dir"), exist_ok=True)
        with open(os.path.join(cls.tmpdir, "sub", "dir", "othername.bin"),
                  "wb") as f:
            f.write(b"hello\n")
        cls.fixtures = fixtures
        cls.shim = cls._find_read_fault_shim()
        cls.write_shim = find_write_fault_shim(
            cls.write_shim_path, cls.exe, cls.tmpdir)

    @classmethod
    def _find_read_fault_shim(cls):
        return find_read_fault_shim(cls.shim_path, cls.exe, cls.tmpdir)

    @classmethod
    def tearDownClass(cls):
        if cls.tmpdir and os.path.isdir(cls.tmpdir):
            shutil.rmtree(cls.tmpdir, ignore_errors=True)

    # -- helpers ------------------------------------------------------------

    def fixture(self, name):
        return os.path.join(self.tmpdir, name + ".bin")

    def run_tag(self, key_hex, path, *extra):
        return subprocess.run(
            [self.exe, "tag", "--key-hex", key_hex, "--file", path, *extra],
            capture_output=True)

    def assertTagSuccess(self, result, expected_tag, label=""):
        self.assertEqual(
            result.returncode, 0,
            f"{label}: expected exit 0, got {result.returncode}; "
            f"stderr={result.stderr!r}")
        self.assertEqual(result.stderr, b"",
                         f"{label}: stderr must be empty, got {result.stderr!r}")
        self.assertRegex(result.stdout, TAG_RE,
                         f"{label}: stdout must be 64 lowercase hex chars + "
                         f"newline, got {result.stdout!r}")
        self.assertEqual(result.stdout, expected_tag.encode() + b"\n",
                         f"{label}: wrong tag")

    # -- independent-basis sanity check ------------------------------------

    def test_00_constants_match_recipes_and_stdlib(self):
        """The hard-coded constants must equal Python stdlib HMAC over the
        recipes; the RFC constants must match it too. This makes a typo in a
        constant fail loudly instead of anchoring the suite to the typo."""
        for _name, key, message, tag in PROJECT_VECTORS:
            self.assertEqual(expected_hmac(key, message), tag)
        for key, message, tag in RFC_4231_VECTORS:
            self.assertEqual(expected_hmac(key, message), tag)

    # -- published standard vectors ----------------------------------------

    def test_01_rfc4231_published_vectors(self):
        """RFC 4231 cases 1, 2, 6, 7 as file messages. Cases 6/7 use keys
        longer than the SHA-256 block size, pinning the standard key-hashing
        behavior rather than merely run-to-run reproducibility."""
        for i, (key, message, tag) in enumerate(RFC_4231_VECTORS, 1):
            with self.subTest(rfc_case=i, keylen=len(key) // 2):
                path = os.path.join(self.tmpdir, f"rfc{i}.bin")
                with open(path, "wb") as f:
                    f.write(message)
                self.assertTagSuccess(self.run_tag(key, path), tag,
                                      f"RFC 4231 case {i}")

    # -- file content handling ---------------------------------------------

    def test_10_project_vectors_exact_tags(self):
        for name, key, _message, tag in PROJECT_VECTORS:
            with self.subTest(fixture=name):
                self.assertTagSuccess(
                    self.run_tag(key, self.fixture(name)), tag, name)

    def test_11_empty_file_is_valid_message(self):
        result = self.run_tag("0b" * 20, self.fixture("empty"))
        self.assertTagSuccess(
            result, "999a901219f032cd497cadb5e6051e97b"
                    "6a29ab297bd6ae722bd6062a2f59542")

    def test_12_nul_bytes_after_nul_participate(self):
        base = self.run_tag("0001", self.fixture("nul")).stdout
        # Changing only bytes *after* the NUL must change the tag...
        self.assertNotEqual(
            base, self.run_tag("0001", self.fixture("nul_truncated")).stdout)
        self.assertNotEqual(
            base, self.run_tag("0001", self.fixture("nul_upperword")).stdout)
        # ...and the NUL byte itself participates as well.
        with open(os.path.join(self.tmpdir, "nul_replaced.bin"), "wb") as f:
            f.write(b"\x01bytes-after-nul")
        self.assertNotEqual(
            base, self.run_tag("0001", os.path.join(
                self.tmpdir, "nul_replaced.bin")).stdout)

    def test_13_trailing_newline_is_part_of_message(self):
        with_nl = self.run_tag("0001", self.fixture("hello_lf")).stdout
        without_nl = self.run_tag("0001", self.fixture("hello")).stdout
        self.assertNotEqual(with_nl, without_nl)

    def test_14_newline_forms_are_not_normalized(self):
        lf = self.run_tag("0001", self.fixture("hello_lf")).stdout
        crlf = self.run_tag("0001", self.fixture("hello_crlf")).stdout
        cr = self.run_tag("0001", self.fixture("hello_cr")).stdout
        lf_mid = self.run_tag("0001", self.fixture("lf_in_middle")).stdout
        cr_mid = self.run_tag("0001", self.fixture("cr_in_middle")).stdout
        self.assertEqual(len({lf, crlf, cr, lf_mid, cr_mid}), 5,
                         "LF/CRLF/CR must authenticate as distinct bytes")

    def test_15_large_file_every_byte_counts(self):
        data = large_bytes()
        self.assertEqual(len(data), LARGE_LEN)
        self.assertEqual(LARGE_LEN % 65536, 123)  # recipe guard
        full = self.run_tag(LARGE_KEY_HEX, self.fixture("large")).stdout
        # Missing the 123-byte tail changes the result...
        self.assertNotEqual(
            full, self.run_tag(LARGE_KEY_HEX,
                               self.fixture("large_prefix")).stdout)
        # ...a flip at the very end...
        self.assertNotEqual(
            full, self.run_tag(LARGE_KEY_HEX,
                               self.fixture("large_lastbyte")).stdout)
        # ...and a flip inside the second 64 KiB chunk are all detected.
        self.assertNotEqual(
            full, self.run_tag(LARGE_KEY_HEX,
                               self.fixture("large_mid")).stdout)

    def test_16_path_is_not_part_of_message(self):
        a = self.run_tag("0001", self.fixture("hello_lf"))
        b = self.run_tag("0001", self.fixture("hello_lf_copy"))
        c = self.run_tag("0001",
                         os.path.join(self.tmpdir, "sub", "dir",
                                      "othername.bin"))
        for r in (a, b, c):
            self.assertTagSuccess(
                r, "307a25cbcb6cbca48f5dd2b05fd9174c"
                   "0cf17580f4ea8dd667092f11a77b4d5d")
        self.assertEqual(a.stdout, b.stdout)
        self.assertEqual(a.stdout, c.stdout)

    def test_17_exact_chunk_multiple_is_normal_eof(self):
        """A message of exactly N * 65536 bytes ends with a read that
        returns 0 bytes. That is normal termination, not a read failure:
        the exit code must be 0 and the tag must cover every byte of every
        chunk exactly once. The expected tags are the independently
        computed constants in PROJECT_VECTORS (re-derived via the stdlib
        in test_00), so duplicating or dropping the final chunk -- or
        reporting the clean end as an error -- fails here."""
        expected = {name: tag for name, _key, _msg, tag in PROJECT_VECTORS}
        tags = {}
        for name in ("block1", "block2", "block3"):
            with self.subTest(fixture=name):
                result = self.run_tag(LARGE_KEY_HEX, self.fixture(name))
                self.assertTagSuccess(result, expected[name], name)
                tags[name] = result.stdout
        # Distinct lengths must give distinct tags; in particular the
        # 2-chunk and 3-chunk tags must not equal the 1-chunk tag (which
        # is what a dropped or short-circuited tail would produce).
        self.assertEqual(len(set(tags.values())), 3)
        # The one-byte-off neighbours pin the boundary itself: the last
        # byte of the chunk participates, and no phantom 65537th byte is
        # read past the end.
        for name in ("block1_minus", "block1_plus"):
            with self.subTest(fixture=name):
                self.assertTagSuccess(
                    self.run_tag(LARGE_KEY_HEX, self.fixture(name)),
                    expected[name], name)
        self.assertNotEqual(tags["block1"],
                            self.run_tag(LARGE_KEY_HEX,
                                         self.fixture("block1_minus")).stdout)
        self.assertNotEqual(tags["block1"],
                            self.run_tag(LARGE_KEY_HEX,
                                         self.fixture("block1_plus")).stdout)

    # -- key interpretation -------------------------------------------------

    def test_20_hex_case_insensitive(self):
        lower = self.run_tag("deadbeef", self.fixture("hello"))
        upper = self.run_tag("DEADBEEF", self.fixture("hello"))
        mixed = self.run_tag("DeAdBeEf", self.fixture("hello"))
        for r in (lower, upper, mixed):
            self.assertTagSuccess(
                r, "297a715da8a2b93f287fd5e6e7d4764b"
                   "c3e899df7556d58889a4f986656c8009")
        self.assertEqual(lower.stdout, upper.stdout)
        self.assertEqual(lower.stdout, mixed.stdout)

    def test_21_leading_zero_bytes_preserved(self):
        # "0001" (bytes 00 01) must not collapse to "01" (byte 01).
        two_bytes = self.run_tag("0001", self.fixture("hello_lf")).stdout
        one_byte = self.run_tag("01", self.fixture("hello_lf")).stdout
        three_bytes = self.run_tag("000001",
                                   self.fixture("hello_lf")).stdout
        self.assertEqual(len({two_bytes, one_byte, three_bytes}), 3)
        # And the key must not authenticate as its ASCII hex text either.
        ascii_key = b"0001".hex()  # hex encoding of the *characters* "0001"
        ascii_tag = self.run_tag(ascii_key, self.fixture("hello_lf")).stdout
        self.assertNotEqual(two_bytes, ascii_tag)

    def test_22_leading_zero_in_overlong_key(self):
        # 65-byte key starting with 00: the zero byte must survive both hex
        # decode and the >block-size key-hashing path.
        r = self.run_tag("00" + "ab" * 64, self.fixture("empty"))
        self.assertTagSuccess(
            r, "fcf1b92de29141015920abdc2be4fc82"
               "6b16d17b5092435df4c90ea286cbae4f")
        # Stripping that leading zero (64 bytes, different key) differs...
        self.assertNotEqual(
            r.stdout,
            self.run_tag("ab" * 64, self.fixture("empty")).stdout)
        # ...and does not equal the tag for a 65-byte key with 01 first.
        self.assertNotEqual(
            r.stdout,
            self.run_tag("01" + "ab" * 64, self.fixture("empty")).stdout)

    def test_23_option_order_interchangeable(self):
        a = subprocess.run(
            [self.exe, "tag", "--file", self.fixture("hello_lf"),
             "--key-hex", "0001"], capture_output=True)
        self.assertTagSuccess(
            a, "307a25cbcb6cbca48f5dd2b05fd9174c"
               "0cf17580f4ea8dd667092f11a77b4d5d")

    # -- error contract -----------------------------------------------------

    def assertKeyRejected(self, bad_key, echo_check=True):
        result = self.run_tag(bad_key, self.fixture("hello_lf"))
        self.assertEqual(result.returncode, 2,
                         f"key {bad_key!r}: expected exit 2, got "
                         f"{result.returncode}")
        self.assertEqual(result.stdout, b"",
                         f"key {bad_key!r}: stdout must be empty")
        self.assertNotEqual(result.stderr, b"",
                            f"key {bad_key!r}: an error message is required")
        self.assertNotRegex(
            result.stderr, rb"[0-9a-f]{64}",
            f"key {bad_key!r}: stderr must not look like a valid tag")
        # The submitted key must not be spliced into the error message. This
        # is only checked with distinctive key strings: a one-character key
        # can collide with ordinary words in the fixed message, which would
        # prove nothing about echoing.
        if echo_check:
            self.assertNotIn(
                bad_key.encode(), result.stderr,
                f"key {bad_key!r}: the submitted key must not be echoed back")

    def test_30_invalid_key_odd_length(self):
        self.assertKeyRejected("abc")          # odd number of hex chars
        self.assertKeyRejected("0b0c0")
        self.assertKeyRejected("fedcba987")
        self.assertKeyRejected("a", echo_check=False)
        self.assertKeyRejected("", echo_check=False)  # empty key invalid too

    def test_31_invalid_key_non_hex_characters(self):
        self.assertKeyRejected("zz")
        self.assertKeyRejected("0x01")         # 0x prefix not accepted
        self.assertKeyRejected("ab cd")        # embedded whitespace
        self.assertKeyRejected("deadbeef\n")
        self.assertKeyRejected("abg0")

    def test_32_missing_required_options_exit_2(self):
        r = subprocess.run([self.exe, "tag"], capture_output=True)
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, b"")
        r = subprocess.run(
            [self.exe, "tag", "--file", self.fixture("hello_lf")],
            capture_output=True)
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, b"")
        r = subprocess.run(
            [self.exe, "tag", "--bogus", "x"], capture_output=True)
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, b"")

    def test_35_option_name_after_option_is_missing_value(self):
        """A value-taking option immediately followed by one of this
        command's option names (including the same name again) is a
        missing-value usage error: exit 2, empty stdout, the diagnostic
        names the option and gives the tag usage. The following option
        must not be consumed as a value, so no file read is attempted."""
        path = self.fixture("hello_lf")
        invocations = [
            # The reported case: the second --file is not a file name.
            [self.exe, "tag", "--key-hex", "0001", "--file", "--file"],
            [self.exe, "tag", "--key-hex", "--file", path],
            [self.exe, "tag", "--file", "--key-hex", "0001"],
            [self.exe, "tag", "--key-hex", "--key-hex", "0001",
             "--file", path],
            [self.exe, "tag", "--file", path, "--key-hex"],
        ]
        for argv in invocations:
            with self.subTest(argv=argv[2:]):
                r = subprocess.run(argv, capture_output=True)
                self.assertEqual(r.returncode, 2,
                                 f"{argv[2:]}: expected exit 2, got "
                                 f"{r.returncode}; stderr={r.stderr!r}")
                self.assertEqual(r.stdout, b"")
                self.assertIn(b"requires a value", r.stderr)
                self.assertIn(b"Usage: messagetag tag", r.stderr)

    def test_36_dash_named_files_and_empty_values(self):
        """Only an exact option-name match triggers the missing-value
        rule. A token that merely starts with a dash ("--notes") is still
        a file path; a file literally named "--file" stays usable via an
        explicit path prefix; and an explicitly empty value keeps its own
        diagnostic instead of becoming a missing-value error."""
        hello_tag = ("307a25cbcb6cbca48f5dd2b05fd9174c"
                     "0cf17580f4ea8dd667092f11a77b4d5d")
        # "--notes" after --file is a path, not an option.
        with open(os.path.join(self.tmpdir, "--notes"), "wb") as f:
            f.write(b"hello\n")
        r = subprocess.run(
            [self.exe, "tag", "--key-hex", "0001", "--file", "--notes"],
            capture_output=True, cwd=self.tmpdir)
        self.assertTagSuccess(r, hello_tag, "file named --notes")

        # A file literally named "--file" works via ./--file ...
        with open(os.path.join(self.tmpdir, "--file"), "wb") as f:
            f.write(b"hello\n")
        r = subprocess.run(
            [self.exe, "tag", "--key-hex", "0001", "--file", "./--file"],
            capture_output=True, cwd=self.tmpdir)
        self.assertTagSuccess(r, hello_tag, "file named --file via ./")

        # ... but the bare "--file" is a missing-value error even though
        # a file by that name exists right there.
        r = subprocess.run(
            [self.exe, "tag", "--key-hex", "0001", "--file", "--file"],
            capture_output=True, cwd=self.tmpdir)
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, b"")
        self.assertIn(b"requires a value", r.stderr)

        # An explicitly empty file path is a read failure (exit 1), not a
        # missing-value error.
        r = subprocess.run(
            [self.exe, "tag", "--key-hex", "0001", "--file", ""],
            capture_output=True)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout, b"")
        self.assertIn(b"read", r.stderr.lower())

    def test_33_unopenable_file_exit_1(self):
        missing = os.path.join(self.tmpdir, "does-not-exist.bin")
        result = self.run_tag("0001", missing)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"",
                         "a read failure must not print any tag")
        self.assertNotRegex(result.stderr, rb"\A\s*\Z")
        self.assertNotRegex(result.stderr, rb"[0-9a-f]{64}")
        self.assertIn(b"read", result.stderr.lower())

        # When the tests don't run as root, an unreadable file is a second,
        # independent way to trigger the same failure.
        if os.geteuid() != 0:
            locked = os.path.join(self.tmpdir, "locked.bin")
            with open(locked, "w") as f:
                f.write("data")
            os.chmod(locked, 0)
            try:
                result = self.run_tag("0001", locked)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"read", result.stderr.lower())
            finally:
                os.chmod(locked, stat.S_IRUSR | stat.S_IWUSR)

    def test_34_read_error_after_partial_read(self):
        """The file opens fine and a non-empty prefix is read, then a read
        fails mid-message. The whole operation must fail with exit code 1,
        no bytes on stdout and a read-error message on stderr -- even
        though the prefix already read would authenticate to a perfectly
        valid tag. Finalizing the partial message (treating the failure as
        normal EOF) or reporting it as a key/usage error (exit 2) both
        fail here.

        The failure is injected with an LD_PRELOAD shim that makes read(2)
        fail with EIO after a chosen number of bytes of the message file;
        it does not depend on file permissions or on special files."""
        if self.shim is None:
            self.skipTest("read-fault shim not available (build with CMake "
                          "or pass its path as the second argument)")
        if not os.path.exists("/proc/self/fd"):
            self.skipTest("read-fault shim needs /proc/self/fd (Linux)")

        data = stream_bytes(READ_CHUNK + 5000)   # > one chunk, ragged tail
        path = os.path.join(self.tmpdir, "midread.bin")
        with open(path, "wb") as f:
            f.write(data)

        def run_injected(fail_after, target=path):
            env = dict(os.environ)
            env["LD_PRELOAD"] = self.shim
            env["MESSAGETAG_READ_FAULT_PATH"] = target
            env["MESSAGETAG_READ_FAULT_AFTER"] = str(fail_after)
            return subprocess.run(
                [self.exe, "tag", "--key-hex", "0001", "--file", path],
                capture_output=True, env=env)

        # Control: shim loaded but aimed at a different path must not
        # disturb a normal run -- the full message authenticates exactly.
        # This also proves the shim is actually loaded for the runs below.
        control = run_injected(1, target=path + ".not-the-target")
        self.assertTagSuccess(control, expected_hmac("0001", data),
                              "shim control run")

        # Fail after a non-empty prefix at several offsets: inside the
        # first chunk, exactly at the chunk boundary, inside the second
        # chunk, and one byte before the real end of the file.
        for fail_after in (1, 5000, READ_CHUNK, READ_CHUNK + 1234,
                           len(data) - 1):
            with self.subTest(fail_after=fail_after):
                # The prefix alone is a valid message with a valid tag;
                # that tag must NOT be produced.
                prefix_tag = expected_hmac("0001", data[:fail_after])
                result = run_injected(fail_after)
                self.assertEqual(
                    result.returncode, 1,
                    f"fail_after={fail_after}: expected exit 1, got "
                    f"{result.returncode}; stdout={result.stdout!r} "
                    f"stderr={result.stderr!r}")
                self.assertEqual(
                    result.stdout, b"",
                    f"fail_after={fail_after}: no tag may be printed for "
                    f"a partially read message (prefix tag would be "
                    f"{prefix_tag})")
                self.assertNotEqual(
                    result.stderr, b"",
                    f"fail_after={fail_after}: a read failure must be "
                    f"reported on stderr")
                self.assertIn(b"read", result.stderr.lower())
                self.assertNotRegex(result.stderr, rb"[0-9a-f]{64}")

    # -- result output must fully reach stdout -----------------------------

    TAG_LINE = (b"307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11"
                b"a77b4d5d\n")

    def tag_argv(self):
        return [self.exe, "tag", "--key-hex", "0001",
                "--file", self.fixture("hello_lf")]

    def test_42_stdout_write_fails_after_partial_tag(self):
        """A correct tag that cannot be fully written is a failure, not a
        success: exit 1 at every mid-line boundary, the accepted prefix is
        all that reaches stdout (never a complete tag line), and stderr
        carries one output-write diagnostic with no key/usage/secret."""
        if self.write_shim is None:
            self.skipTest("write-fault shim not available (build with CMake "
                          "or pass its path as the third argument)")
        # Every boundary: zero bytes, single byte, mid-line, one short of
        # the line, and exactly the tag without its newline (64 bytes) --
        # the last must still fail because the trailing '\n' never landed.
        for after in (0, 1, 10, 32, 63, 64):
            for errno in (FAULT_EPIPE, FAULT_ENOSPC, FAULT_EIO):
                with self.subTest(after=after, errno=errno):
                    result = run_with_write_fault(
                        self.tag_argv(), self.write_shim, after, errno)
                    assert_stdout_write_failure(
                        self, result, self.TAG_LINE, after,
                        secret_hexes=("0001",), label=f"tag a={after}")

    def test_43_whole_line_accepted_is_success(self):
        """Boundary from the other side: once all 65 bytes (64 hex + '\\n')
        are accepted the run is an ordinary success with empty stderr. This
        pins the flushing/completion requirement -- a flush that reports
        failure after a full buffer write would wrongly fail here."""
        if self.write_shim is None:
            self.skipTest("write-fault shim not available")
        result = run_with_write_fault(
            self.tag_argv(), self.write_shim,
            len(self.TAG_LINE), FAULT_EPIPE)
        self.assertTagSuccess(
            result, self.TAG_LINE[:-1].decode(), "fully accepted line")

    def test_44_closed_pipe_is_exit_1_not_sigpipe(self):
        """A downstream pipe that closes while the result write is blocked
        must surface as exit 1 plus the write diagnostic, never as death by
        SIGPIPE (a negative/141 status) and never as a false exit 0."""
        if not hasattr(os, "set_blocking"):
            self.skipTest("non-blocking pipe control needs os.set_blocking")
        rc, stderr = run_with_closed_stdout(self.tag_argv())
        assert_closed_pipe_failure(
            self, rc, stderr, secret_hexes=("0001",), label="tag")

    def test_45_prior_error_precedence_survives_bad_stdout(self):
        """An earlier, higher-priority error keeps its own exit code and
        message even when stdout is unwritable; the output-write diagnostic
        must not appear for commands that never reached result output."""
        if self.write_shim is None:
            self.skipTest("write-fault shim not available")
        # Parameter error (bad key) -> 2, usage retained.
        r = run_with_write_fault(
            [self.exe, "tag", "--key-hex", "zz",
             "--file", self.fixture("hello_lf")],
            self.write_shim, 0, FAULT_EPIPE)
        self.assertEqual(r.returncode, 2)
        self.assertIn(b"Usage: messagetag tag", r.stderr)
        self.assertNotIn(WRITE_FAIL_MARKER, r.stderr.lower())
        # Read failure (missing file) -> 1, but the read message, not the
        # output-write one.
        missing = os.path.join(self.tmpdir, "absent.bin")
        r = run_with_write_fault(
            [self.exe, "tag", "--key-hex", "0001", "--file", missing],
            self.write_shim, 0, FAULT_ENOSPC)
        self.assertEqual(r.returncode, 1)
        self.assertIn(b"read", r.stderr.lower())
        self.assertNotIn(WRITE_FAIL_MARKER, r.stderr.lower())

    # -- recoverable output trouble must still finish the line ------------

    def test_46_short_writes_and_eintr_recover_into_full_tag(self):
        """A write that temporarily accepts only part of the line, or
        temporarily returns EINTR, is not a failure. With valid inputs and a
        stdout that ultimately accepts the whole line, ``tag`` must still
        exit 0 with empty stderr and exactly the correct 64-hex line plus
        its newline -- never just a length-plausible line.

        The scripted shim pins, in order: an interruption before any byte
        is sent; an interruption after a non-empty prefix; several
        consecutive short writes; shorts and EINTR interleaved a finite
        number of times; and the critical tail case where all 64 tag
        characters are already out and only '\\n' remains. The accepted
        prefix must appear exactly once, in order, followed by the
        remainder: recovery retries the unwritten bytes, it never replays
        accepted ones or stops before the newline."""
        if self.write_shim is None:
            self.skipTest("write-fault shim not available (build with CMake "
                          "or pass its path as the third argument)")
        expected_tag = self.TAG_LINE[:-1].decode()
        tag_chars = self.TAG_LINE[:64]
        scripts = [
            # EINTR before a single byte has been sent.
            "eintr,pass",
            "eintr,eintr,eintr,pass",
            # EINTR after a non-empty prefix has already been accepted.
            "short:1,eintr,pass",
            "short:10,eintr,eintr,pass",
            "short:32,eintr,short:16,eintr,pass",
            # Several consecutive short writes, then the remainder.
            "short:1,short:1,short:7,short:13,short:31,pass",
            # The whole line accepted one byte per write call.
            ",".join(["short:1"] * len(self.TAG_LINE)),
            # Finite shorts and interruptions interleaved, then recovery.
            "eintr,short:5,eintr,short:5,eintr,eintr,short:20,short:20,pass",
            # Nothing out first (EINTR), then ragged shorts to the end.
            "eintr,short:33,short:31,short:1",
            # All 64 hex characters out, only the newline left: a temporary
            # interruption must neither end the command early nor restart
            # the whole line on recovery.
            "short:64,eintr,pass",
            "short:64,eintr,eintr,eintr,pass",
            "short:64,short:1",
        ]
        for script in scripts:
            with self.subTest(script=script):
                result = run_with_write_script(
                    self.tag_argv(), self.write_shim, script)
                self.assertTagSuccess(result, expected_tag, script)
                # Exact equality already pins order and completeness; these
                # spell out the no-duplicate/no-hole requirement on the
                # prefix the receiver already held.
                self.assertEqual(
                    result.stdout, tag_chars + b"\n",
                    f"{script}: line must be tag chars once, then newline")
                self.assertEqual(result.stdout.count(tag_chars), 1,
                                 f"{script}: accepted tag prefix re-emitted")
                self.assertEqual(result.stdout.count(tag_chars[:32]), 1,
                                 f"{script}: accepted half-line re-emitted")
                self.assertEqual(result.stdout.find(tag_chars), 0,
                                 f"{script}: line order changed")

    def test_47_permanent_failure_after_recoverable_stretch_tag(self):
        """After a finite, recovered run of EINTR/short writes, a permanent
        EPIPE/ENOSPC/EIO that arrives while the line is still incomplete
        keeps the existing failure meaning: exit 1, only the bytes actually
        accepted so far on stdout (never completed or padded afterwards),
        and exactly one output-write diagnostic on stderr -- no usage, no
        key echo, no recomputed tag. This includes the point where all 64
        tag characters are out and only the newline remains missing."""
        if self.write_shim is None:
            self.skipTest("write-fault shim not available")
        # (script, bytes actually delivered before the sticky failure).
        cases = [
            ("eintr,fail:32", 0, FAULT_EPIPE),
            ("short:30,eintr,fail:32", 30, FAULT_EPIPE),
            ("short:10,eintr,short:20,eintr,eintr,fail:28", 30,
             FAULT_ENOSPC),
            ("eintr,short:1,eintr,short:9,fail:5", 10, FAULT_EIO),
            # Recovered all the way to the last byte, then permanent error.
            ("short:64,eintr,fail:32", 64, FAULT_EPIPE),
            ("short:64,fail:5", 64, FAULT_EIO),
        ]
        for script, delivered, fail_errno in cases:
            with self.subTest(script=script):
                result = run_with_write_script(
                    self.tag_argv(), self.write_shim, script)
                assert_stdout_write_failure(
                    self, result, self.TAG_LINE, delivered,
                    secret_hexes=("0001",), label=script)
                # Nothing must follow the residual prefix after the failure.
                self.assertEqual(
                    result.stdout, self.TAG_LINE[:delivered],
                    f"{script}: receiver must hold only the accepted prefix")

    # -- entry-point compatibility -----------------------------------------

    def test_40_version_entry_point(self):
        r = subprocess.run([self.exe, "--version"], capture_output=True)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout, b"messagetag 0.1.0\n")
        self.assertEqual(r.stderr, b"")

    def test_41_unknown_invocation_exit_2(self):
        r = subprocess.run([self.exe], capture_output=True)
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, b"")


class VerifyRegression(unittest.TestCase):
    """Contract for ``messagetag verify``.

    Expected tags are the independently computed constants already used by
    the tag suite (re-derived from Python's hmac in TagRegression.test_00);
    verify never learns the "right answer" from the program under test.
    """

    exe = None
    tmpdir = None
    shim_path = None
    shim = None
    write_shim_path = None
    write_shim = None

    # (label, key hex, fixture name, expected tag) -- a spread across empty
    # messages, NUL bytes, trailing newlines, hex-case keys and large files.
    CASES = [
        ("empty",      "0b" * 20, "empty",
         "999a901219f032cd497cadb5e6051e97b6a29ab297bd6ae722bd6062a2f59542"),
        ("hello_lf",   "0001", "hello_lf",
         "307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11a77b4d5d"),
        ("hello",      "0001", "hello",
         "ee44e44a606a62df24b198d7130faa42a53e2aa5db4133210fd7c657aa7bb6ab"),
        ("nul",        "0001", "nul",
         "50da50e788e0ecda4126d1ac5752a88c0ab5fc4ce1dda87cb7d32fa34fd5c5f6"),
        ("large",      LARGE_KEY_HEX, "large",
         "d524cb7fca18676b75e28f2bb79b9a80718ecc589328bc2288192439f3e090d7"),
        ("block2",     LARGE_KEY_HEX, "block2",
         "f6f09c1fe5588e2f7c0196783cbe145c1f4f2fbeba87b156816cda9f90f6e154"),
        ("upperkey",   "DEADBEEF", "hello",
         "297a715da8a2b93f287fd5e6e7d4764bc3e899df7556d58889a4f986656c8009"),
    ]

    @classmethod
    def setUpClass(cls):
        if not cls.exe or not os.path.isfile(cls.exe):
            raise RuntimeError("messagetag executable not found: %r" % cls.exe)
        cls.tmpdir = tempfile.mkdtemp(prefix="messagetag-verify-")
        fixtures = {}
        for name, _key, message, _tag in PROJECT_VECTORS:
            fixtures.setdefault(name, message)
        for rel, data in fixtures.items():
            path = os.path.join(cls.tmpdir, rel + ".bin")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(data)
        os.makedirs(os.path.join(cls.tmpdir, "sub"), exist_ok=True)
        with open(os.path.join(cls.tmpdir, "sub", "copy.bin"), "wb") as f:
            f.write(b"hello\n")
        cls.fixtures = fixtures
        cls.shim = find_read_fault_shim(cls.shim_path, cls.exe, cls.tmpdir)
        cls.write_shim = find_write_fault_shim(
            cls.write_shim_path, cls.exe, cls.tmpdir)

    @classmethod
    def tearDownClass(cls):
        if cls.tmpdir and os.path.isdir(cls.tmpdir):
            shutil.rmtree(cls.tmpdir, ignore_errors=True)

    # -- helpers ------------------------------------------------------------

    def fixture(self, name):
        return os.path.join(self.tmpdir, name + ".bin")

    def run_verify(self, key_hex, path, tag_hex, *extra):
        return subprocess.run(
            [self.exe, "verify", "--key-hex", key_hex, "--file", path,
             "--tag-hex", tag_hex, *extra],
            capture_output=True)

    def assertVerifyOk(self, result, label=""):
        self.assertEqual(
            result.returncode, 0,
            f"{label}: expected exit 0, got {result.returncode}; "
            f"stderr={result.stderr!r}")
        self.assertEqual(result.stdout, b"OK\n",
                         f"{label}: stdout must be exactly b'OK\\n', got "
                         f"{result.stdout!r}")
        self.assertEqual(result.stderr, b"",
                         f"{label}: stderr must be empty, got "
                         f"{result.stderr!r}")

    def assertMismatch(self, result, label=""):
        self.assertEqual(
            result.returncode, 3,
            f"{label}: expected exit 3, got {result.returncode}; "
            f"stdout={result.stdout!r} stderr={result.stderr!r}")
        self.assertEqual(result.stdout, b"",
                         f"{label}: stdout must carry no bytes on mismatch, "
                         f"got {result.stdout!r}")
        self.assertNotEqual(result.stderr, b"",
                            f"{label}: a mismatch diagnostic is required")
        lower = result.stderr.lower()
        self.assertIn(b"mismatch", lower,
                      f"{label}: diagnostic must state the mismatch")
        # The diagnostic must not assign a definite cause: a mismatch can
        # equally come from an altered message or a different key.
        for forbidden in (b"wrong key", b"bad key", b"incorrect key",
                          b"tamper", b"modif", b"corrupt"):
            self.assertNotIn(forbidden, lower,
                             f"{label}: diagnostic must not claim a specific "
                             f"cause ({forbidden!r})")

    def assertNoSecretLeak(self, result, tag_hex, key_hex, label=""):
        # Never print a tag-length hex run in any casing, the supplied tag
        # itself, or the key material.
        self.assertNotRegex(result.stderr, rb"(?i)[0-9a-f]{64}",
                            f"{label}: stderr must not contain a tag-length "
                            f"hex string")
        self.assertNotIn(tag_hex.lower().encode(), result.stderr.lower(),
                         f"{label}: the supplied tag must not be echoed")
        if len(key_hex) >= 4:
            self.assertNotIn(key_hex.encode(), result.stderr,
                             f"{label}: key material must not be echoed")

    def assertUsageError(self, result, label=""):
        self.assertEqual(
            result.returncode, 2,
            f"{label}: expected exit 2, got {result.returncode}; "
            f"stderr={result.stderr!r}")
        self.assertEqual(result.stdout, b"",
                         f"{label}: stdout must be empty, got "
                         f"{result.stdout!r}")
        self.assertIn(b"Usage: messagetag verify", result.stderr,
                      f"{label}: stderr must give the verify usage")

    # -- success ------------------------------------------------------------

    def test_50_success_is_exactly_ok_newline(self):
        for label, key, name, tag in self.CASES:
            with self.subTest(case=label):
                self.assertVerifyOk(
                    self.run_verify(key, self.fixture(name), tag), label)

    def test_51_accepts_tag_command_output_with_newline_removed(self):
        """The tag consumed by verify is exactly what ``messagetag tag``
        prints with the trailing newline stripped -- no new wrapping."""
        for label, key, name, _tag in self.CASES[:4]:
            with self.subTest(case=label):
                tagged = subprocess.run(
                    [self.exe, "tag", "--key-hex", key,
                     "--file", self.fixture(name)], capture_output=True)
                self.assertEqual(tagged.returncode, 0)
                self.assertTrue(tagged.stdout.endswith(b"\n"))
                # Pass through the raw bytes of the tag line; verify itself
                # rejects whitespace, so stripping is the contract, not
                # implicit trimming.
                supplied = tagged.stdout[:-1].decode()
                self.assertVerifyOk(
                    self.run_verify(key, self.fixture(name), supplied), label)

    def test_52_tag_hex_case_insensitive(self):
        tag = "307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11a77b4d5d"
        for variant in (tag, tag.upper(), "".join(
                c.upper() if i % 2 == 0 else c for i, c in enumerate(tag))):
            with self.subTest(variant=variant[:8]):
                self.assertVerifyOk(
                    self.run_verify("0001", self.fixture("hello_lf"),
                                    variant))

    def test_53_path_not_part_of_message(self):
        tag = "307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11a77b4d5d"
        for path in (self.fixture("hello_lf"),
                     os.path.join(self.tmpdir, "sub", "copy.bin")):
            self.assertVerifyOk(
                self.run_verify("0001", path, tag), path)

    def test_54_option_order_interchangeable(self):
        tag = "307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11a77b4d5d"
        path = self.fixture("hello_lf")
        for argv in (
            [self.exe, "verify", "--file", path, "--key-hex", "0001",
             "--tag-hex", tag],
            [self.exe, "verify", "--tag-hex", tag, "--file", path,
             "--key-hex", "0001"],
        ):
            r = subprocess.run(argv, capture_output=True)
            self.assertVerifyOk(r)

    # -- authentication failure --------------------------------------------

    def test_60_modified_message_mismatch(self):
        # Tag authenticates hello_lf; every other fixture must fail,
        # including one-byte neighbours (hello without newline, CR variant).
        tag = "307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11a77b4d5d"
        for name in ("hello", "hello_cr", "hello_crlf", "nul", "empty"):
            with self.subTest(fixture=name):
                r = self.run_verify("0001", self.fixture(name), tag)
                self.assertMismatch(r, name)
                self.assertNoSecretLeak(r, tag, "0001", name)

    def test_61_different_key_mismatch(self):
        tag = "307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11a77b4d5d"
        for wrong_key in ("0002", "000001", "deadbeef", "0b" * 20):
            with self.subTest(key=wrong_key):
                r = self.run_verify(wrong_key, self.fixture("hello_lf"), tag)
                self.assertMismatch(r, wrong_key)
                self.assertNoSecretLeak(r, tag, wrong_key, wrong_key)

    def test_62_flipped_tag_mismatch_at_every_position_class(self):
        """Tags differing in the first byte, the last byte and a middle
        byte all give the same plain mismatch result, regardless of how
        long a prefix happens to match."""
        tag = bytearray.fromhex(
            "307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11a77b4d5d")
        for pos in (0, 15, 31):
            flipped = tag.copy()
            flipped[pos] ^= 0x01
            supplied = flipped.hex()
            with self.subTest(pos=pos):
                r = self.run_verify("0001", self.fixture("hello_lf"),
                                    supplied)
                self.assertMismatch(r, f"pos {pos}")
                self.assertNoSecretLeak(r, supplied, "0001", f"pos {pos}")

    def test_63_trailing_newline_participates(self):
        lf = "307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11a77b4d5d"
        no_lf = "ee44e44a606a62df24b198d7130faa42a53e2aa5db4133210fd7c657aa7bb6ab"
        # Tag for "hello\n" must not verify the file without the newline...
        self.assertMismatch(
            self.run_verify("0001", self.fixture("hello"), lf))
        # ...and the converse.
        self.assertMismatch(
            self.run_verify("0001", self.fixture("hello_lf"), no_lf))

    def test_64_empty_vs_nonempty_distinguished(self):
        empty_tag = expected_hmac("0001", b"")
        r = self.run_verify("0001", self.fixture("hello"), empty_tag)
        self.assertMismatch(r)

    # -- tag format: parameter errors before any file access --------------

    def test_70_tag_must_be_exactly_64_hex_chars(self):
        good = "307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11a77b4d5d"
        bad = [
            "",            # empty
            good[:-1],     # 63 chars, truncated by one
            good[:-2],     # 62 chars
            good[:32],     # 32 chars (16 bytes)
            good + "aa",   # over-long (33 bytes)
            good + "0",    # 65 chars, odd
            "0x" + good,   # 0x prefix
            " " + good,    # leading whitespace
            good + " ",    # trailing whitespace
            good[:10] + " " + good[11:],  # embedded whitespace
            good + "\n",   # the newline tag output ends with: must be stripped
            good[:-1] + "g",  # non-hex character
            "z" * 64,      # all non-hex but right length
            good[:-1] + "G",  # G is not hex
        ]
        for supplied in bad:
            with self.subTest(tag=repr(supplied)):
                r = self.run_verify("0001", self.fixture("hello_lf"), supplied)
                self.assertUsageError(r, repr(supplied))
                # The malformed tag itself must not be echoed back.
                if supplied:
                    self.assertNotIn(supplied.encode(), r.stderr)

    def test_71_bad_key_is_parameter_error(self):
        good = "307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11a77b4d5d"
        for bad_key in ("", "abc", "0x01", "zz", "ab cd"):
            with self.subTest(key=repr(bad_key)):
                r = self.run_verify(bad_key, self.fixture("hello_lf"), good)
                self.assertUsageError(r, repr(bad_key))

    def test_72_format_checked_before_file_is_opened(self):
        """An invalid key/tag is a parameter error even when the file does
        not exist: input validation must precede reading."""
        good = "307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11a77b4d5d"
        missing = os.path.join(self.tmpdir, "no-such-file.bin")
        self.assertFalse(os.path.exists(missing))
        # Malformed tag + missing file -> 2 (not 1, not 3).
        self.assertUsageError(
            self.run_verify("0001", missing, "abc"), "bad tag, missing file")
        self.assertUsageError(
            self.run_verify("0001", missing, ""), "empty tag, missing file")
        self.assertUsageError(
            self.run_verify("zz", missing, good), "bad key, missing file")
        # Well-formed inputs against a missing file are a read failure (1).
        r = self.run_verify("0001", missing, good)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout, b"")

    def test_73_missing_valueless_and_unknown_options_exit_2(self):
        path = self.fixture("hello_lf")
        good = "307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11a77b4d5d"
        invocations = [
            [self.exe, "verify"],
            [self.exe, "verify", "--key-hex", "0001", "--file", path],
            [self.exe, "verify", "--key-hex", "0001", "--tag-hex", good],
            [self.exe, "verify", "--file", path, "--tag-hex", good],
            [self.exe, "verify", "--key-hex", "0001", "--file", path,
             "--tag-hex"],                       # option without a value
            [self.exe, "verify", "--key-hex", "0001", "--file", path,
             "--tag-hex", good, "--bogus", "x"],  # unknown argument
            [self.exe, "verify", "--key-hex"],   # missing value, end of argv
            [self.exe, "verify", "tag-hex", good, "--key-hex", "0001",
             "--file", path],                    # looks like, but no dashes
        ]
        for argv in invocations:
            with self.subTest(argv=argv[2:]):
                r = subprocess.run(argv, capture_output=True)
                self.assertUsageError(r, repr(argv))

    def test_74_option_name_after_option_is_missing_value(self):
        """A value-taking option immediately followed by one of verify's
        option names (including the same name again) is a missing-value
        usage error -- reported before any file is read -- even when the
        other options carry a perfectly valid key and tag, and even when
        a file with the option's name actually exists."""
        path = self.fixture("hello_lf")
        good = "307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11a77b4d5d"
        invocations = [
            [self.exe, "verify", "--key-hex", "0001", "--file", path,
             "--tag-hex", "--tag-hex"],
            [self.exe, "verify", "--key-hex", "0001", "--file",
             "--tag-hex", good],
            [self.exe, "verify", "--key-hex", "--file", path,
             "--tag-hex", good],
            [self.exe, "verify", "--file", "--file", "--key-hex", "0001",
             "--tag-hex", good],
            [self.exe, "verify", "--tag-hex", "--key-hex", "0001",
             "--file", path],
        ]
        for argv in invocations:
            with self.subTest(argv=argv[2:]):
                r = subprocess.run(argv, capture_output=True)
                self.assertUsageError(r, repr(argv))
                self.assertIn(b"requires a value", r.stderr)
                self.assertNoSecretLeak(r, good, "0001", repr(argv))

        # A file literally named "--file" existing in the working
        # directory does not turn the missing value into a file read.
        with open(os.path.join(self.tmpdir, "--file"), "wb") as f:
            f.write(b"hello\n")
        r = subprocess.run(
            [self.exe, "verify", "--key-hex", "0001", "--file", "--file",
             "--tag-hex", good],
            capture_output=True, cwd=self.tmpdir)
        self.assertUsageError(r, "existing file named --file")
        self.assertIn(b"requires a value", r.stderr)

        # A dash-leading token that is not one of verify's option names
        # is still a value: "--notes" after --file is a file path.
        with open(os.path.join(self.tmpdir, "--notes"), "wb") as f:
            f.write(b"hello\n")
        r = subprocess.run(
            [self.exe, "verify", "--key-hex", "0001", "--file", "--notes",
             "--tag-hex", good],
            capture_output=True, cwd=self.tmpdir)
        self.assertVerifyOk(r, "file named --notes")

    # -- read / computation failures ---------------------------------------

    def test_80_unopenable_file_exit_1(self):
        good = "307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11a77b4d5d"
        missing = os.path.join(self.tmpdir, "does-not-exist.bin")
        r = self.run_verify("0001", missing, good)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout, b"")
        self.assertIn(b"read", r.stderr.lower())
        self.assertNoSecretLeak(r, good, "0001", "missing file")

        if os.geteuid() != 0:
            locked = os.path.join(self.tmpdir, "locked.bin")
            with open(locked, "w") as f:
                f.write("data")
            os.chmod(locked, 0)
            try:
                r = self.run_verify("0001", locked, good)
                self.assertEqual(r.returncode, 1)
                self.assertEqual(r.stdout, b"")
                self.assertIn(b"read", r.stderr.lower())
            finally:
                os.chmod(locked, stat.S_IRUSR | stat.S_IWUSR)

    def test_81_read_error_after_partial_read_is_exit_1(self):
        """Open succeeds, a non-empty prefix is read, then a read fails.
        Verification must end with exit 1 and empty stdout: it must neither
        accept on the partial prefix nor report a mismatch (exit 3) as if
        the whole file had been read. Injected with the LD_PRELOAD shim."""
        if self.shim is None:
            self.skipTest("read-fault shim not available (build with CMake "
                          "or pass its path as the second argument)")
        if not os.path.exists("/proc/self/fd"):
            self.skipTest("read-fault shim needs /proc/self/fd (Linux)")

        data = stream_bytes(READ_CHUNK + 5000)
        path = os.path.join(self.tmpdir, "midread-verify.bin")
        with open(path, "wb") as f:
            f.write(data)
        correct_tag = expected_hmac("0001", data)

        env = dict(os.environ)
        env["LD_PRELOAD"] = self.shim
        env["MESSAGETAG_READ_FAULT_PATH"] = path
        for fail_after in (1, 5000, READ_CHUNK, len(data) - 1):
            with self.subTest(fail_after=fail_after):
                env["MESSAGETAG_READ_FAULT_AFTER"] = str(fail_after)
                # Correct tag for the WHOLE message: a verifier that
                # finalized the readable prefix would exit 3, which is just
                # as wrong as printing OK.
                r = subprocess.run(
                    [self.exe, "verify", "--key-hex", "0001",
                     "--file", path, "--tag-hex", correct_tag],
                    capture_output=True, env=env)
                self.assertEqual(
                    r.returncode, 1,
                    f"fail_after={fail_after}: expected exit 1, got "
                    f"{r.returncode}; stdout={r.stdout!r} "
                    f"stderr={r.stderr!r}")
                self.assertEqual(r.stdout, b"")
                self.assertIn(b"read", r.stderr.lower())

                # And a tag matching only the readable prefix must not turn
                # the read failure into a successful verification either.
                prefix_tag = expected_hmac("0001", data[:fail_after])
                r2 = subprocess.run(
                    [self.exe, "verify", "--key-hex", "0001",
                     "--file", path, "--tag-hex", prefix_tag],
                    capture_output=True, env=env)
                self.assertEqual(r2.returncode, 1)
                self.assertEqual(r2.stdout, b"")

    # -- result output must fully reach stdout -----------------------------

    OK_LINE = b"OK\n"

    def verify_argv(self):
        tag = ("307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11"
               "a77b4d5d")
        return [self.exe, "verify", "--key-hex", "0001",
                "--file", self.fixture("hello_lf"), "--tag-hex", tag]

    def test_90_stdout_write_fails_after_partial_ok(self):
        """A passed comparison is not success unless "OK\\n" is wholly
        written. At every short boundary the run exits 1 with only the
        accepted prefix (never a complete "OK\\n"), and one output-write
        diagnostic that leaks neither the key nor the supplied/recomputed
        tag. EPIPE/ENOSPC/EIO all behave identically."""
        if self.write_shim is None:
            self.skipTest("write-fault shim not available (build with CMake "
                          "or pass its path as the third argument)")
        tag = ("307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11"
               "a77b4d5d")
        # 0, 1 ("O"), 2 ("OK" without the newline -- must still fail).
        for after in (0, 1, 2):
            for errno in (FAULT_EPIPE, FAULT_ENOSPC, FAULT_EIO):
                with self.subTest(after=after, errno=errno):
                    result = run_with_write_fault(
                        self.verify_argv(), self.write_shim, after, errno)
                    assert_stdout_write_failure(
                        self, result, self.OK_LINE, after,
                        secret_hexes=("0001", tag), label=f"verify a={after}")

    def test_91_whole_ok_line_accepted_is_success(self):
        if self.write_shim is None:
            self.skipTest("write-fault shim not available")
        result = run_with_write_fault(
            self.verify_argv(), self.write_shim,
            len(self.OK_LINE), FAULT_EPIPE)
        self.assertVerifyOk(result, "fully accepted OK line")

    def test_92_closed_pipe_is_exit_1_not_sigpipe(self):
        """Closing the downstream pipe while verify emits OK must end as
        exit 1 with the write diagnostic, not SIGPIPE death or exit 0."""
        if not hasattr(os, "set_blocking"):
            self.skipTest("non-blocking pipe control needs os.set_blocking")
        tag = ("307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11"
               "a77b4d5d")
        rc, stderr = run_with_closed_stdout(self.verify_argv())
        assert_closed_pipe_failure(
            self, rc, stderr, secret_hexes=("0001", tag), label="verify")

    def test_93_prior_error_precedence_survives_bad_stdout(self):
        """Mismatch (3), parameter error (2) and read failure (1) keep
        their own codes and messages against an unwritable stdout; the
        output-write diagnostic is reserved for the output stage."""
        if self.write_shim is None:
            self.skipTest("write-fault shim not available")
        good = ("307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11"
                "a77b4d5d")
        # Mismatch -> 3 with the mismatch message.
        r = run_with_write_fault(
            [self.exe, "verify", "--key-hex", "0002",
             "--file", self.fixture("hello_lf"), "--tag-hex", good],
            self.write_shim, 0, FAULT_EPIPE)
        self.assertEqual(r.returncode, 3)
        self.assertIn(b"mismatch", r.stderr.lower())
        self.assertNotIn(WRITE_FAIL_MARKER, r.stderr.lower())
        # Parameter error (bad tag) -> 2 with usage.
        r = run_with_write_fault(
            [self.exe, "verify", "--key-hex", "0001",
             "--file", self.fixture("hello_lf"), "--tag-hex", "abc"],
            self.write_shim, 0, FAULT_EPIPE)
        self.assertEqual(r.returncode, 2)
        self.assertIn(b"Usage: messagetag verify", r.stderr)
        self.assertNotIn(WRITE_FAIL_MARKER, r.stderr.lower())
        # Read failure (missing file) -> 1 with the read message.
        missing = os.path.join(self.tmpdir, "absent-verify.bin")
        r = run_with_write_fault(
            [self.exe, "verify", "--key-hex", "0001",
             "--file", missing, "--tag-hex", good],
            self.write_shim, 0, FAULT_ENOSPC)
        self.assertEqual(r.returncode, 1)
        self.assertIn(b"read", r.stderr.lower())
        self.assertNotIn(WRITE_FAIL_MARKER, r.stderr.lower())

    # -- recoverable output trouble must still finish "OK\n" --------------

    def test_94_short_writes_and_eintr_recover_into_ok(self):
        """On a passed comparison, recoverable output trouble must not turn
        valid authentication into a failure. With well-formed inputs and a
        stdout that ultimately accepts the line, ``verify`` exits 0 with
        empty stderr and exactly b"OK\\n": an interruption before the first
        byte, an interruption after the non-empty "O" prefix, repeated short
        writes, shorts interleaved with a finite number of EINTRs, and the
        tail case where "OK" is already out and only the newline remains.
        The recovered line is delivered once, in order -- the prefix the
        receiver already held is never replayed and the command never ends
        before the newline."""
        if self.write_shim is None:
            self.skipTest("write-fault shim not available (build with CMake "
                          "or pass its path as the third argument)")
        tag = ("307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11"
               "a77b4d5d")
        scripts = [
            # EINTR before any byte is sent.
            "eintr,pass",
            "eintr,eintr,eintr,pass",
            # EINTR after the non-empty "O" prefix is out.
            "short:1,eintr,pass",
            "short:1,eintr,eintr,eintr,pass",
            # Short writes only: "O", then "K", then the newline.
            "short:1,short:1,short:1",
            # Interruptions and short writes interleaved a finite number of
            # times, then normal acceptance.
            "eintr,short:1,eintr,short:1,eintr,pass",
            # "OK" already delivered, only the newline left: the temporary
            # interruption must not stop the command nor re-output "OK".
            "short:2,eintr,pass",
            "short:2,eintr,eintr,pass",
            "short:2,short:1",
        ]
        for script in scripts:
            with self.subTest(script=script):
                result = run_with_write_script(
                    self.verify_argv(), self.write_shim, script)
                self.assertVerifyOk(result, script)
                # The receiver holds the prefix it already saw exactly once.
                self.assertEqual(result.stdout.count(b"O"), 1, script)
                self.assertEqual(result.stdout.count(b"OK"), 1, script)
                self.assertEqual(result.stdout.find(b"OK"), 0, script)

    def test_95_permanent_failure_after_recoverable_stretch_verify(self):
        """After a recovered stretch of EINTR/short writes, a permanent
        EPIPE/ENOSPC/EIO while "OK\\n" is still incomplete keeps the
        established failure contract: exit 1, stdout holds only the prefix
        actually delivered (never a completed OK line), stderr one
        output-write diagnostic with no usage and no echo of the key, the
        supplied tag or a recomputed tag -- including when "OK" itself is
        already out and only the newline failed."""
        if self.write_shim is None:
            self.skipTest("write-fault shim not available")
        tag = ("307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11"
               "a77b4d5d")
        # (script, bytes delivered before the sticky failure).
        cases = [
            ("eintr,fail:32", 0, FAULT_EPIPE),
            ("short:1,eintr,fail:28", 1, FAULT_ENOSPC),
            ("eintr,short:1,eintr,eintr,fail:5", 1, FAULT_EIO),
            # "OK" is out; the missing newline must still be a failure.
            ("short:2,eintr,fail:32", 2, FAULT_EPIPE),
            ("short:2,fail:28", 2, FAULT_ENOSPC),
        ]
        for script, delivered, _fail_errno in cases:
            with self.subTest(script=script):
                result = run_with_write_script(
                    self.verify_argv(), self.write_shim, script)
                assert_stdout_write_failure(
                    self, result, self.OK_LINE, delivered,
                    secret_hexes=("0001", tag), label=script)
                self.assertEqual(
                    result.stdout, self.OK_LINE[:delivered],
                    f"{script}: receiver must hold only the accepted prefix")


def main():
    if len(sys.argv) not in (2, 3, 4):
        print("usage: regression_test.py /path/to/messagetag "
              "[/path/to/libread_fault_shim.so] "
              "[/path/to/libwrite_fault_shim.so]", file=sys.stderr)
        return 2
    TagRegression.exe = os.path.abspath(sys.argv[1])
    TagRegression.tmpdir = None
    TagRegression.shim_path = (os.path.abspath(sys.argv[2])
                               if len(sys.argv) >= 3 else None)
    TagRegression.write_shim_path = (os.path.abspath(sys.argv[3])
                                     if len(sys.argv) >= 4 else None)
    VerifyRegression.exe = TagRegression.exe
    VerifyRegression.tmpdir = None
    VerifyRegression.shim_path = TagRegression.shim_path
    VerifyRegression.write_shim_path = TagRegression.write_shim_path
    argv = [sys.argv[0], "-v"]
    # unittest's TextTestRunner gives non-zero exit when a test fails.
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite([
        loader.loadTestsFromTestCase(TagRegression),
        loader.loadTestsFromTestCase(VerifyRegression),
    ])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
