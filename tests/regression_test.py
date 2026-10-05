#!/usr/bin/env python3
"""Automatic regression tests for the documented ``messagetag tag`` contract.

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
  stdout and a read-error message, never a partial-message tag.

Usage:

    python3 tests/regression_test.py /path/to/messagetag \
        [/path/to/libread_fault_shim.so]
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


class TagRegression(unittest.TestCase):
    exe = None
    tmpdir = None
    shim_path = None   # optional second CLI argument: read-fault shim
    shim = None

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

    @classmethod
    def _find_read_fault_shim(cls):
        """Locate (or, as a fallback, build) the LD_PRELOAD read-fault
        shim used by test_34. Returns None when no shim is available; the
        test then skips loudly instead of silently losing coverage."""
        candidates = []
        if cls.shim_path:
            candidates.append(cls.shim_path)
        exe_dir = os.path.dirname(cls.exe)
        candidates += [
            os.path.join(exe_dir, "libread_fault_shim.so"),
            os.path.join(exe_dir, "read_fault_shim.so"),
        ]
        for path in candidates:
            if os.path.isfile(path):
                return path
        # Direct invocation without a CMake build of the shim: compile it
        # from next to this script if a C++ compiler is available.
        src = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "read_fault_shim.cpp")
        compiler = shutil.which("c++") or shutil.which("g++") \
            or shutil.which("clang++")
        if os.path.isfile(src) and compiler:
            out = os.path.join(cls.tmpdir, "libread_fault_shim.so")
            built = subprocess.run(
                [compiler, "-shared", "-fPIC", "-O2", "-o", out, src,
                 "-ldl"], capture_output=True)
            if built.returncode == 0 and os.path.isfile(out):
                return out
        return None

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
                         f"{label}: stdout must be exactly 'OK\\n', got "
                         f"{result.stdout!r}")
        self.assertEqual(result.stderr, b"",
                         f"{label}: stderr must be empty, got {result.stderr!r}")

    def assertVerifyMismatch(self, result, key_hex, tag_hex, label=""):
        """Exit 3, empty stdout, and a stderr message that states the
        mismatch without leaking anything: not the recomputed tag, not any
        64-hex-looking string, and not the submitted key."""
        self.assertEqual(
            result.returncode, 3,
            f"{label}: expected exit 3, got {result.returncode}; "
            f"stdout={result.stdout!r} stderr={result.stderr!r}")
        self.assertEqual(result.stdout, b"",
                         f"{label}: stdout must be empty on mismatch")
        self.assertNotEqual(result.stderr, b"",
                            f"{label}: mismatch must be reported on stderr")
        self.assertIn(b"not match", result.stderr.lower(),
                      f"{label}: stderr must say the tag does not match")
        self.assertNotRegex(
            result.stderr, rb"[0-9a-fA-F]{64}",
            f"{label}: stderr must not contain any tag (recomputed, "
            f"submitted, or a matching prefix)")
        if len(key_hex) >= 8:
            # Only checked for distinctive keys: a very short key string can
            # collide with ordinary words in the fixed message.
            self.assertNotIn(key_hex.encode(), result.stderr,
                             f"{label}: the key must not be echoed")

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

    # -- verify subcommand --------------------------------------------------

    def test_50_verify_ok_for_all_vectors(self):
        """Every pinned tag verifies against its own fixture: exit 0, stdout
        exactly 'OK\\n', empty stderr."""
        for name, key, _message, tag in PROJECT_VECTORS:
            with self.subTest(fixture=name):
                self.assertVerifyOk(
                    self.run_verify(key, self.fixture(name), tag), name)

    def test_51_verify_accepts_either_hex_case(self):
        tag = "307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11a77b4d5d"
        self.assertVerifyOk(
            self.run_verify("0001", self.fixture("hello_lf"), tag.upper()),
            "uppercase tag")
        mixed = "".join(c.upper() if i % 2 else c for i, c in enumerate(tag))
        self.assertVerifyOk(
            self.run_verify("0001", self.fixture("hello_lf"), mixed),
            "mixed-case tag")

    def test_52_verify_mismatch_exit_3(self):
        """A well-formed tag that does not authenticate gives exit 3, empty
        stdout and a leak-free stderr message -- whether the message was
        changed, the key was changed, or the tag itself was altered."""
        tag = "307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11a77b4d5d"
        # Same key, different message (no trailing newline).
        self.assertVerifyMismatch(
            self.run_verify("0001", self.fixture("hello"), tag),
            "0001", tag, "message changed")
        # Same message, different key.
        self.assertVerifyMismatch(
            self.run_verify(LARGE_KEY_HEX, self.fixture("hello_lf"), tag),
            LARGE_KEY_HEX, tag, "key changed")
        # Same message and key, tag altered in the last hex digit.
        altered = tag[:-1] + ("0" if tag[-1] != "0" else "1")
        self.assertVerifyMismatch(
            self.run_verify("0001", self.fixture("hello_lf"), altered),
            "0001", altered, "tag altered")
        # Tag altered in the FIRST hex digit: a comparison that stops at the
        # first difference still has to report a plain mismatch.
        altered0 = ("1" if tag[0] != "1" else "2") + tag[1:]
        self.assertVerifyMismatch(
            self.run_verify("0001", self.fixture("hello_lf"), altered0),
            "0001", altered0, "tag altered at first digit")
        # Empty file with a tag that does not belong to it.
        self.assertVerifyMismatch(
            self.run_verify("0b" * 20, self.fixture("empty"), tag),
            "0b" * 20, tag, "empty message, foreign tag")

    def test_53_verify_invalid_tag_exit_2(self):
        """The tag must be exactly 64 hex characters: empty, truncated,
        over-long, non-hex, whitespace-bearing and 0x-prefixed values are
        all usage errors (exit 2, empty stdout, reason plus verify usage on
        stderr)."""
        good = "307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11a77b4d5d"
        bad_tags = [
            "",                 # empty
            good[:63],          # truncated
            good + "0",         # over-long
            good[:62],          # far too short
            "zz" + good[2:],    # non-hex characters
            "0x" + good,        # 0x prefix
            good[:32] + " " + good[32:],   # embedded whitespace
            good + "\n",        # trailing newline is not part of the tag
            " " + good,         # leading whitespace
            good[:-1] + "g",    # non-hex at the very end
        ]
        for bad in bad_tags:
            with self.subTest(tag=bad):
                r = self.run_verify("0001", self.fixture("hello_lf"), bad)
                self.assertEqual(r.returncode, 2,
                                 f"tag {bad!r}: expected exit 2, got "
                                 f"{r.returncode}")
                self.assertEqual(r.stdout, b"",
                                 f"tag {bad!r}: stdout must be empty")
                self.assertIn(b"--tag-hex", r.stderr,
                              f"tag {bad!r}: stderr must show verify usage")
                self.assertNotRegex(r.stderr, rb"[0-9a-fA-F]{64}",
                                    f"tag {bad!r}: stderr must not contain "
                                    f"a tag")

    def test_54_verify_tag_format_checked_before_file(self):
        """Input formats are validated before the file is read: an invalid
        tag is a usage error even when the message file does not exist --
        never exit 1 (read) or 3 (mismatch)."""
        missing = os.path.join(self.tmpdir, "does-not-exist.bin")
        r = self.run_verify("0001", missing, "abc")
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, b"")
        self.assertIn(b"--tag-hex", r.stderr)
        # An invalid key is likewise reported before any file access.
        r = self.run_verify("xyz", missing,
                            "307a25cbcb6cbca48f5dd2b05fd9174c"
                            "0cf17580f4ea8dd667092f11a77b4d5d")
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, b"")
        # With valid formats, the missing file is a read failure (exit 1).
        r = self.run_verify("0001", missing,
                            "307a25cbcb6cbca48f5dd2b05fd9174c"
                            "0cf17580f4ea8dd667092f11a77b4d5d")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout, b"")
        self.assertIn(b"read", r.stderr.lower())

    def test_55_verify_argument_errors_exit_2(self):
        good = "307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11a77b4d5d"
        path = self.fixture("hello_lf")
        cases = [
            ["verify"],
            ["verify", "--key-hex", "0001", "--file", path],      # no tag
            ["verify", "--key-hex", "0001", "--tag-hex", good],   # no file
            ["verify", "--file", path, "--tag-hex", good],        # no key
            ["verify", "--key-hex", "0001", "--file", path,
             "--tag-hex", good, "--bogus", "x"],                  # unknown
            ["verify", "--key-hex"],                              # no value
            ["verify", "--key-hex", "0001", "--file", path, "--tag-hex"],
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                r = subprocess.run([self.exe, *argv], capture_output=True)
                self.assertEqual(r.returncode, 2,
                                 f"{argv}: expected exit 2, got "
                                 f"{r.returncode}")
                self.assertEqual(r.stdout, b"")
                self.assertIn(b"verify", r.stderr,
                              f"{argv}: stderr must name the verify command")

    def test_56_verify_unopenable_file_exit_1(self):
        missing = os.path.join(self.tmpdir, "does-not-exist.bin")
        r = self.run_verify("0001", missing,
                            "307a25cbcb6cbca48f5dd2b05fd9174c"
                            "0cf17580f4ea8dd667092f11a77b4d5d")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout, b"",
                         "a read failure must not print OK or a tag")
        self.assertIn(b"read", r.stderr.lower())
        self.assertNotRegex(r.stderr, rb"[0-9a-fA-F]{64}")

    def test_57_verify_read_error_after_partial_read(self):
        """Same injected mid-read failure as test_34, but for verify: the
        run must exit 1 with empty stdout -- never 'OK' from a partially
        read message, and never a mismatch verdict either."""
        if self.shim is None:
            self.skipTest("read-fault shim not available (build with CMake "
                          "or pass its path as the second argument)")
        if not os.path.exists("/proc/self/fd"):
            self.skipTest("read-fault shim needs /proc/self/fd (Linux)")

        data = stream_bytes(READ_CHUNK + 5000)
        path = os.path.join(self.tmpdir, "midread-verify.bin")
        with open(path, "wb") as f:
            f.write(data)
        tag = expected_hmac("0001", data)

        def run_injected(fail_after, target=path):
            env = dict(os.environ)
            env["LD_PRELOAD"] = self.shim
            env["MESSAGETAG_READ_FAULT_PATH"] = target
            env["MESSAGETAG_READ_FAULT_AFTER"] = str(fail_after)
            return subprocess.run(
                [self.exe, "verify", "--key-hex", "0001", "--file", path,
                 "--tag-hex", tag],
                capture_output=True, env=env)

        # Control: shim aimed elsewhere must not disturb a normal verify.
        control = run_injected(1, target=path + ".not-the-target")
        self.assertVerifyOk(control, "shim control run")

        for fail_after in (1, READ_CHUNK, len(data) - 1):
            with self.subTest(fail_after=fail_after):
                result = run_injected(fail_after)
                self.assertEqual(result.returncode, 1,
                                 f"fail_after={fail_after}: expected exit 1, "
                                 f"got {result.returncode}")
                self.assertEqual(result.stdout, b"",
                                 f"fail_after={fail_after}: no OK may be "
                                 f"printed for a partially read message")
                self.assertIn(b"read", result.stderr.lower())

    def test_58_verify_empty_file_ok(self):
        """An empty file is a valid message for verification too."""
        tag = expected_hmac("0b" * 20, b"")
        self.assertVerifyOk(
            self.run_verify("0b" * 20, self.fixture("empty"), tag),
            "empty file")

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


def main():
    if len(sys.argv) not in (2, 3):
        print("usage: regression_test.py /path/to/messagetag "
              "[/path/to/libread_fault_shim.so]", file=sys.stderr)
        return 2
    TagRegression.exe = os.path.abspath(sys.argv[1])
    TagRegression.tmpdir = None
    TagRegression.shim_path = (os.path.abspath(sys.argv[2])
                               if len(sys.argv) == 3 else None)
    argv = [sys.argv[0], "-v"]
    # unittest's TextTestRunner gives non-zero exit when a test fails.
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TagRegression)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
