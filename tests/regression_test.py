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

The mirror-image case is pinned just as hard: *recoverable* output
trouble -- short writes and transient EINTRs, including interruptions
before the first byte, after a non-empty prefix, and when only the
trailing newline remains -- must still end in exit 0 with exactly the
complete result line on stdout (the accepted prefix appearing exactly
once, in order, with no duplication and no missing trailing newline) and
empty stderr. The shim's scripted mode
(MESSAGETAG_WRITE_FAULT_SCRIPT) replays those sequences deterministically
and appends every intercepted write to a trace file, so the tests prove
the interruptions were actually injected rather than the shim being
inert. A permanent error (EPIPE/ENOSPC/EIO) arriving after such
recoverable steps keeps the original failure contract: exit 1, only the
accepted prefix on stdout, one output-write diagnostic.

The ``verify`` suite additionally pins: success prints exactly ``OK\\n``;
a tag that fails to authenticate gives exit 3 with empty stdout and a
diagnostic that neither names a cause nor leaks the recomputed tag, a
matching prefix or the key; the supplied tag must be exactly 64 hex
characters (the ``tag`` output with its trailing newline removed, no new
encapsulation); and parameter format is checked before the file is opened.

The ``--file -`` (standard input) suite pins: piped bytes authenticate to
the same independently computed tags as the same bytes in a file (empty
input included); bytes arriving in installments give the same tag and
nothing is output before the input ends; a file literally named ``-``
stays readable as ``./-`` while ``--file -`` keeps meaning standard input;
parameter errors are reported (exit 2) without waiting for input that
never ends; an unreadable standard input, and a read error after a
non-empty prefix (injected via the read-fault shim with the message file
as fd 0), are exit 1 with empty stdout and a standard-input read
diagnostic -- the received prefix is never authenticated as the message.
It also pins the recoverable counterpart: a read(2) interrupted with
EINTR before any byte arrived (including the empty message's EOF read) or
after a non-empty prefix -- once or in a finite burst, with later bytes
still arriving in batches that contain NUL bytes and cross the 64 KiB
read boundary -- must simply be retried, so both commands still
authenticate the complete message (tag: exit 0 with the independently
computed tag; verify: OK for the whole-message tag and exit 3 for a tag
matching only the pre-interruption prefix), and nothing is concluded
while the input is still open. The read shim's scripted mode
(MESSAGETAG_READ_FAULT_SCRIPT) replays those reads deterministically and
traces every intercepted read, so the interruptions are proven real
rather than replaced by delayed or chunked delivery. A permanent read
error arriving after such recovery keeps exit 1 with empty stdout and the
standard-input read diagnostic, even when verify's supplied tag matches
the prefix received so far.

Key handling at the 64-byte SHA-256 block-size boundary is pinned against
the same independent bases (hard-coded constants re-derived from Python's
hmac/hashlib at runtime): zero bytes appended to a non-empty key of at
most 64 decoded bytes (63 padded to exactly 64 included) cannot change
the tag and the padded forms cross-verify; one zero byte further (65
bytes) crosses the block size, so the key is hashed and yields the
standard long-key tag -- identical to its SHA-256 digest supplied as a
32-byte key -- and the original tag is a plain mismatch for it; a key of
exactly 64 bytes is used as-is and differs from its own digest as a key,
while longer keys match their digest as a key; the digest is supplied as
the hex of its raw 32 bytes, never as the digest text's characters; and
the empty key stays a parameter error. All relations hold on the empty
message and on a NUL-containing message, from file and standard input.

Usage:

    python3 tests/regression_test.py /path/to/messagetag \
        [/path/to/libread_fault_shim.so] \
        [/path/to/libwrite_fault_shim.so]
"""

import errno
import hashlib
import hmac as py_hmac
import os
import re
import select
import shutil
import stat
import subprocess
import sys
import tempfile
import time
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

# ---------------------------------------------------------------------------
# Keys at the 64-byte SHA-256 block-size boundary
#
# RFC 2104 key normalization, which every conforming HMAC implementation
# applies: a key of at most 64 bytes is zero-padded to the 64-byte block
# (appending zero bytes to such a key cannot change the tag), while a key
# longer than 64 bytes is first replaced by its SHA-256 digest (it then
# authenticates exactly like that 32-byte digest used as the key). A key of
# exactly 64 bytes is used as-is and is NOT interchangeable with its own
# digest. Key lengths here are always decoded-byte lengths: 64 key bytes
# are 128 hex characters on the command line.
# ---------------------------------------------------------------------------

KB_MESSAGES = {
    # Every relation must hold on the empty message and on a non-empty
    # message containing zero bytes with content after them alike.
    "empty": b"",
    "nul": b"\x00key-boundary\x00tail",
}

KB_SHORT = "0b" * 20                     # 20-byte key
KB_KEY63 = bytes(range(1, 64)).hex()     # 63 bytes: 01 02 ... 3e 3f
KB_KEY64 = KB_KEY63 + "00"               # zero-padded to exactly 64 bytes
KB_KEY65 = KB_KEY63 + "0000"             # one zero byte past the boundary
KB_LONG = bytes((i * 7 + 2) % 256
                for i in range(100)).hex()   # 100 bytes: well past it
KB_ZERO1 = "00"                          # a single zero byte: a legal key
KB_ZERO64 = "00" * 64                    # its zero-padded form at the boundary
KB_ZERO65 = "00" * 65                    # one zero byte past it

# SHA-256 digests of the raw key bytes, themselves usable as 32-byte keys.
# They reach --key-hex as the hexadecimal of the 32 digest bytes (64 hex
# characters) -- never as the digest's hexadecimal *text*.
KB_KEY64_DIGEST = hashlib.sha256(bytes.fromhex(KB_KEY64)).hexdigest()
KB_KEY65_DIGEST = hashlib.sha256(bytes.fromhex(KB_KEY65)).hexdigest()
KB_LONG_DIGEST = hashlib.sha256(bytes.fromhex(KB_LONG)).hexdigest()

# Hard-coded expected tags for the boundary keys, computed independently of
# the program with Python's hmac/hashlib and re-derived at runtime by
# KeyBoundaryRegression.test_120. Only distinct values appear: a padded or
# digest form shares its base key's standard tag by definition, and the
# suite proves the program reproduces that sharing rather than assuming it.
KB_TAGS = {
    ("empty", "short"):
        "999a901219f032cd497cadb5e6051e97b6a29ab297bd6ae722bd6062a2f59542",
    ("empty", "k63"):
        "6d3f298be7bae388fd14e89cc2343c2aecb21cc32528bbc5fb7b088330411e99",
    ("empty", "k65"):
        "8fad81043946ebc2c9dab07dd2e63002e4f9ba5f8c2e83a14172281bf71d73a7",
    ("empty", "k64digest"):
        "6f629726d25f724ac335c3eee5c508a80e5abd76196ea92a52973dc93f577834",
    ("empty", "long"):
        "f3f5b57698dc2d4662795bf2a3baafb20c9faac11e69b7835d7c44ce4fd6b0ad",
    ("empty", "zero"):
        "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
    ("empty", "zero65"):
        "2dc19480eae3a02d634b585f777b82d13b92d3683016bb3266718cc5e8089417",
    ("nul", "short"):
        "9ec678925ddd43fd76a2357452a1f5ef8289d1a00472566f1a427c051ca4722a",
    ("nul", "k63"):
        "f9daccf42b6296e9b4dbdac12b773781d5f1cc783c06d36792df5d1dd9d59d58",
    ("nul", "k65"):
        "ff919a5aff633b948b892f449ba1a4385b18dbfeb37a7e6be28a86909115d431",
    ("nul", "k64digest"):
        "07eb39fa5ed965d6d01ebd8ca8c57fe66d9c7c644a66cce956052476853770e2",
    ("nul", "long"):
        "3e02e3c73deeeb1caeac231ff34c82999ede6f3ffe32ad6aaf79c04832dfb5f1",
    ("nul", "zero"):
        "ac4a277bece14e672cb30768c40d74926a6a76f9df8c2a93c167a6840f4328f9",
    ("nul", "zero65"):
        "4e0b6c12ae88174163a3e9c43b98ce34563b9fbaf2c337617e222aeec5eae8ec",
}

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


# ---------------------------------------------------------------------------
# Scripted read faults: recoverable read interruptions (transient EINTRs
# interleaved with bounded short reads), optionally followed by a permanent
# read error. They model a read(2) that is temporarily interrupted *before*
# any byte arrived -- not merely bytes arriving in installments.
# ---------------------------------------------------------------------------

# Errno names the read-fault shim accepts in MESSAGETAG_READ_FAULT_SCRIPT,
# as (script token -> numeric errno).
READ_SCRIPT_ERRNOS = {
    "EINTR": errno.EINTR,
    "EPIPE": errno.EPIPE,
    "ENOSPC": errno.ENOSPC,
    "EIO": errno.EIO,
}


def read_script_env(shim, steps, trace_path, fd=0):
    """Environment for running messagetag under the read-fault shim in
    scripted mode on ``fd`` (default standard input). ``steps`` is a list of
    positive integers (bound the next read to at most that many bytes -- an
    ordinary short read), "PASS" (one read slot passes through untouched),
    "EINTR" (fail that read with EINTR, expecting the caller to retry) and
    "EPIPE"/"ENOSPC"/"EIO" (fail permanently from that read on). Once the
    script is exhausted reads pass through untouched. The shim appends one
    line per intercepted read to ``trace_path`` so the tests can prove the
    interruptions really happened, in order."""
    env = dict(os.environ)
    env["LD_PRELOAD"] = shim
    env["MESSAGETAG_READ_FAULT_FD"] = str(fd)
    env["MESSAGETAG_READ_FAULT_SCRIPT"] = ",".join(str(s) for s in steps)
    env["MESSAGETAG_READ_FAULT_TRACE"] = trace_path
    if os.path.exists(trace_path):
        os.unlink(trace_path)
    return env


def read_read_trace(trace_path):
    """The read shim's trace: b"D<n>" (n bytes delivered), b"E<n>" (read
    failed with errno n) and b"P<n>" (n bytes delivered by a read that
    passed through after the script ended)."""
    with open(trace_path, "rb") as f:
        return f.read().split()


def expected_read_trace(steps, length):
    """Replay ``steps`` against an input of ``length`` bytes exactly the way
    the shim and a correct caller interact on a regular file handed over as
    fd 0:

    * an integer step bounds one read(2) to N bytes; regular files return
      exactly min(N, remaining) bytes, and 0 only at EOF;
    * "PASS" lets one read through with the caller's 65536-byte count;
    * "EINTR" fails one read and is retried, even when only the EOF read
      remains (e.g. the empty message);
    * a permanent errno fails one read and ends the stream at the number of
      bytes delivered so far.

    A 0-byte result ends the stream, so later script slots are never
    consumed. Reads after the script is exhausted pass through untouched,
    65536 bytes at a time, ending in the 0-byte EOF read.

    Returns (events, delivered, latched): the exact trace lines, how many
    message bytes were delivered, and whether a permanent error latched."""
    events = []
    remaining = length
    for step in steps:
        if step == "EINTR":
            # Interrupted before any byte arrived (possibly on the EOF read
            # itself); the caller retries with the next script slot.
            events.append(b"E%d" % errno.EINTR)
            continue
        if step == "PASS":
            cap = READ_CHUNK
            n = min(cap, remaining)
            events.append(b"P%d" % n)
        elif isinstance(step, str):
            events.append(b"E%d" % READ_SCRIPT_ERRNOS[step])
            return events, length - remaining, True
        else:
            n = min(step, remaining)
            events.append(b"D%d" % n)
        if n == 0:
            # Clean EOF: the caller stops; remaining script slots are never
            # reached.
            return events, length, False
        remaining -= n
    # Script exhausted: ordinary 65536-byte reads until EOF, then the final
    # zero-byte read.
    while remaining > 0:
        n = min(READ_CHUNK, remaining)
        events.append(b"P%d" % n)
        remaining -= n
    events.append(b"P0")
    return events, length, False


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


# ---------------------------------------------------------------------------
# Scripted write faults: recoverable interruptions (short writes, EINTR)
# optionally followed by a permanent error.
# ---------------------------------------------------------------------------

# Errno names the write-fault shim accepts in MESSAGETAG_WRITE_FAULT_SCRIPT.
SCRIPT_ERRNOS = {
    "EINTR": errno.EINTR,
    "EPIPE": errno.EPIPE,
    "ENOSPC": errno.ENOSPC,
    "EIO": errno.EIO,
}


def run_with_write_script(argv, shim, steps, trace_path):
    """Run the full command ``argv`` with the write-fault shim in scripted
    mode: ``steps`` is a list of integers (deliver at most that many bytes
    of the next write -- a short write), "EINTR" (fail that write with
    EINTR, expecting the caller to retry) and "EPIPE"/"ENOSPC"/"EIO" (fail
    permanently from that write on). Once the script is exhausted, writes
    to standard output pass through untouched. The shim appends one line
    per intercepted write to ``trace_path`` so the test can prove the
    interruptions really happened, in order."""
    env = dict(os.environ)
    env["LD_PRELOAD"] = shim
    env["MESSAGETAG_WRITE_FAULT_FD"] = "1"
    env["MESSAGETAG_WRITE_FAULT_SCRIPT"] = ",".join(
        str(step) for step in steps)
    env["MESSAGETAG_WRITE_FAULT_TRACE"] = trace_path
    if os.path.exists(trace_path):
        os.unlink(trace_path)
    return subprocess.run(argv, capture_output=True, env=env)


def read_write_trace(trace_path):
    """The shim's trace as a list of events: b"D<n>" (n bytes delivered),
    b"E<n>" (write failed with errno n), b"P<n>" (n bytes passed through
    after the script ended)."""
    with open(trace_path, "rb") as f:
        return f.read().split()


def expected_write_trace(steps, line_len):
    """Replay ``steps`` against a result line of ``line_len`` bytes exactly
    the way the shim and a correct caller interact: an integer step
    delivers a short write of min(step, remaining) bytes, "EINTR" fails one
    write and is retried, a permanent errno fails one write and ends the
    attempt, and bytes still unsent when the script runs out go through as
    one final pass-through write. Returns (events, latched)."""
    events = []
    remaining = line_len
    for step in steps:
        if remaining == 0:
            break
        if isinstance(step, int):
            n = min(step, remaining)
            events.append(b"D%d" % n)
            remaining -= n
        elif step == "EINTR":
            events.append(b"E%d" % errno.EINTR)
        else:
            events.append(b"E%d" % SCRIPT_ERRNOS[step])
            return events, True
    if remaining > 0:
        events.append(b"P%d" % remaining)
    return events, False


def scripted_prefix_len(steps, line_len):
    """How many bytes of the result line the receiver holds once ``steps``
    ends in a permanent error: the short writes before it, each capped by
    what remains of the line."""
    remaining = line_len
    delivered = 0
    for step in steps:
        if remaining == 0:
            break
        if isinstance(step, int):
            n = min(step, remaining)
            delivered += n
            remaining -= n
        elif step == "EINTR":
            continue
        else:
            break
    return delivered


def run_tag_or_verify_script(case, argv, steps, tmpdir):
    """Shared driver for the scripted-fault tests: run ``argv`` under the
    shim with ``steps`` and return (result, trace). The trace is what makes
    the success cases non-vacuous -- without it, an inert shim would let
    every recoverable-fault test pass without injecting anything."""
    trace_path = os.path.join(tmpdir, "write-trace.log")
    result = run_with_write_script(argv, case.write_shim, steps, trace_path)
    return result, read_write_trace(trace_path)


def assert_recoverable_script_succeeds(case, argv, steps, tmpdir, full_line,
                                       assert_success, label=""):
    """A bounded sequence of short writes and EINTRs -- before any byte,
    mid-line, or with only the trailing newline left -- must not change
    the observable success contract: exit 0, empty stderr, and stdout
    holding exactly ``full_line`` once (the already-accepted prefix is not
    re-emitted, the remainder follows in order, the trailing newline is
    not dropped). The trace must show every scripted step was consumed,
    proving the interruptions were injected and retried."""
    result, trace = run_tag_or_verify_script(case, argv, steps, tmpdir)
    assert_success(result, label or f"steps={steps}")
    expected, latched = expected_write_trace(steps, len(full_line))
    case.assertFalse(latched, f"{label}: test bug: script latches")
    case.assertEqual(
        trace, expected,
        f"{label}: the shim must have injected exactly the scripted "
        f"interruptions (steps={steps}); got trace {trace}")
    # Belt and braces on top of assert_success: the line appears exactly
    # once -- no duplicated prefix, no re-emitted line after recovery.
    case.assertEqual(result.stdout.count(full_line), 1,
                     f"{label}: the complete line must appear exactly once")
    case.assertEqual(len(result.stdout), len(full_line),
                     f"{label}: no extra bytes around the result line")


def assert_scripted_permanent_failure(case, argv, steps, tmpdir, full_line,
                                      secret_hexes=(), label=""):
    """Recoverable steps followed by a permanent error keep the original
    failure contract: exit 1, only the prefix accepted before the
    permanent error on stdout, and exactly one output-write diagnostic --
    the earlier EINTRs and short writes neither turned the run into a
    success nor produced extra diagnostics."""
    result, trace = run_tag_or_verify_script(case, argv, steps, tmpdir)
    after = scripted_prefix_len(steps, len(full_line))
    assert_stdout_write_failure(
        case, result, full_line, after, secret_hexes=secret_hexes,
        label=label or f"steps={steps}")
    expected, latched = expected_write_trace(steps, len(full_line))
    case.assertTrue(latched, f"{label}: test bug: script never latches")
    case.assertEqual(
        trace, expected,
        f"{label}: the shim must have injected exactly the scripted "
        f"interruptions (steps={steps}); got trace {trace}")


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

    # -- recoverable output interruptions still deliver the full result ---

    def tag_script_success(self, steps, label=""):
        """Run tag under a scripted sequence of short writes / EINTRs that
        all recover, and pin the full success contract against the
        independently computed tag constant (never the program's own
        earlier output)."""
        assert_recoverable_script_succeeds(
            self, self.tag_argv(), steps, self.tmpdir, self.TAG_LINE,
            lambda r, lbl: self.assertTagSuccess(
                r, self.TAG_LINE[:-1].decode(), lbl),
            label or f"tag steps={steps}")

    def test_46_eintr_before_any_byte_still_succeeds(self):
        """Writes transiently interrupted before a single byte has been
        accepted must not fail the run or corrupt the result: once the
        write succeeds the whole 65-byte line lands exactly once, stderr
        stays empty and the exit code is 0."""
        if self.write_shim is None:
            self.skipTest("write-fault shim not available")
        for steps in (["EINTR"], ["EINTR", "EINTR", "EINTR"]):
            with self.subTest(steps=steps):
                self.tag_script_success(steps)

    def test_47_short_writes_and_eintr_interleaved_still_succeed(self):
        """A non-empty prefix already delivered, then interruptions and
        more short writes: the receiver keeps the prefix exactly once and
        the remainder follows in order, so stdout is exactly the tag line.
        Includes scripts with no EINTR at all (pure short writes) and
        bursts of consecutive interrupts."""
        if self.write_shim is None:
            self.skipTest("write-fault shim not available")
        scripts = [
            [10, "EINTR"],
            [1, "EINTR", "EINTR"],
            [32, "EINTR", 20, "EINTR"],
            [7, "EINTR", "EINTR", 7, 7, 7, "EINTR", 7],
            [1, 2, 3, "EINTR", 5, 8, "EINTR", 13, 21],
            [10, 20, 30, 4, 1],          # short writes only, no interrupt
            [1] * 64 + [1],              # one byte at a time, no interrupt
        ]
        for steps in scripts:
            with self.subTest(steps=steps):
                self.tag_script_success(steps)

    def test_48_only_trailing_newline_left_when_interrupted(self):
        """All 64 tag characters accepted, only the trailing newline left,
        and the write is then interrupted one or more times: the command
        must not finish early (the newline is still owed), and after
        recovery it must emit just the newline -- not restart the line,
        which would duplicate the tag on stdout."""
        if self.write_shim is None:
            self.skipTest("write-fault shim not available")
        scripts = [
            [64, "EINTR"],
            [64, "EINTR", "EINTR"],
            [10, 54, "EINTR"],
            [63, "EINTR", 1, "EINTR"],
        ]
        for steps in scripts:
            with self.subTest(steps=steps):
                self.tag_script_success(steps)

    def test_49_permanent_error_after_recoverable_steps(self):
        """EINTRs and short writes that recover, then a permanent error
        (EPIPE/ENOSPC/EIO) before the line is complete: the original
        failure contract applies unchanged -- exit 1, only the accepted
        prefix on stdout, one output-write diagnostic, no usage, no key or
        tag echoed. The earlier recoverable interruptions must not have
        turned the run into a success or added diagnostics."""
        if self.write_shim is None:
            self.skipTest("write-fault shim not available")
        scripts = [
            ["EINTR", "EPIPE"],                       # nothing delivered
            ["EINTR", "EINTR", "ENOSPC"],
            [10, "EINTR", "EPIPE"],                   # prefix, interrupt
            [5, "EINTR", 9, "EINTR", "EIO"],          # interleaved
            [64, "EINTR", "ENOSPC"],                  # only newline owed
            [1, "EINTR", 63, "EIO"],                  # one byte short
        ]
        for steps in scripts:
            with self.subTest(steps=steps):
                assert_scripted_permanent_failure(
                    self, self.tag_argv(), steps, self.tmpdir, self.TAG_LINE,
                    secret_hexes=("0001",), label=f"tag steps={steps}")



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

    # -- recoverable output interruptions still deliver the full result ---

    GOOD_TAG = ("307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11"
                "a77b4d5d")

    def verify_script_success(self, steps, label=""):
        """Run verify under a scripted sequence of short writes / EINTRs
        that all recover: a passed authentication must still surface as
        exit 0, exactly b'OK\\n' on stdout and empty stderr -- the
        interruption must not turn a valid authentication into a reported
        failure."""
        assert_recoverable_script_succeeds(
            self, self.verify_argv(), steps, self.tmpdir, self.OK_LINE,
            self.assertVerifyOk, label or f"verify steps={steps}")

    def test_94_eintr_and_short_writes_still_give_ok(self):
        """Transient EINTRs -- before any byte, after a non-empty prefix,
        and when only the trailing newline is left -- plus interleaved
        short writes must not fail a passing verification: exit 0, stdout
        exactly 'OK\\n' once, stderr empty. The shim trace proves each
        interruption was really injected and retried."""
        if self.write_shim is None:
            self.skipTest("write-fault shim not available")
        scripts = [
            ["EINTR"],                       # interrupted before any byte
            ["EINTR", "EINTR", "EINTR"],
            [1, "EINTR"],                    # "O" delivered, then interrupt
            [1, "EINTR", 1, "EINTR"],
            [1, "EINTR", "EINTR", 1],
            [2, "EINTR"],                    # "OK" out, only '\n' owed
            [2, "EINTR", "EINTR"],
            [1, 1, 1],                       # short writes only
        ]
        for steps in scripts:
            with self.subTest(steps=steps):
                self.verify_script_success(steps)

    def test_95_permanent_error_after_recoverable_steps(self):
        """Recoverable interruptions followed by a permanent error keep
        the original failure contract: exit 1, only the accepted prefix
        on stdout (never a complete 'OK\\n'), one output-write diagnostic
        that leaks neither the key nor the supplied/recomputed tag."""
        if self.write_shim is None:
            self.skipTest("write-fault shim not available")
        scripts = [
            ["EINTR", "EPIPE"],                  # nothing delivered
            ["EINTR", "EINTR", "EIO"],
            [1, "EINTR", "ENOSPC"],              # "O" delivered
            [1, "EINTR", 1, "EINTR", "EPIPE"],   # "OK" delivered
            [2, "EINTR", "EIO"],                 # only newline owed
        ]
        for steps in scripts:
            with self.subTest(steps=steps):
                assert_scripted_permanent_failure(
                    self, self.verify_argv(), steps, self.tmpdir,
                    self.OK_LINE, secret_hexes=("0001", self.GOOD_TAG),
                    label=f"verify steps={steps}")


class StdinRegression(unittest.TestCase):
    """Contract for ``--file -``: the message comes from standard input.

    Every byte delivered before the normal end of input is authenticated
    exactly as if it had been read from a file, so the expected tags are
    the same independently computed constants used by the file suites.
    """

    exe = None
    tmpdir = None
    shim_path = None
    shim = None

    HELLO_LF_TAG = ("307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11"
                    "a77b4d5d")

    @classmethod
    def setUpClass(cls):
        if not cls.exe or not os.path.isfile(cls.exe):
            raise RuntimeError("messagetag executable not found: %r" % cls.exe)
        cls.tmpdir = tempfile.mkdtemp(prefix="messagetag-stdin-")
        cls.shim = find_read_fault_shim(cls.shim_path, cls.exe, cls.tmpdir)

    @classmethod
    def tearDownClass(cls):
        if cls.tmpdir and os.path.isdir(cls.tmpdir):
            shutil.rmtree(cls.tmpdir, ignore_errors=True)

    # -- helpers ------------------------------------------------------------

    def run_tag_stdin(self, key_hex, data, *extra, **kwargs):
        return subprocess.run(
            [self.exe, "tag", "--key-hex", key_hex, "--file", "-", *extra],
            input=data, capture_output=True, **kwargs)

    def run_verify_stdin(self, key_hex, data, tag_hex, *extra, **kwargs):
        return subprocess.run(
            [self.exe, "verify", "--key-hex", key_hex, "--file", "-",
             "--tag-hex", tag_hex, *extra],
            input=data, capture_output=True, **kwargs)

    def assertTagSuccess(self, result, expected_tag, label=""):
        self.assertEqual(
            result.returncode, 0,
            f"{label}: expected exit 0, got {result.returncode}; "
            f"stderr={result.stderr!r}")
        self.assertEqual(result.stderr, b"",
                         f"{label}: stderr must be empty, got {result.stderr!r}")
        self.assertEqual(result.stdout, expected_tag.encode() + b"\n",
                         f"{label}: wrong tag, got {result.stdout!r}")

    def assertStdinReadFailure(self, result, label=""):
        """A standard-input read failure: exit 1, empty stdout, one stderr
        line that names the standard-input read failure and leaks neither
        key nor tag material."""
        self.assertEqual(
            result.returncode, 1,
            f"{label}: expected exit 1, got {result.returncode}; "
            f"stdout={result.stdout!r} stderr={result.stderr!r}")
        self.assertEqual(result.stdout, b"",
                         f"{label}: no result may be produced from a "
                         f"partially read input")
        self.assertNotEqual(result.stderr, b"",
                            f"{label}: a read failure must be reported")
        lower = result.stderr.lower()
        self.assertIn(b"read", lower,
                      f"{label}: diagnostic must name the read failure")
        self.assertIn(b"standard input", lower,
                      f"{label}: diagnostic must name standard input")
        self.assertNotRegex(result.stderr, rb"(?i)[0-9a-f]{64}",
                            f"{label}: stderr must not contain a tag")

    # -- the same bytes give the same tag, from file or standard input ------

    def test_100_stdin_matches_file_and_independent_constants(self):
        """Piping the fixture bytes through ``--file -`` must reproduce the
        independently computed constant tags (re-derived via the stdlib in
        TagRegression.test_00): empty input, NUL bytes and what follows
        them, every newline form, trailing newlines, messages spanning
        several read chunks and exact chunk multiples."""
        names = ["empty", "hello", "hello_lf", "hello_crlf", "hello_cr",
                 "nul", "nul_truncated", "lf_in_middle", "cr_in_middle",
                 "large", "large_mid", "block1", "block2", "block3",
                 "block1_minus", "block1_plus"]
        vectors = {name: (key, msg, tag)
                   for name, key, msg, tag in PROJECT_VECTORS}
        for name in names:
            key, message, tag = vectors[name]
            with self.subTest(fixture=name):
                self.assertTagSuccess(
                    self.run_tag_stdin(key, message), tag, name)

    def test_101_empty_stdin_is_valid_message(self):
        """End of input before any byte is the empty message, not an
        error: the standard empty-message tag is produced."""
        self.assertTagSuccess(
            self.run_tag_stdin("0b" * 20, b""),
            "999a901219f032cd497cadb5e6051e97b6a29ab297bd6ae722bd6062a2f59542")

    def test_102_chunked_arrival_same_tag_and_no_early_output(self):
        """Bytes arriving in several installments authenticate exactly as
        the same bytes arriving at once, and nothing is output (and no
        conclusion is reached) while the input is still open: after a
        partial write the process must still be waiting with an empty
        stdout, and only the final close releases the tag line."""
        data = large_bytes()
        proc = subprocess.Popen(
            [self.exe, "tag", "--key-hex", LARGE_KEY_HEX, "--file", "-"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        try:
            # Feed the message in uneven pieces that do not line up with
            # the 64 KiB read buffer.
            pieces = [data[:1], data[1:65537], data[65537:65537 + 123],
                      data[65537 + 123:]]
            for piece in pieces[:3]:
                proc.stdin.write(piece)
                proc.stdin.flush()
            # The message is incomplete: no tag, no exit, no prompt.
            self.assertIsNone(
                proc.poll(),
                "no conclusion may be reached before the input ends")
            readable, _, _ = select.select([proc.stdout], [], [], 0.5)
            self.assertEqual(
                readable, [],
                "nothing may be written before the input ends")
            proc.stdin.write(pieces[3])
            proc.stdin.close()
            proc.stdin = None  # communicate() must not touch it again
            stdout, stderr = proc.communicate(timeout=30)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        self.assertEqual(proc.returncode, 0, f"stderr={stderr!r}")
        self.assertEqual(stderr, b"")
        self.assertEqual(stdout, expected_hmac(LARGE_KEY_HEX, data).encode()
                      + b"\n")

    def test_103_verify_stdin_ok_and_mismatch(self):
        ok = self.run_verify_stdin("0001", b"hello\n", self.HELLO_LF_TAG)
        self.assertEqual(ok.returncode, 0, f"stderr={ok.stderr!r}")
        self.assertEqual(ok.stdout, b"OK\n")
        self.assertEqual(ok.stderr, b"")
        # The same tag against different piped bytes is a plain mismatch:
        # exit 3, empty stdout, no cause assigned.
        bad = self.run_verify_stdin("0001", b"hello", self.HELLO_LF_TAG)
        self.assertEqual(bad.returncode, 3, f"stderr={bad.stderr!r}")
        self.assertEqual(bad.stdout, b"")
        self.assertIn(b"mismatch", bad.stderr.lower())
        self.assertNotRegex(bad.stderr, rb"(?i)[0-9a-f]{64}")

    def test_104_dash_named_file_and_stdin_precedence(self):
        """Only a --file value of exactly "-" selects standard input. A
        file literally named "-" stays readable as "./-", and "--file -"
        in the same directory still reads standard input, not that file."""
        dash_dir = os.path.join(self.tmpdir, "dashdir")
        os.makedirs(dash_dir, exist_ok=True)
        with open(os.path.join(dash_dir, "-"), "wb") as f:
            f.write(b"hello\n")
        # "./-" reads the file named "-".
        r = subprocess.run(
            [self.exe, "tag", "--key-hex", "0001", "--file", "./-"],
            capture_output=True, cwd=dash_dir)
        self.assertTagSuccess(r, self.HELLO_LF_TAG, "file named - via ./-")
        # "--file -" in the very same directory reads standard input:
        # piping different bytes must give those bytes' tag, not the
        # file's, and piping the same bytes gives the same tag as the file.
        via_stdin = self.run_tag_stdin("0001", b"hello\n", cwd=dash_dir)
        self.assertTagSuccess(via_stdin, self.HELLO_LF_TAG,
                              "same bytes via stdin")
        different = self.run_tag_stdin("0001", b"hello", cwd=dash_dir)
        self.assertTagSuccess(
            different,
            "ee44e44a606a62df24b198d7130faa42a53e2aa5db4133210fd7c657aa7bb6ab",
            "stdin wins over the file named -")

    # -- parameter errors are reported before standard input is read -------

    def test_105_parameter_errors_do_not_wait_for_stdin(self):
        """An invalid key, an invalid tag or a missing required option is
        exit 2 with the command's usage even when the upstream never ends
        its input: the command must not block waiting for the message."""
        invocations = [
            [self.exe, "tag", "--key-hex", "zz", "--file", "-"],
            [self.exe, "tag", "--key-hex", "0001"],          # no --file
            [self.exe, "tag", "--key-hex", "0001", "--file", "-",
             "--bogus", "x"],
            [self.exe, "verify", "--key-hex", "0001", "--file", "-",
             "--tag-hex", "abc"],
            [self.exe, "verify", "--key-hex", "zz", "--file", "-",
             "--tag-hex", self.HELLO_LF_TAG],
            [self.exe, "verify", "--key-hex", "0001", "--file", "-"],
        ]
        for argv in invocations:
            with self.subTest(argv=argv[2:]):
                proc = subprocess.Popen(
                    argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)
                try:
                    # The write end of stdin stays open the whole time; a
                    # command that tried to read the message first would
                    # block here.
                    rc = proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate()
                    self.fail(f"{argv[2:]}: parameter error must be "
                              f"reported without waiting for standard input")
                finally:
                    if proc.poll() is None:
                        proc.kill()
                stdout = proc.stdout.read()
                stderr = proc.stderr.read()
                proc.stdin.close()
                self.assertEqual(rc, 2, f"{argv[2:]}: stderr={stderr!r}")
                self.assertEqual(stdout, b"")
                self.assertIn(USAGE_MARKER, stderr)

    # -- standard-input read failures ---------------------------------------

    def test_106_unreadable_stdin_exit_1(self):
        """A standard input that cannot be read at all (here: a directory
        handed over as fd 0, so the very first read fails) is exit 1 with
        empty stdout and a standard-input read diagnostic -- for both
        commands."""
        dir_fd = os.open(self.tmpdir, os.O_RDONLY)
        try:
            for argv in (
                [self.exe, "tag", "--key-hex", "0001", "--file", "-"],
                [self.exe, "verify", "--key-hex", "0001", "--file", "-",
                 "--tag-hex", self.HELLO_LF_TAG],
            ):
                with self.subTest(command=argv[1]):
                    r = subprocess.run(argv, stdin=dir_fd,
                                       capture_output=True)
                    self.assertStdinReadFailure(r, argv[1])
        finally:
            os.close(dir_fd)

    def test_107_read_error_after_partial_stdin(self):
        """Standard input delivers a non-empty prefix and then fails: the
        received prefix must never be authenticated as the whole message.
        tag must not print the prefix's (perfectly valid) tag; verify must
        neither accept the prefix's tag nor report a mismatch against the
        whole message's tag -- both are exit 1 with empty stdout."""
        if self.shim is None:
            self.skipTest("read-fault shim not available (build with CMake "
                          "or pass its path as the second argument)")
        if not os.path.exists("/proc/self/fd"):
            self.skipTest("read-fault shim needs /proc/self/fd (Linux)")

        data = stream_bytes(READ_CHUNK + 5000)
        path = os.path.join(self.tmpdir, "stdin-midread.bin")
        with open(path, "wb") as f:
            f.write(data)
        whole_tag = expected_hmac("0001", data)

        env = dict(os.environ)
        env["LD_PRELOAD"] = self.shim
        env["MESSAGETAG_READ_FAULT_PATH"] = path

        def run_injected(argv, fail_after):
            env["MESSAGETAG_READ_FAULT_AFTER"] = str(fail_after)
            fd = os.open(path, os.O_RDONLY)
            try:
                return subprocess.run(argv, stdin=fd, capture_output=True,
                                      env=env)
            finally:
                os.close(fd)

        for fail_after in (1, 5000, READ_CHUNK, len(data) - 1):
            prefix_tag = expected_hmac("0001", data[:fail_after])
            with self.subTest(fail_after=fail_after):
                r = run_injected(
                    [self.exe, "tag", "--key-hex", "0001", "--file", "-"],
                    fail_after)
                self.assertStdinReadFailure(r, f"tag fail_after={fail_after}")
                self.assertNotIn(prefix_tag.encode(), r.stdout)

                # Correct tag for the WHOLE message: finalizing the prefix
                # would surface as a mismatch (exit 3), which is wrong too.
                r = run_injected(
                    [self.exe, "verify", "--key-hex", "0001", "--file", "-",
                     "--tag-hex", whole_tag],
                    fail_after)
                self.assertStdinReadFailure(
                    r, f"verify whole-tag fail_after={fail_after}")

                # A tag matching only the delivered prefix must not turn
                # the read failure into a successful verification.
                r = run_injected(
                    [self.exe, "verify", "--key-hex", "0001", "--file", "-",
                     "--tag-hex", prefix_tag],
                    fail_after)
                self.assertStdinReadFailure(
                    r, f"verify prefix-tag fail_after={fail_after}")

    # -- recoverable read interruptions (transient EINTR) ------------------
    #
    # A read(2) interrupted with EINTR before any byte arrived is not a
    # failure and not an end of input: messagetag retries the read and keeps
    # authenticating. The read-fault shim's scripted mode replays such
    # interruptions deterministically (one script step per intercepted read,
    # recorded in a trace file), so -- unlike mere delayed or chunked
    # delivery -- every case below really experiences read(2) returning -1
    # with errno EINTR.

    # A 70000-byte message: a NUL-led prefix whose bytes after the NUL must
    # count, followed by a position-dependent stream that itself contains
    # further NUL bytes and runs well past the 64 KiB read boundary. The
    # expected tags rest on Python's hmac (expected_hmac), an implementation
    # unrelated to the program under test, and are pinned to hard-coded
    # constants below; the program's own output is never the oracle.
    EINTR_KEY = "0001"
    EINTR_MSG_LEN = 70000
    EINTR_NUL_PREFIX = b"\x00bytes-after-nul\n"      # 17 bytes
    EINTR_MSG_TAG = ("ff2b937a6d336b0c5653f509966faddc"
                     "7bd3465d6430d5fab6d2da5c8d219a78")
    # HMAC of strict prefixes: a read that wrongly finalized the message at
    # the interruption point would emit (tag) or accept (verify) one of
    # these.
    EINTR_TAG_PREFIX10 = ("758809c29e817b21aa665020f5f2f812"
                          "ffc8a824f00b994cc5f95a2a873ddd57")
    EINTR_TAG_PREFIX100 = ("2400240bc58a673137590535026274eb"
                           "1dd82b537824f492904b1faae46a63a1")
    EINTR_TAG_EMPTY = ("baafaeb488bb08400d215ebca2c9b50229"
                       "94a40cc7754cda868210be62054281")

    _read_script_seq = 0

    @classmethod
    def interrupted_message(cls):
        tail = cls.EINTR_MSG_LEN - len(cls.EINTR_NUL_PREFIX)
        return cls.EINTR_NUL_PREFIX + stream_bytes(tail)

    def require_read_shim(self):
        if self.shim is None:
            self.skipTest("read-fault shim not available (build with CMake "
                          "or pass its path as the second argument)")
        if not os.path.exists("/proc/self/fd"):
            self.skipTest("read-fault shim needs /proc/self/fd (Linux)")

    def run_stdin_read_script(self, argv, steps, data, label):
        """Run ``argv`` with ``data`` in a regular file handed over as fd 0
        and the read shim scripted on fd 0. Returns (result, trace). The
        regular file makes every bounded read exact (like test_107); the
        trace proves each scripted interruption really happened."""
        self.require_read_shim()
        path = os.path.join(self.tmpdir, "eintr-%s.bin" % label)
        with open(path, "wb") as f:
            f.write(data)
        StdinRegression._read_script_seq += 1
        trace_path = os.path.join(
            self.tmpdir, "read-trace-%d.log" % self._read_script_seq)
        env = read_script_env(self.shim, steps, trace_path)
        fd = os.open(path, os.O_RDONLY)
        try:
            result = subprocess.run(argv, stdin=fd, capture_output=True,
                                    env=env)
        finally:
            os.close(fd)
        return result, read_read_trace(trace_path)

    def assertReadTraceExact(self, trace, steps, length, label,
                             latched=False):
        expected, _delivered, did_latch = expected_read_trace(steps, length)
        self.assertEqual(
            trace, expected,
            f"{label}: the shim must have injected exactly the scripted "
            f"read steps (steps={steps}); got trace {trace}")
        self.assertEqual(did_latch, latched, f"{label}: latch mismatch")

    def tag_script_argv(self):
        return [self.exe, "tag", "--key-hex", self.EINTR_KEY, "--file", "-"]

    def verify_script_argv(self, tag_hex):
        return [self.exe, "verify", "--key-hex", self.EINTR_KEY,
                "--file", "-", "--tag-hex", tag_hex]

    def test_108_eintr_before_first_message_byte(self):
        """The very first read of standard input -- before any message byte
        has arrived -- is interrupted once or in a finite burst, then
        recovers. tag must still exit 0 with empty stderr and the tag of
        the complete (NUL-containing, boundary-spanning) message, and the
        trace must show the EINTR read(s) really happened and were
        retried."""
        msg = self.interrupted_message()
        # The hard-coded constant must equal the independently computed
        # stdlib HMAC, so this assertion cannot be fooled by a typo.
        self.assertEqual(expected_hmac(self.EINTR_KEY, msg),
                         self.EINTR_MSG_TAG)
        for steps in (["EINTR"], ["EINTR", "EINTR", "EINTR"]):
            with self.subTest(steps=steps):
                result, trace = self.run_stdin_read_script(
                    self.tag_script_argv(), steps, msg,
                    "before-first-%d" % len(steps))
                self.assertTagSuccess(result, self.EINTR_MSG_TAG,
                                      f"steps={steps}")
                self.assertReadTraceExact(trace, steps, len(msg),
                                          f"steps={steps}")

    def test_109_eintr_after_nonempty_prefix_recovers_with_batches(self):
        """A non-empty prefix already received, then one or several
        consecutive EINTRs, then reading resumes with bytes still arriving
        in bounded batches; interruptions are also placed directly on the
        64 KiB chunk boundary and right after an interior NUL byte. The
        already received content is neither lost nor repeated nor
        reordered: the result is the tag of the whole message and the trace
        accounts for every byte exactly once."""
        msg = self.interrupted_message()
        # A NUL byte from the position-dependent stream sits at stream
        # offset 75, i.e. absolute offset 92 after the 17-byte NUL prefix.
        self.assertEqual(msg[0], 0)
        self.assertEqual(msg[92], 0)
        scripts = [
            [10, "EINTR"],
            [110, "EINTR"],                            # just past NUL@92
            [100, "EINTR", "EINTR"],                  # burst after prefix
            [READ_CHUNK, "EINTR"],                    # on the 64 KiB edge
            ["PASS", "EINTR", 100, "EINTR"],          # full chunk, resume
            [10, "EINTR", "EINTR", 100, 1000, "EINTR", 40000, 10000],
        ]
        for steps in scripts:
            with self.subTest(steps=steps):
                result, trace = self.run_stdin_read_script(
                    self.tag_script_argv(), steps, msg,
                    "prefix-%d" % len(repr(steps)))
                self.assertTagSuccess(result, self.EINTR_MSG_TAG,
                                      f"steps={steps}")
                self.assertReadTraceExact(trace, steps, len(msg),
                                          f"steps={steps}")
                # Exactly one result line: no re-emitted prefix around it.
                self.assertEqual(
                    result.stdout, self.EINTR_MSG_TAG.encode() + b"\n")

    def test_110_verify_eintr_ok_whole_tag_mismatch_prefix_tag(self):
        """verify under the same recoverable interruptions: the correct
        whole-message tag still gives exactly 'OK\\n' with exit 0 and empty
        stderr (including an interruption before the first byte and one on
        the chunk boundary), while a tag that matches only the prefix read
        before the interruption stays a mismatch (exit 3, empty stdout)
        once reading has recovered and completed the message."""
        msg = self.interrupted_message()
        ok_scripts = [
            ["EINTR"],
            [10, "EINTR", "EINTR"],
            [READ_CHUNK, "EINTR"],
        ]
        for steps in ok_scripts:
            with self.subTest(steps=steps, tag="whole"):
                result, trace = self.run_stdin_read_script(
                    self.verify_script_argv(self.EINTR_MSG_TAG), steps, msg,
                    "verify-ok-%d" % len(repr(steps)))
                self.assertEqual(result.returncode, 0,
                                 f"steps={steps}: stderr={result.stderr!r}")
                self.assertEqual(result.stdout, b"OK\n")
                self.assertEqual(result.stderr, b"")
                self.assertReadTraceExact(trace, steps, len(msg),
                                          f"steps={steps}")
        # A tag matching only the first 10 bytes (already read when EINTR
        # hits) must not be accepted: after recovery the rest of the same
        # message arrives, and this is an ordinary mismatch -- not OK, and
        # not a read failure.
        steps = [10, "EINTR"]
        result, trace = self.run_stdin_read_script(
            self.verify_script_argv(self.EINTR_TAG_PREFIX10), steps, msg,
            "verify-prefix10")
        self.assertEqual(result.returncode, 3,
                         f"stderr={result.stderr!r}")
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"mismatch", result.stderr.lower())
        self.assertNotRegex(result.stderr, rb"(?i)[0-9a-f]{64}")
        self.assertReadTraceExact(trace, steps, len(msg), "prefix10")

    def test_111_empty_input_interrupted_is_valid_empty_message(self):
        """An empty input whose EOF read is interrupted (once or twice in a
        row) is still the legal empty message for both commands: tag emits
        the standard empty-message tag, verify accepts that tag."""
        for steps in (["EINTR"], ["EINTR", "EINTR"]):
            with self.subTest(steps=steps, command="tag"):
                result, trace = self.run_stdin_read_script(
                    self.tag_script_argv(), steps, b"",
                    "empty-tag-%d" % len(steps))
                self.assertTagSuccess(result, self.EINTR_TAG_EMPTY,
                                      f"empty tag steps={steps}")
                self.assertReadTraceExact(trace, steps, 0,
                                          f"empty tag steps={steps}")
            with self.subTest(steps=steps, command="verify"):
                result, trace = self.run_stdin_read_script(
                    self.verify_script_argv(self.EINTR_TAG_EMPTY), steps,
                    b"", "empty-verify-%d" % len(steps))
                self.assertEqual(result.returncode, 0,
                                 f"stderr={result.stderr!r}")
                self.assertEqual(result.stdout, b"OK\n")
                self.assertEqual(result.stderr, b"")
                self.assertReadTraceExact(trace, steps, 0,
                                          f"empty verify steps={steps}")

    def test_112_permanent_read_error_after_recovery(self):
        """A transient EINTR that recovers, followed by a permanent read
        error, keeps the read-failure contract for both commands: exit 1,
        empty stdout, a standard-input read diagnostic that echoes neither
        the key nor any tag. verify must neither pass nor report a mismatch
        when the supplied tag matches the whole message or exactly the
        prefix received before the permanent error (including an empty
        prefix when the error follows the first EINTR). The trace shows the
        recoverable interruption really happened before the latch."""
        msg = self.interrupted_message()
        # (steps, bytes delivered before the permanent error, tag to give
        # verify, tag label).
        cases = [
            (["EINTR", "EIO"], 0, self.EINTR_TAG_EMPTY, "empty-prefix"),
            (["EINTR", "EIO"], 0, self.EINTR_MSG_TAG, "whole-tag"),
            ([10, "EINTR", "EIO"], 10, self.EINTR_TAG_PREFIX10,
             "prefix10-tag"),
            ([10, "EINTR", "EIO"], 10, self.EINTR_MSG_TAG, "whole-tag"),
            ([100, "EINTR", "EINTR", "ENOSPC"], 100,
             self.EINTR_TAG_PREFIX100, "prefix100-tag"),
        ]
        for steps, delivered_bytes, tag_hex, tag_label in cases:
            label = f"steps={steps},{tag_label}"
            with self.subTest(command="tag", **{"case": label}):
                result, trace = self.run_stdin_read_script(
                    self.tag_script_argv(), steps, msg,
                    "perm-tag-%d-%s" % (delivered_bytes, tag_label))
                self.assertStdinReadFailure(result, label)
                self.assertNotIn(self.EINTR_KEY.encode(), result.stderr)
                self.assertReadTraceExact(trace, steps, len(msg), label,
                                          latched=True)
                self.assertEqual(
                    sum(int(e[1:]) for e in trace
                        if e[:1] in (b"D", b"P")),
                    delivered_bytes,
                    f"{label}: only the pre-error prefix may be delivered")
            with self.subTest(command="verify", **{"case": label}):
                result, trace = self.run_stdin_read_script(
                    self.verify_script_argv(tag_hex), steps, msg,
                    "perm-verify-%d-%s" % (delivered_bytes, tag_label))
                self.assertStdinReadFailure(result, label)
                # No key, supplied tag or recomputed tag in the diagnostic.
                self.assertNotIn(self.EINTR_KEY.encode(), result.stderr)
                self.assertNotIn(tag_hex.encode(), result.stderr)
                # Exit 1 specifically -- neither OK (0) nor mismatch (3).
                self.assertNotIn(b"mismatch", result.stderr.lower())
                self.assertReadTraceExact(trace, steps, len(msg), label,
                                          latched=True)

    def _wait_for_trace_prefix(self, trace_path, want_prefix, timeout):
        """Poll the shim trace until its lines start with ``want_prefix``
        (or fail after ``timeout`` seconds). Used while the child is alive
        to prove an interruption has already happened."""
        deadline = time.monotonic() + timeout
        lines = []
        while time.monotonic() < deadline:
            if os.path.exists(trace_path):
                with open(trace_path, "rb") as f:
                    lines = f.read().split()
                if lines[:len(want_prefix)] == want_prefix:
                    return lines
            time.sleep(0.02)
        raise AssertionError(
            f"trace never reached {want_prefix!r} within {timeout}s; "
            f"got {lines!r}")

    def test_113_eintr_while_input_still_open_no_early_conclusion(self):
        """End-to-end over a live pipe: the first read is interrupted
        before a single input byte has been sent, and a burst of two
        interruptions hits after a non-empty first installment while the
        input remains open. Neither command may end early, emit a result or
        print a prompt; the trace's pre-data 'EINTR' line proves a genuine
        read interruption rather than delayed/chunked sending. After the
        remaining bytes (including a NUL-led prefix and content crossing
        the 64 KiB boundary) arrive in installments and the input ends
        normally, tag prints the whole-message tag and verify prints OK."""
        self.require_read_shim()
        msg = self.interrupted_message()
        self.assertEqual(expected_hmac(self.EINTR_KEY, msg),
                         self.EINTR_MSG_TAG)
        # First read: EINTR with nothing ever written to the pipe. Then 100
        # bytes are allowed through, followed by two consecutive EINTRs
        # while input is still open, then one bounded read; the rest flows
        # after the script is exhausted.
        steps = ["EINTR", 100, "EINTR", "EINTR", 1000]
        eintr = b"E%d" % errno.EINTR

        def drive(command, argv, expect_line):
            StdinRegression._read_script_seq += 1
            trace_path = os.path.join(
                self.tmpdir,
                "read-trace-live-%d.log" % self._read_script_seq)
            env = read_script_env(self.shim, steps, trace_path)
            proc = subprocess.Popen(
                argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=env)
            try:
                # No bytes sent yet; the child must already have survived
                # the pre-first-byte interruption and be blocked reading.
                self._wait_for_trace_prefix(trace_path, [eintr], 5)
                self.assertIsNone(
                    proc.poll(),
                    f"{command}: interruption must not end the process "
                    f"while input is open")
                readable, _, _ = select.select([proc.stdout], [], [], 0.5)
                self.assertEqual(readable, [],
                                 f"{command}: no output before input ends")

                # First installment, then a burst of two interruptions.
                proc.stdin.write(msg[:100])
                proc.stdin.flush()
                self._wait_for_trace_prefix(
                    trace_path, [eintr, b"D100", eintr, eintr], 5)
                self.assertIsNone(
                    proc.poll(),
                    f"{command}: still-open input must keep the process "
                    f"waiting after the interruptions")
                readable, _, _ = select.select([proc.stdout], [], [], 0.5)
                self.assertEqual(readable, [],
                                 f"{command}: no result or prompt while "
                                 f"input is open")

                # Remaining installments deliberately misaligned with the
                # 64 KiB buffer: across the boundary, a small piece, tail.
                for piece in (msg[100:65537], msg[65537:65637],
                              msg[65637:]):
                    proc.stdin.write(piece)
                    proc.stdin.flush()
                proc.stdin.close()
                proc.stdin = None  # communicate() must not touch it again
                stdout, stderr = proc.communicate(timeout=30)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate()
            self.assertEqual(proc.returncode, 0,
                             f"{command}: stderr={stderr!r}")
            self.assertEqual(stderr, b"", f"{command}: {stderr!r}")
            self.assertEqual(stdout, expect_line)

            trace = read_read_trace(trace_path)
            # The first four events are fixed and prove the interruptions
            # happened in order, before and after the first installment.
            self.assertEqual(trace[:4], [eintr, b"D100", eintr, eintr])
            tail = trace[4:]
            self.assertTrue(len(tail) >= 2)
            self.assertEqual(tail[-1], b"P0")  # the clean EOF read
            self.assertFalse(any(e.startswith(b"E") for e in tail),
                             f"{command}: unexpected late errors: {tail}")
            # Every message byte exactly once: no loss, no repeat.
            delivered = sum(int(e[1:]) for e in trace
                            if e[:1] in (b"D", b"P"))
            self.assertEqual(delivered, len(msg))

        drive("tag", self.tag_script_argv(),
              self.EINTR_MSG_TAG.encode() + b"\n")
        drive("verify", self.verify_script_argv(self.EINTR_MSG_TAG),
              b"OK\n")


class KeyBoundaryRegression(unittest.TestCase):
    """RFC 2104 key normalization at the 64-byte SHA-256 block boundary.

    Pins, for both commands and for file and standard-input messages:

    - appending zero bytes to a non-empty key of at most 64 decoded bytes
      (staying at or below 64) cannot change the tag, and all such padded
      forms cross-verify one tag -- including 63 bytes padded to exactly 64;
    - one zero byte further (65 bytes) crosses the block size: the key is
      hashed and yields the standard long-key tag, identical to its
      SHA-256 digest used as a 32-byte key, and the original tag is a
      plain mismatch for it;
    - a key of exactly 64 bytes is used as-is and differs from its own
      SHA-256 digest as a key, while a key longer than 64 bytes matches
      its digest as a key and cross-verifies with it;
    - the digest reaches --key-hex as the hex of its raw 32 bytes, never
      as the digest text's character bytes;
    - the empty key stays a parameter error (exit 2) -- the zero-padding
      relation never makes it a legal key.

    Expected tags are the hard-coded KB_TAGS constants, re-derived from
    Python's hmac/hashlib (an implementation unrelated to the program) in
    test_120; the program's own output is never the oracle, and a tag
    printed by ``tag`` is never the sole basis for a ``verify`` verdict.
    """

    exe = None
    tmpdir = None

    # Padded forms of the 20-byte key: 20, 21, 32, 63 and 64 decoded bytes
    # -- all at or below the 64-byte block, hence all the same standard key.
    SHORT_PADDED = [KB_SHORT + "00" * n for n in (0, 1, 12, 43, 44)]

    @classmethod
    def setUpClass(cls):
        if not cls.exe or not os.path.isfile(cls.exe):
            raise RuntimeError("messagetag executable not found: %r" % cls.exe)
        cls.tmpdir = tempfile.mkdtemp(prefix="messagetag-keyboundary-")
        for name, data in KB_MESSAGES.items():
            with open(os.path.join(cls.tmpdir, name + ".bin"), "wb") as f:
                f.write(data)

    @classmethod
    def tearDownClass(cls):
        if cls.tmpdir and os.path.isdir(cls.tmpdir):
            shutil.rmtree(cls.tmpdir, ignore_errors=True)

    # -- helpers ------------------------------------------------------------

    def msg_file(self, name):
        return os.path.join(self.tmpdir, name + ".bin")

    def run_tag(self, key_hex, msg_name):
        return subprocess.run(
            [self.exe, "tag", "--key-hex", key_hex,
             "--file", self.msg_file(msg_name)], capture_output=True)

    def run_tag_stdin(self, key_hex, msg_name):
        return subprocess.run(
            [self.exe, "tag", "--key-hex", key_hex, "--file", "-"],
            input=KB_MESSAGES[msg_name], capture_output=True)

    def run_verify(self, key_hex, msg_name, tag_hex):
        return subprocess.run(
            [self.exe, "verify", "--key-hex", key_hex,
             "--file", self.msg_file(msg_name), "--tag-hex", tag_hex],
            capture_output=True)

    def run_verify_stdin(self, key_hex, msg_name, tag_hex):
        return subprocess.run(
            [self.exe, "verify", "--key-hex", key_hex, "--file", "-",
             "--tag-hex", tag_hex],
            input=KB_MESSAGES[msg_name], capture_output=True)

    def assertTagSuccess(self, result, expected_tag, label=""):
        self.assertEqual(
            result.returncode, 0,
            f"{label}: expected exit 0, got {result.returncode}; "
            f"stderr={result.stderr!r}")
        self.assertEqual(result.stderr, b"",
                         f"{label}: stderr must be empty, got "
                         f"{result.stderr!r}")
        self.assertRegex(result.stdout, TAG_RE,
                         f"{label}: stdout must be 64 lowercase hex chars "
                         f"+ newline, got {result.stdout!r}")
        self.assertEqual(result.stdout, expected_tag.encode() + b"\n",
                         f"{label}: wrong tag")

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

    def assertMismatch(self, result, key_hex, tag_hex, label=""):
        """A legal but non-matching combination: exit 3, empty stdout, and
        a diagnostic that states the mismatch without assigning a cause
        and without leaking the key, the supplied tag or a recomputed
        tag."""
        self.assertEqual(
            result.returncode, 3,
            f"{label}: expected exit 3, got {result.returncode}; "
            f"stdout={result.stdout!r} stderr={result.stderr!r}")
        self.assertEqual(result.stdout, b"",
                         f"{label}: stdout must carry no bytes on mismatch")
        self.assertNotEqual(result.stderr, b"",
                            f"{label}: a mismatch diagnostic is required")
        lower = result.stderr.lower()
        self.assertIn(b"mismatch", lower,
                      f"{label}: diagnostic must state the mismatch")
        for forbidden in (b"wrong key", b"bad key", b"incorrect key",
                          b"tamper", b"modif", b"corrupt"):
            self.assertNotIn(forbidden, lower,
                             f"{label}: diagnostic must not claim a "
                             f"specific cause ({forbidden!r})")
        self.assertNotRegex(result.stderr, rb"(?i)[0-9a-f]{64}",
                            f"{label}: stderr must not contain a "
                            f"recomputed/echoed tag")
        self.assertNotIn(tag_hex.lower().encode(), lower,
                         f"{label}: the supplied tag must not be echoed")
        self.assertNotIn(key_hex.lower().encode(), lower,
                         f"{label}: key material must not be echoed")

    # -- independent basis and standard relations ----------------------------

    def test_120_constants_match_stdlib_and_distinguish(self):
        """Every hard-coded KB_TAGS constant equals Python stdlib HMAC over
        the recipe, the standard normalization relations hold on the
        stdlib side, and the chosen keys/messages genuinely distinguish
        what must differ (so the mismatch tests below are not vacuous)."""
        key_for = {
            "short": KB_SHORT, "k63": KB_KEY63, "k65": KB_KEY65,
            "k64digest": KB_KEY64_DIGEST, "long": KB_LONG,
            "zero": KB_ZERO1, "zero65": KB_ZERO65,
        }
        # The boundary counts decoded bytes, not hex characters.
        self.assertEqual(len(bytes.fromhex(KB_SHORT)), 20)
        self.assertEqual(len(bytes.fromhex(KB_KEY63)), 63)
        self.assertEqual(len(bytes.fromhex(KB_KEY64)), 64)
        self.assertEqual(len(bytes.fromhex(KB_KEY65)), 65)
        self.assertEqual(len(bytes.fromhex(KB_LONG)), 100)
        for digest in (KB_KEY64_DIGEST, KB_KEY65_DIGEST, KB_LONG_DIGEST):
            self.assertEqual(len(bytes.fromhex(digest)), 32)
        for (msg_name, label), tag in KB_TAGS.items():
            with self.subTest(message=msg_name, key=label):
                self.assertEqual(
                    expected_hmac(key_for[label], KB_MESSAGES[msg_name]),
                    tag)
        for msg_name, message in KB_MESSAGES.items():
            def t(label):
                return KB_TAGS[(msg_name, label)]
            with self.subTest(message=msg_name, check="stdlib-relations"):
                # Zero-padding at or below 64 bytes changes nothing.
                for padded in self.SHORT_PADDED:
                    self.assertEqual(expected_hmac(padded, message),
                                     t("short"))
                self.assertEqual(expected_hmac(KB_KEY64, message), t("k63"))
                self.assertEqual(expected_hmac(KB_ZERO64, message),
                                 t("zero"))
                # Past 64 bytes the key authenticates as its digest.
                self.assertEqual(expected_hmac(KB_KEY65_DIGEST, message),
                                 t("k65"))
                self.assertEqual(expected_hmac(KB_LONG_DIGEST, message),
                                 t("long"))
                # And the selected data really separates the sides of
                # every boundary the suite pins.
                self.assertNotEqual(t("k63"), t("k65"))
                self.assertNotEqual(t("k63"), t("k64digest"))
                self.assertNotEqual(t("zero"), t("zero65"))
                self.assertNotEqual(
                    t("long"),
                    expected_hmac(KB_LONG_DIGEST.encode().hex(), message))

    # -- zero padding at or below the block size -----------------------------

    def test_121_trailing_zero_bytes_up_to_block_size_same_tag(self):
        """The 20-byte key and its zero-padded forms of 21, 32, 63 and 64
        decoded bytes all produce the independently computed tag -- on the
        empty message and on the NUL-containing message alike."""
        for msg_name in KB_MESSAGES:
            for padded in self.SHORT_PADDED:
                n = len(bytes.fromhex(padded))
                with self.subTest(message=msg_name, key_bytes=n):
                    self.assertLessEqual(n, 64)
                    self.assertTagSuccess(
                        self.run_tag(padded, msg_name),
                        KB_TAGS[(msg_name, "short")],
                        f"{msg_name}/{n}B")

    def test_122_boundary_63_padded_to_64_but_not_65(self):
        """The 63-byte key and its one-zero-byte padding to exactly 64
        bytes share one tag; padding further to 65 bytes crosses the block
        size and yields the different, standard long-key tag."""
        for msg_name in KB_MESSAGES:
            with self.subTest(message=msg_name):
                expected = KB_TAGS[(msg_name, "k63")]
                self.assertTagSuccess(
                    self.run_tag(KB_KEY63, msg_name), expected, "63B")
                self.assertTagSuccess(
                    self.run_tag(KB_KEY64, msg_name), expected, "64B")
                self.assertTagSuccess(
                    self.run_tag(KB_KEY65, msg_name),
                    KB_TAGS[(msg_name, "k65")], "65B")

    def test_123_padded_keys_cross_verify_one_tag(self):
        """Every padded form of each short key verifies the shared tag:
        exit 0, exactly 'OK\\n', empty stderr."""
        for msg_name in KB_MESSAGES:
            short_tag = KB_TAGS[(msg_name, "short")]
            for padded in self.SHORT_PADDED:
                n = len(bytes.fromhex(padded))
                with self.subTest(message=msg_name, key_bytes=n):
                    self.assertVerifyOk(
                        self.run_verify(padded, msg_name, short_tag),
                        f"{msg_name}/{n}B")
            boundary_tag = KB_TAGS[(msg_name, "k63")]
            for key in (KB_KEY63, KB_KEY64):
                n = len(bytes.fromhex(key))
                with self.subTest(message=msg_name, key_bytes=n):
                    self.assertVerifyOk(
                        self.run_verify(key, msg_name, boundary_tag),
                        f"{msg_name}/{n}B")

    # -- crossing the block size ---------------------------------------------

    def test_124_crossing_boundary_lands_on_standard_long_key(self):
        """The 65-byte key authenticates exactly like its SHA-256 digest
        used as a 32-byte key (they cross-verify), and is NOT equivalent
        to the 63/64-byte key it was padded from: the original tag is a
        plain mismatch for it, in both directions."""
        for msg_name in KB_MESSAGES:
            inner_tag = KB_TAGS[(msg_name, "k63")]
            outer_tag = KB_TAGS[(msg_name, "k65")]
            with self.subTest(message=msg_name, check="digest-equivalence"):
                self.assertTagSuccess(
                    self.run_tag(KB_KEY65_DIGEST, msg_name), outer_tag,
                    "digest of 65B key")
                self.assertVerifyOk(
                    self.run_verify(KB_KEY65, msg_name, outer_tag), "65B")
                self.assertVerifyOk(
                    self.run_verify(KB_KEY65_DIGEST, msg_name, outer_tag),
                    "digest of 65B key")
            with self.subTest(message=msg_name, check="65B vs inner tag"):
                self.assertMismatch(
                    self.run_verify(KB_KEY65, msg_name, inner_tag),
                    KB_KEY65, inner_tag, "65B key, 63B tag")
            with self.subTest(message=msg_name, check="63B vs outer tag"):
                self.assertMismatch(
                    self.run_verify(KB_KEY63, msg_name, outer_tag),
                    KB_KEY63, outer_tag, "63B key, 65B tag")

    def test_125_exact_block_size_key_differs_from_its_digest(self):
        """A key of exactly 64 bytes is used as-is: its tag differs from
        the tag of its own SHA-256 digest used as a key, and each side
        rejects the other's tag as a plain mismatch."""
        for msg_name in KB_MESSAGES:
            as_is_tag = KB_TAGS[(msg_name, "k63")]  # 64B key used as-is
            digest_tag = KB_TAGS[(msg_name, "k64digest")]
            with self.subTest(message=msg_name):
                self.assertTagSuccess(
                    self.run_tag(KB_KEY64_DIGEST, msg_name), digest_tag,
                    "digest of 64B key")
                self.assertMismatch(
                    self.run_verify(KB_KEY64, msg_name, digest_tag),
                    KB_KEY64, digest_tag, "64B key, digest tag")
                self.assertMismatch(
                    self.run_verify(KB_KEY64_DIGEST, msg_name, as_is_tag),
                    KB_KEY64_DIGEST, as_is_tag, "digest key, 64B tag")

    def test_126_overlong_key_matches_its_digest_key(self):
        """A 100-byte key is hashed before use: it produces the same
        independently computed tag as its SHA-256 digest supplied as a
        32-byte key, and the two forms cross-verify that tag."""
        for msg_name in KB_MESSAGES:
            tag = KB_TAGS[(msg_name, "long")]
            with self.subTest(message=msg_name):
                self.assertTagSuccess(
                    self.run_tag(KB_LONG, msg_name), tag, "100B key")
                self.assertTagSuccess(
                    self.run_tag(KB_LONG_DIGEST, msg_name), tag,
                    "digest of 100B key")
                self.assertVerifyOk(
                    self.run_verify(KB_LONG, msg_name, tag), "100B key")
                self.assertVerifyOk(
                    self.run_verify(KB_LONG_DIGEST, msg_name, tag),
                    "digest of 100B key")

    def test_127_digest_key_is_raw_bytes_not_hex_text(self):
        """The digest is supplied as the hex of its raw 32 bytes. Using
        the digest's 64 hex *characters* as a 64-byte key instead is a
        different, perfectly legal key: it yields its own independently
        computed tag and does not verify the over-long key's tag."""
        for msg_name, message in KB_MESSAGES.items():
            text_key = KB_LONG_DIGEST.encode().hex()  # 64 ASCII bytes
            with self.subTest(message=msg_name):
                self.assertEqual(len(bytes.fromhex(text_key)), 64)
                self.assertTagSuccess(
                    self.run_tag(text_key, msg_name),
                    expected_hmac(text_key, message), "digest text as key")
                self.assertMismatch(
                    self.run_verify(text_key, msg_name,
                                    KB_TAGS[(msg_name, "long")]),
                    text_key, KB_TAGS[(msg_name, "long")],
                    "digest-text key vs long-key tag")

    # -- zero-byte keys and the empty key ------------------------------------

    def test_128_zero_byte_keys_and_empty_key(self):
        """A key of zero bytes only still follows the same rules: one zero
        byte and 64 zero bytes share a tag (and cross-verify), 65 zero
        bytes are hashed to a different standard tag -- while the EMPTY
        key stays a parameter error (exit 2) for both commands and is
        never rescued by the zero-padding relation."""
        for msg_name in KB_MESSAGES:
            zero_tag = KB_TAGS[(msg_name, "zero")]
            with self.subTest(message=msg_name):
                self.assertTagSuccess(
                    self.run_tag(KB_ZERO1, msg_name), zero_tag, "1 zero")
                self.assertTagSuccess(
                    self.run_tag(KB_ZERO64, msg_name), zero_tag, "64 zeros")
                self.assertVerifyOk(
                    self.run_verify(KB_ZERO64, msg_name, zero_tag),
                    "64 zeros")
                self.assertTagSuccess(
                    self.run_tag(KB_ZERO65, msg_name),
                    KB_TAGS[(msg_name, "zero65")], "65 zeros")
                self.assertMismatch(
                    self.run_verify(KB_ZERO65, msg_name, zero_tag),
                    KB_ZERO65, zero_tag, "65 zeros vs 64-zero tag")
        for argv in (
            [self.exe, "tag", "--key-hex", "",
             "--file", self.msg_file("empty")],
            [self.exe, "verify", "--key-hex", "",
             "--file", self.msg_file("empty"),
             "--tag-hex", KB_TAGS[("empty", "zero")]],
        ):
            with self.subTest(command=argv[1], check="empty-key"):
                r = subprocess.run(argv, capture_output=True)
                self.assertEqual(r.returncode, 2,
                                 f"{argv[1]}: empty key must be a "
                                 f"parameter error, got {r.returncode}; "
                                 f"stderr={r.stderr!r}")
                self.assertEqual(r.stdout, b"")
                self.assertIn(USAGE_MARKER, r.stderr)

    # -- the same bytes from standard input ----------------------------------

    def test_129_stdin_matches_file_for_boundary_keys(self):
        """Every boundary relation reproduces when the same message bytes
        arrive on standard input instead of a file: identical independently
        computed tags, OK for equivalent keys, mismatch across the
        boundary."""
        cases = [
            (KB_SHORT, "short"), (self.SHORT_PADDED[-1], "short"),
            (KB_KEY63, "k63"), (KB_KEY64, "k63"),
            (KB_KEY65, "k65"), (KB_KEY65_DIGEST, "k65"),
            (KB_KEY64_DIGEST, "k64digest"),
            (KB_LONG, "long"), (KB_LONG_DIGEST, "long"),
            (KB_ZERO1, "zero"), (KB_ZERO64, "zero"), (KB_ZERO65, "zero65"),
        ]
        for msg_name in KB_MESSAGES:
            for key_hex, label in cases:
                n = len(bytes.fromhex(key_hex))
                with self.subTest(message=msg_name, key=label, key_bytes=n):
                    self.assertTagSuccess(
                        self.run_tag_stdin(key_hex, msg_name),
                        KB_TAGS[(msg_name, label)], f"{msg_name}/{label}")
        for msg_name in KB_MESSAGES:
            with self.subTest(message=msg_name, check="verify-stdin"):
                self.assertVerifyOk(self.run_verify_stdin(
                    KB_KEY64, msg_name, KB_TAGS[(msg_name, "k63")]),
                    "64B padded form")
                self.assertVerifyOk(self.run_verify_stdin(
                    KB_LONG_DIGEST, msg_name, KB_TAGS[(msg_name, "long")]),
                    "digest of 100B key")
                self.assertMismatch(
                    self.run_verify_stdin(KB_KEY65, msg_name,
                                          KB_TAGS[(msg_name, "k63")]),
                    KB_KEY65, KB_TAGS[(msg_name, "k63")],
                    "65B key vs inner tag")


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
    StdinRegression.exe = TagRegression.exe
    StdinRegression.tmpdir = None
    StdinRegression.shim_path = TagRegression.shim_path
    KeyBoundaryRegression.exe = TagRegression.exe
    KeyBoundaryRegression.tmpdir = None
    argv = [sys.argv[0], "-v"]
    # unittest's TextTestRunner gives non-zero exit when a test fails.
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite([
        loader.loadTestsFromTestCase(TagRegression),
        loader.loadTestsFromTestCase(VerifyRegression),
        loader.loadTestsFromTestCase(StdinRegression),
        loader.loadTestsFromTestCase(KeyBoundaryRegression),
    ])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
