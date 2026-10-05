#!/usr/bin/env python3
"""Regression tests for the messagetag `tag` command.

Every expected tag below is a known-answer vector produced independently of
the program under test:

* The RFC 4231 cases are the published HMAC-SHA-256 test vectors.
* All other tags were computed once with Python's `hmac`/`hashlib`
  (an implementation separate from the OpenSSL calls in src/main.cpp) and
  are frozen here as hex literals.

Because the expectations are hardcoded, a failure means a *publicly
documented behavior changed* — the test name identifies which one — and not
merely that two runs of the same binary disagree.

Usage:
    python3 tests/regression.py [path-to-messagetag-binary]

The binary path may also be given via the MESSAGETAG_BIN environment
variable; it defaults to ./build/messagetag.  Run directly or via CTest
(`ctest --test-dir build`).
"""

import os
import re
import subprocess
import sys
import tempfile
import unittest

BINARY = (
    sys.argv[1]
    if len(sys.argv) > 1
    else os.environ.get("MESSAGETAG_BIN", os.path.join("build", "messagetag"))
)

# ---------------------------------------------------------------------------
# Known-answer vectors (see module docstring for provenance).
# ---------------------------------------------------------------------------

# RFC 4231, Test Case 1: key = 0x0b * 20, data = "Hi There".
RFC4231_CASE1_KEY = "0b" * 20
RFC4231_CASE1_MSG = b"Hi There"
RFC4231_CASE1_TAG = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

# RFC 4231, Test Case 2: key = "Jefe", data = "what do ya want for nothing?".
RFC4231_CASE2_KEY = "4a656665"
RFC4231_CASE2_MSG = b"what do ya want for nothing?"
RFC4231_CASE2_TAG = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"

# RFC 4231, Test Case 6: key = 0xaa * 131 (longer than the 64-byte SHA-256
# block size, so the key itself is hashed first), data as below.
RFC4231_CASE6_KEY = "aa" * 131
RFC4231_CASE6_MSG = b"Test Using Larger Than Block-Size Key - Hash Key First"
RFC4231_CASE6_TAG = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"

# README example: key bytes 00 01, message "hello\n" (trailing newline is
# part of the message) and "hello" (no newline).
README_KEY = "0001"
README_MSG_NL = b"hello\n"
README_TAG_NL = "307a25cbcb6cbca48f5dd2b05fd9174c0cf17580f4ea8dd667092f11a77b4d5d"
README_MSG_NO_NL = b"hello"
README_TAG_NO_NL = "ee44e44a606a62df24b198d7130faa42a53e2aa5db4133210fd7c657aa7bb6ab"

# Empty message, key = deadbeef.
EMPTY_MSG_KEY = "deadbeef"
EMPTY_MSG_TAG = "bf5515149cf797955c4d3194cca42472883281951697c8375d9d9b107f384225"

# Binary message containing zero bytes; the bytes after each zero byte are
# part of the authenticated message.  Key = cafe01.
ZERO_BYTES_KEY = "cafe01"
ZERO_BYTES_MSG = b"abc\x00def\x00\x00ghi"
ZERO_BYTES_TAG = "a9afa13169e83deafed15ffebe02580a8c31a57c15e06e49350522b08cdb8091"

# Same text with CRLF vs LF line endings: the endings must not be
# normalized, so each form has its own tag.  Key = cafe01.
CRLF_KEY = "cafe01"
CRLF_MSG = b"line1\r\nline2\r\n"
CRLF_TAG = "cb39bb7b4aeb31ddd45bbca4374815707b22b33517282e0c510f15483ec29c94"
LF_MSG = b"line1\nline2\n"
LF_TAG = "8868f0946ef4ce216fb95854b825342a6f7a10c2a43f750b41c2fd749aecd13b"

# Leading zero bytes in the key are significant: key 00 ff authenticates
# differently from key ff.  Message = b"data".
LEADING_ZERO_KEY = "00ff"
LEADING_ZERO_TAG = "19fc0049914d0b35b09592a95b682bde022b6716745bd6c55028963967f6d448"
SHORT_KEY = "ff"
SHORT_KEY_TAG = "2c96c92c9ba66b61ed391791069279d1594b43697c720f81e7f97fac09fd595f"

# Files larger than the reader's 64 KiB buffer.  LARGE_PATTERN generates a
# deterministic, position-dependent byte pattern so that dropped, duplicated
# or reordered bytes anywhere in the file change the tag.
LARGE_KEY = "0102030405060708"
def large_pattern(length):
    return bytes((i * 7 + 3) % 256 for i in range(length))

# 2 * 64 KiB + 123 bytes: larger than 64 KiB and NOT a multiple of 64 KiB,
# so a final partial buffer must be handled exactly.
LARGE_ODD_MSG = large_pattern(2 * 65536 + 123)
LARGE_ODD_TAG = "504b450a75a4dabdb1fbc2314db5f481c415436dbf4db187af90eed29da9c924"

# Exactly 64 KiB: the buffer-boundary case (full read followed by EOF).
LARGE_64K_MSG = large_pattern(65536)
LARGE_64K_TAG = "8380e5757c81d1d410151041c6045418a0d3d79ba761ccc2313056ab7bb34075"

TAG_RE = re.compile(rb"[0-9a-f]{64}")


def run_tag(*args):
    """Run the binary with the given arguments; return the CompletedProcess."""
    return subprocess.run(
        [BINARY, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class TagTestBase(unittest.TestCase):
    """Helpers shared by the tag test cases."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="messagetag-test-")
        self.addCleanup(self._tmp.cleanup)
        self.tmpdir = self._tmp.name

    def write_file(self, name, content):
        path = os.path.join(self.tmpdir, name)
        with open(path, "wb") as f:
            f.write(content)
        return path

    def tag_of(self, key_hex, content, filename="msg.bin"):
        """Tag `content` with `key_hex`; assert full success contract and
        return the 64-char lowercase hex tag as str."""
        path = self.write_file(filename, content)
        result = run_tag("tag", "--key-hex", key_hex, "--file", path)
        self.assertEqual(
            result.returncode, 0,
            f"expected exit code 0, got {result.returncode}; "
            f"stderr: {result.stderr!r}")
        self.assertEqual(
            result.stderr, b"",
            f"successful run must keep stderr empty, got: {result.stderr!r}")
        tag = result.stdout.decode("ascii", errors="replace")
        self.assertRegex(
            tag, r"^[0-9a-f]{64}\n$",
            "stdout must be exactly 64 lowercase hex characters plus a "
            "newline (no extra output, no uppercase)")
        return tag.rstrip("\n")


class TestStandardHmacVectors(TagTestBase):
    """The tag must be standard HMAC-SHA-256 of the key bytes over the
    file's raw bytes, pinned by published RFC 4231 vectors."""

    def test_rfc4231_case1(self):
        self.assertEqual(
            self.tag_of(RFC4231_CASE1_KEY, RFC4231_CASE1_MSG),
            RFC4231_CASE1_TAG)

    def test_rfc4231_case2(self):
        self.assertEqual(
            self.tag_of(RFC4231_CASE2_KEY, RFC4231_CASE2_MSG),
            RFC4231_CASE2_TAG)

    def test_rfc4231_case6_key_longer_than_block_size(self):
        # 131-byte key > 64-byte SHA-256 block: the standard hashes the key
        # first.  Guards against truncating/padding the key instead.
        self.assertEqual(
            self.tag_of(RFC4231_CASE6_KEY, RFC4231_CASE6_MSG),
            RFC4231_CASE6_TAG)

    def test_readme_example(self):
        # The documented example must keep producing the documented tag.
        self.assertEqual(
            self.tag_of(README_KEY, README_MSG_NL), README_TAG_NL)


class TestKeyHexDecoding(TagTestBase):
    """Every two hex characters are one key byte; the decoded bytes — not
    the text and not a numeric interpretation — are the HMAC key."""

    def test_uppercase_and_lowercase_hex_are_the_same_key(self):
        lower = self.tag_of("0a0b0c0d", b"message")
        upper = self.tag_of("0A0B0C0D", b"message")
        mixed = self.tag_of("0a0B0c0D", b"message")
        self.assertEqual(lower, upper)
        self.assertEqual(lower, mixed)

    def test_leading_zero_bytes_are_preserved(self):
        # "00ff" is two key bytes 00 ff, not the one-byte key ff and not
        # the number 255.
        self.assertEqual(
            self.tag_of(LEADING_ZERO_KEY, b"data"), LEADING_ZERO_TAG)
        self.assertEqual(
            self.tag_of(SHORT_KEY, b"data"), SHORT_KEY_TAG)
        self.assertNotEqual(
            self.tag_of(LEADING_ZERO_KEY, b"data"),
            self.tag_of(SHORT_KEY, b"data"))

    def test_key_text_itself_is_not_the_key(self):
        # HMAC of the ASCII string "0001" as key would differ from HMAC
        # with key bytes 00 01; the README vector pins the byte-decoding.
        ascii_key_tag = self.tag_of("30303031", README_MSG_NL)  # "0001" as text
        self.assertNotEqual(ascii_key_tag, README_TAG_NL)
        self.assertEqual(self.tag_of(README_KEY, README_MSG_NL), README_TAG_NL)


class TestMessageFileContents(TagTestBase):
    """The message is every raw byte of the file: no text interpretation,
    no truncation, no newline handling."""

    def test_empty_file_is_a_valid_message(self):
        self.assertEqual(
            self.tag_of(EMPTY_MSG_KEY, b""), EMPTY_MSG_TAG)

    def test_zero_bytes_and_what_follows_them_are_authenticated(self):
        self.assertEqual(
            self.tag_of(ZERO_BYTES_KEY, ZERO_BYTES_MSG), ZERO_BYTES_TAG)
        # Content after a zero byte must not be dropped.
        self.assertNotEqual(
            self.tag_of(ZERO_BYTES_KEY, b"abc\x00def"),
            self.tag_of(ZERO_BYTES_KEY, b"abc\x00XYZ"))

    def test_trailing_newline_belongs_to_the_message(self):
        self.assertEqual(
            self.tag_of(README_KEY, README_MSG_NL), README_TAG_NL)
        self.assertEqual(
            self.tag_of(README_KEY, README_MSG_NO_NL), README_TAG_NO_NL)
        self.assertNotEqual(README_TAG_NL, README_TAG_NO_NL)

    def test_line_endings_are_not_normalized(self):
        self.assertEqual(self.tag_of(CRLF_KEY, CRLF_MSG), CRLF_TAG)
        self.assertEqual(self.tag_of(CRLF_KEY, LF_MSG), LF_TAG)
        self.assertNotEqual(CRLF_TAG, LF_TAG)

    def test_file_larger_than_64kib_not_a_multiple(self):
        # 2 * 64 KiB + 123 bytes: every byte must be authenticated exactly
        # once, including the trailing partial buffer.
        self.assertEqual(
            self.tag_of(LARGE_KEY, LARGE_ODD_MSG), LARGE_ODD_TAG)

    def test_file_exactly_64kib(self):
        self.assertEqual(
            self.tag_of(LARGE_KEY, LARGE_64K_MSG), LARGE_64K_TAG)

    def test_path_does_not_affect_the_tag(self):
        content = b"same bytes, different locations"
        os.makedirs(os.path.join(self.tmpdir, "a"), exist_ok=True)
        os.makedirs(os.path.join(self.tmpdir, "b"), exist_ok=True)
        tag_a = self.tag_of("0b0b", content, filename="a/first-name.msg")
        tag_b = self.tag_of("0b0b", content, filename="b/another-name.msg")
        self.assertEqual(tag_a, tag_b)


class TestCommandLineContract(unittest.TestCase):
    """Exit codes and stream usage are part of the published interface."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="messagetag-test-")
        self.addCleanup(self._tmp.cleanup)
        self.msg_path = os.path.join(self._tmp.name, "msg.bin")
        with open(self.msg_path, "wb") as f:
            f.write(b"hello\n")

    def test_success_contract(self):
        result = run_tag("tag", "--key-hex", "0001", "--file", self.msg_path)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.stdout, README_TAG_NL.encode() + b"\n")

    def test_invalid_key_odd_length(self):
        key = "0123456789abcde"  # 15 characters
        result = run_tag("tag", "--key-hex", key, "--file", self.msg_path)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"", "no tag may be printed")
        self.assertNotEqual(result.stderr, b"", "an error must be reported")
        self.assertNotIn(
            key.encode(), result.stderr,
            "the error message must not echo the submitted key")
        self.assertIsNone(
            TAG_RE.search(result.stdout),
            "stdout must not contain anything looking like a tag")

    def test_invalid_key_non_hex_characters(self):
        key = "xxnothexkey!!"
        result = run_tag("tag", "--key-hex", key, "--file", self.msg_path)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"", "no tag may be printed")
        self.assertNotEqual(result.stderr, b"", "an error must be reported")
        self.assertNotIn(
            key.encode(), result.stderr,
            "the error message must not echo the submitted key")

    def test_unreadable_file(self):
        missing = os.path.join(self._tmp.name, "does-not-exist.bin")
        result = run_tag("tag", "--key-hex", "0001", "--file", missing)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"", "no tag may be printed")
        self.assertNotEqual(result.stderr, b"", "the read failure must be reported")
        self.assertIn(
            b"read", result.stderr.lower(),
            "stderr must explain that reading the file failed")
        self.assertIsNone(
            TAG_RE.fullmatch(result.stdout.strip()),
            "stdout must not contain anything looking like a valid tag")

    def test_version_entry_point(self):
        result = run_tag("--version")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.stdout, b"messagetag 0.1.0\n")

    def test_missing_required_options(self):
        result = run_tag("tag")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertNotEqual(result.stderr, b"")

    def test_unknown_argument(self):
        result = run_tag("tag", "--key-hex", "0001", "--file",
                         self.msg_path, "--bogus")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")


if __name__ == "__main__":
    # Strip the binary-path argument so unittest sees only its own flags.
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        del sys.argv[1]
    unittest.main(verbosity=2)
