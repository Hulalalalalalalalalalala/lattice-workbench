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

Usage:

    python3 tests/regression_test.py /path/to/messagetag
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


def large_bytes():
    """131195 bytes whose value depends on every position: two whole 64 KiB
    read chunks plus a 123-byte tail. Dropping, repeating or reordering any
    byte changes the tag."""
    return bytes((i * 31 + 7) % 256 for i in range(LARGE_LEN))


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

TAG_RE = re.compile(rb"\A[0-9a-f]{64}\n\Z")


def expected_hmac(key_hex, message):
    return py_hmac.new(bytes.fromhex(key_hex), message,
                       hashlib.sha256).hexdigest()


class TagRegression(unittest.TestCase):
    exe = None
    tmpdir = None

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
    if len(sys.argv) != 2:
        print("usage: regression_test.py /path/to/messagetag", file=sys.stderr)
        return 2
    TagRegression.exe = os.path.abspath(sys.argv[1])
    TagRegression.tmpdir = None
    argv = [sys.argv[0], "-v"]
    # unittest's TextTestRunner gives non-zero exit when a test fails.
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TagRegression)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
