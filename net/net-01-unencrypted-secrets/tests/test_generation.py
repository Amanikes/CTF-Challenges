"""Generator behaviour tests for NET-01 — Unencrypted Secrets."""

import os
import unittest
from pathlib import Path

from support import CAPTURE_NAME, generate, run, tcpdump_available

FLAG = "GZCTF{NET01_TEST_FLAG}"


class GeneratorTests(unittest.TestCase):
    def test_missing_flag_is_rejected(self):
        path, process = generate(None)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("GZCTF_FLAG is missing or empty", process.stderr)
        self.assertFalse(path.exists())

    def test_empty_flag_is_rejected(self):
        path, process = generate("   ")
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("GZCTF_FLAG is missing or empty", process.stderr)
        self.assertFalse(path.exists())

    def test_over_long_flag_is_rejected(self):
        flag = "GZCTF{" + "A" * 240 + "}"
        path, process = generate(flag)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("outside the supported range", process.stderr)
        self.assertNotIn(flag, process.stderr)
        self.assertFalse(path.exists())

    def test_non_ascii_flag_is_rejected(self):
        path, process = generate("GZCTF{bad\u00e9}")
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("outside the supported range", process.stderr)

    def test_valid_flag_produces_a_capture(self):
        path, process = generate(FLAG)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertTrue(path.exists())
        self.assertEqual(path.name, CAPTURE_NAME)

        header = path.read_bytes()[:4]
        self.assertIn(header, (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1"),
                      "capture does not start with a libpcap magic value")

    def test_capture_size_is_reasonable(self):
        path, process = generate(FLAG)
        self.assertEqual(process.returncode, 0, process.stderr)
        size = path.stat().st_size
        self.assertGreaterEqual(size, 8 * 1024)
        self.assertLessEqual(size, 4 * 1024 * 1024)

    def test_permissions_allow_the_service_to_read_it(self):
        path, process = generate(FLAG)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_generator_output_does_not_leak_the_flag(self):
        path, process = generate(FLAG)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertNotIn(FLAG, process.stdout)
        self.assertNotIn(FLAG, process.stderr)

    def test_different_flags_produce_different_captures(self):
        first, first_process = generate("GZCTF{one}")
        second, second_process = generate("GZCTF{two}")
        self.assertEqual(first_process.returncode, 0, first_process.stderr)
        self.assertEqual(second_process.returncode, 0, second_process.stderr)
        self.assertNotEqual(first.read_bytes(), second.read_bytes())

    def test_capture_is_readable_by_tcpdump(self):
        if not tcpdump_available():
            self.skipTest("tcpdump is not available")
        path, process = generate(FLAG)
        self.assertEqual(process.returncode, 0, process.stderr)

        result = run(["tcpdump", "-nn", "-r", str(path)])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("192.168.10.10", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
