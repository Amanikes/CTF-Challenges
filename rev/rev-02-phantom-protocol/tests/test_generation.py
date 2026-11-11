"""Generator and protocol-format tests for REV-02 — Phantom Protocol.

These exercise generator/generate_package.py directly (no container needed) and
cross-check the Python implementation against an independent reference vector.
"""

import importlib.util
import unittest
import zipfile

from support import (
    ARCHIVE_NAME,
    PACKAGE_DIRECTORY,
    ROOT,
    generate_package,
    quarantine,
    read_protocol,
    tempdir,
)

# Independent reference implementation of the documented pipeline. Any change to
# the key or the stage constants must fail this vector.
REFERENCE_KEY = b"AegisPhantomKey!"
REFERENCE_TOKEN = b"AXUM{phantom_vector_01}"
REFERENCE_PAYLOAD = bytes.fromhex("69ef3d93d8eeab37fdaaf122ca9917b572748f994afb54")


def load_generator():
    spec = importlib.util.spec_from_file_location(
        "phantom_generate_package", ROOT / "generator" / "generate_package.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.generator = load_generator()
        cls.readme = ROOT / "package" / "README.txt"

    def test_reference_vector_matches_generator(self):
        self.assertEqual(self.generator.transform(REFERENCE_TOKEN), REFERENCE_PAYLOAD)

    def test_serialized_header_matches_specification(self):
        payload = self.generator.serialize(REFERENCE_PAYLOAD)
        self.assertEqual(payload[0:4], b"PHTM")
        self.assertEqual(payload[4], 1)
        self.assertEqual(payload[5], len(REFERENCE_PAYLOAD))
        self.assertEqual(payload[6:8], b"\x00\x00")
        self.assertEqual(payload[8:], REFERENCE_PAYLOAD)

    def test_missing_flag_fails_clearly(self):
        with quarantine("GZCTF_FLAG"):
            archive, process = generate_package("", tempdir(), readme=self.readme)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("GZCTF_FLAG is missing or empty", process.stderr)
        self.assertFalse(archive.exists())

    def test_empty_flag_fails_clearly(self):
        directory = tempdir()
        archive, process = generate_package("   ", directory, readme=self.readme)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("GZCTF_FLAG is missing or empty", process.stderr)
        self.assertFalse(archive.exists())

    def test_over_long_flag_is_rejected(self):
        directory = tempdir()
        long_flag = "AXUM{" + "A" * 200 + "}"
        archive, process = generate_package(long_flag, directory, readme=self.readme)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("outside the supported range", process.stderr)
        self.assertNotIn(long_flag, process.stderr)

    def test_valid_flag_produces_valid_protocol_data(self):
        flag = "AXUM{generation_test_01}"
        directory = tempdir()
        archive, process = generate_package(flag, directory, readme=self.readme)
        self.assertEqual(process.returncode, 0, process.stderr)

        protocol = read_protocol(archive)
        self.assertEqual(protocol[0:4], b"PHTM")
        self.assertEqual(protocol[4], 1)
        self.assertEqual(protocol[5], len(flag.encode()))
        self.assertEqual(len(protocol), 8 + len(flag.encode()))

    def test_archive_contains_only_participant_files(self):
        directory = tempdir()
        archive, process = generate_package("AXUM{zip_layout}", directory, readme=self.readme)
        self.assertEqual(process.returncode, 0, process.stderr)

        with zipfile.ZipFile(archive) as handle:
            names = sorted(handle.namelist())
            self.assertEqual(
                names,
                [
                    f"{PACKAGE_DIRECTORY}/README.txt",
                    f"{PACKAGE_DIRECTORY}/phantom-client",
                    f"{PACKAGE_DIRECTORY}/protocol.dat",
                ],
            )

            modes = {
                name: oct((handle.getinfo(name).external_attr >> 16) & 0o777) for name in names
            }
            self.assertEqual(modes[f"{PACKAGE_DIRECTORY}/phantom-client"], "0o755")
            self.assertEqual(modes[f"{PACKAGE_DIRECTORY}/protocol.dat"], "0o644")

    def test_archive_contains_no_plaintext_flag(self):
        flag = "AXUM{never_plaintext_42}"
        directory = tempdir()
        archive, process = generate_package(flag, directory, readme=self.readme)
        self.assertEqual(process.returncode, 0, process.stderr)

        blob = archive.read_bytes()
        self.assertNotIn(flag.encode(), blob)
        self.assertNotIn(flag.encode(), read_protocol(archive))

    def test_different_flags_produce_different_payloads(self):
        first_dir = tempdir()
        second_dir = tempdir()
        first, _ = generate_package("AXUM{diff_one}", first_dir, readme=self.readme)
        second, _ = generate_package("AXUM{diff_two}", second_dir, readme=self.readme)
        self.assertNotEqual(read_protocol(first), read_protocol(second))

    def test_generator_log_does_not_leak_the_flag(self):
        flag = "AXUM{log_check_99}"
        archive, process = generate_package(flag, tempdir(), readme=self.readme)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertNotIn(flag, process.stdout)
        self.assertNotIn(flag, process.stderr)

    def test_protocol_payload_is_not_the_plaintext(self):
        flag = "AXUM{payload_must_differ}"
        archive, _ = generate_package(flag, tempdir(), readme=self.readme)
        self.assertNotEqual(read_protocol(archive)[8:], flag.encode())


if __name__ == "__main__":
    unittest.main(verbosity=2)
