"""Binary behaviour tests for REV-02 — Phantom Protocol.

Every test runs the packaged phantom-client inside a container built from the
challenge image, so it exercises exactly the artifact participants receive.
"""

import unittest

from support import (
    ChallengeInstance,
    build_protocol,
    docker_available,
    forward_token,
    read_protocol,
)

FLAG = "AXUM{phantom_validation_01}"


@unittest.skipUnless(docker_available(), "docker is not available")
class BinaryValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.instance = ChallengeInstance(FLAG).__enter__()
        cls.archive = cls.instance.fetch_archive()
        cls.protocol = read_protocol_from(cls.archive)

    @classmethod
    def tearDownClass(cls):
        cls.instance.__exit__(None, None, None)

    def run_client(self, protocol_bytes, args):
        return self.instance.run_client(protocol_bytes, args)

    def test_usage_without_arguments(self):
        result = self.run_client(self.protocol, [])
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"Usage", result.stdout)
        self.assertIn(b"--verify", result.stdout)

    def test_usage_on_invalid_argument_count(self):
        result = self.run_client(self.protocol, ["--verify"])
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"Usage", result.stdout)

    def test_usage_on_unknown_option(self):
        result = self.run_client(self.protocol, ["--token", "'x'"])
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"Usage", result.stdout)

    def test_correct_token_is_accepted(self):
        result = self.run_client(self.protocol, ["--verify", f"'{FLAG}'"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), b"ACCESS GRANTED")

    def test_incorrect_token_is_denied(self):
        result = self.run_client(self.protocol, ["--verify", "'AXUM{phantom_wrong_01}'"])
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.strip(), b"ACCESS DENIED")

    def test_empty_candidate_is_denied(self):
        result = self.run_client(self.protocol, ["--verify", "''"])
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.strip(), b"ACCESS DENIED")

    def test_shorter_candidate_is_denied(self):
        result = self.run_client(self.protocol, ["--verify", "'AXUM{phantom_validation_0}'"])
        self.assertEqual(result.returncode, 1)

    def test_missing_data_file_is_reported(self):
        result = self.run_client(None, ["--verify", f"'{FLAG}'"])
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"could not be read", result.stderr)

    def test_bad_magic_is_rejected(self):
        broken = build_protocol(FLAG.encode(), magic=b"XXXX")
        result = self.run_client(broken, ["--verify", f"'{FLAG}'"])
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"unsupported or corrupted format", result.stderr)

    def test_unsupported_version_is_rejected(self):
        broken = build_protocol(FLAG.encode(), version=2)
        result = self.run_client(broken, ["--verify", f"'{FLAG}'"])
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"unsupported or corrupted format", result.stderr)

    def test_zero_length_is_rejected(self):
        broken = build_protocol(FLAG.encode(), declared=0)
        result = self.run_client(broken, ["--verify", f"'{FLAG}'"])
        self.assertEqual(result.returncode, 2)

    def test_excessive_length_is_rejected(self):
        broken = build_protocol(FLAG.encode(), declared=200)
        result = self.run_client(broken, ["--verify", f"'{FLAG}'"])
        self.assertEqual(result.returncode, 2)

    def test_truncated_file_is_rejected(self):
        truncated = self.protocol[:-1]
        result = self.run_client(truncated, ["--verify", f"'{FLAG}'"])
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"unsupported or corrupted format", result.stderr)

    def test_extra_data_is_rejected(self):
        padded = self.protocol + b"\x00"
        result = self.run_client(padded, ["--verify", f"'{FLAG}'"])
        self.assertEqual(result.returncode, 2)

    def test_reserved_bytes_must_be_zero(self):
        broken = build_protocol(FLAG.encode(), reserved=1)
        result = self.run_client(broken, ["--verify", f"'{FLAG}'"])
        self.assertEqual(result.returncode, 2)

    def test_single_byte_payload(self):
        result = self.run_client(build_protocol(b"A"), ["--verify", "'A'"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), b"ACCESS GRANTED")

    def test_maximum_length_payload(self):
        token = "A" * 128
        result = self.run_client(build_protocol(token.encode()), ["--verify", f"'{token}'"])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_binary_never_prints_the_token(self):
        result = self.run_client(self.protocol, ["--verify", "'AXUM{phantom_wrong_02}'"])
        self.assertNotIn(FLAG.encode(), result.stdout)
        self.assertNotIn(FLAG.encode(), result.stderr)

    def test_cross_check_independent_forward_implementation(self):
        """The test's own forward transform must reproduce the generator output."""
        self.assertEqual(forward_token(FLAG.encode()), self.protocol[8:])


def read_protocol_from(archive_bytes):
    import io
    import zipfile

    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        return archive.read("phantom-protocol/protocol.dat")


if __name__ == "__main__":
    unittest.main(verbosity=2)
