"""Two-instance isolation tests for REV-02 — Phantom Protocol."""

import io
import unittest
import zipfile

from support import (
    ChallengeInstance,
    build_protocol,
    docker_available,
    read_protocol,
    recover_token,
    tempdir,
)

FLAG_A = "AXUM{phantom_team_a_1234}"
FLAG_B = "AXUM{phantom_team_b_5678}"

import os


def save(archive_bytes, name):
    path = os.path.join(tempdir(), name)
    with open(path, "wb") as handle:
        handle.write(archive_bytes)
    return path


@unittest.skipUnless(docker_available(), "docker is not available")
class IsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.instance_a = ChallengeInstance(FLAG_A).__enter__()
        cls.instance_b = ChallengeInstance(FLAG_B).__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.instance_a.__exit__(None, None, None)
        cls.instance_b.__exit__(None, None, None)

    def test_each_instance_recovers_its_own_flag(self):
        archive_a = save(self.instance_a.fetch_archive(), "a.zip")
        archive_b = save(self.instance_b.fetch_archive(), "b.zip")

        self.assertEqual(recover_token(archive_a), FLAG_A)
        self.assertEqual(recover_token(archive_b), FLAG_B)

    def test_payloads_differ_between_instances(self):
        archive_a = save(self.instance_a.fetch_archive(), "a.zip")
        archive_b = save(self.instance_b.fetch_archive(), "b.zip")
        self.assertNotEqual(read_protocol(archive_a), read_protocol(archive_b))

    def test_archives_contain_no_foreign_flag(self):
        archive_a = self.instance_a.fetch_archive()
        archive_b = self.instance_b.fetch_archive()

        self.assertNotIn(FLAG_A.encode(), archive_a)
        self.assertNotIn(FLAG_B.encode(), archive_a)
        self.assertNotIn(FLAG_A.encode(), archive_b)
        self.assertNotIn(FLAG_B.encode(), archive_b)

    def test_archives_are_distinct(self):
        self.assertNotEqual(self.instance_a.fetch_archive(), self.instance_b.fetch_archive())

    def test_client_rejects_foreign_token_against_local_data(self):
        archive_b = save(self.instance_b.fetch_archive(), "b.zip")
        protocol_b = read_protocol(archive_b)

        # Instance A holds A's data; B's token must not be accepted there.
        result = self.instance_a.run_client(protocol_b, ["--verify", f"'{FLAG_B}'"])
        self.assertEqual(result.returncode, 0)

        result = self.instance_a.run_client(protocol_b, ["--verify", f"'{FLAG_A}'"])
        self.assertEqual(result.returncode, 1)

    def test_download_endpoint_serves_only_its_own_archive(self):
        archive_a = self.instance_a.fetch_archive()
        archive_b = self.instance_b.fetch_archive()

        with zipfile.ZipFile(io.BytesIO(archive_a)) as handle:
            payload_a = handle.read("phantom-protocol/protocol.dat")
        with zipfile.ZipFile(io.BytesIO(archive_b)) as handle:
            payload_b = handle.read("phantom-protocol/protocol.dat")

        self.assertNotEqual(payload_a, payload_b)
        self.assertEqual(payload_a[8:], build_protocol(FLAG_A.encode())[8:])
        self.assertEqual(payload_b[8:], build_protocol(FLAG_B.encode())[8:])


if __name__ == "__main__":
    unittest.main(verbosity=2)
