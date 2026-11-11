"""ZIP artifact tests for NET-03 — The Last Transmission."""

import io
import unittest
import zipfile

import support  # noqa: F401 - adjusts sys.path

import artifact
from artifact import (
    ARCHIVE_NAME,
    ArtifactError,
    EVIDENCE_PATH,
    build_bundle,
    build_report,
    validate_bundle,
)

FLAG = "GZCTF{NET03_TEST_FLAG}"


class ArtifactTests(unittest.TestCase):
    def test_archive_name(self):
        self.assertEqual(ARCHIVE_NAME, "confidential_bundle.zip")

    def test_bundle_is_a_valid_zip(self):
        data = build_bundle(FLAG)
        self.assertTrue(data.startswith(b"PK\x03\x04"))
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            self.assertIsNone(archive.testzip())

    def test_expected_internal_path(self):
        with zipfile.ZipFile(io.BytesIO(build_bundle(FLAG))) as archive:
            self.assertEqual(archive.namelist(), [EVIDENCE_PATH])
            self.assertEqual(EVIDENCE_PATH, "evidence/incident_summary.txt")

    def test_no_unintended_members(self):
        with zipfile.ZipFile(io.BytesIO(build_bundle(FLAG))) as archive:
            self.assertEqual(len(archive.namelist()), 1)

    def test_runtime_flag_present_in_evidence(self):
        with zipfile.ZipFile(io.BytesIO(build_bundle(FLAG))) as archive:
            report = archive.read(EVIDENCE_PATH).decode("utf-8")
        self.assertIn(FLAG, report)

    def test_required_report_content(self):
        report = build_report(FLAG)
        self.assertIn("ASTERION TECHNOLOGIES", report)
        self.assertIn("CONFIDENTIAL INCIDENT REPORT", report)
        self.assertIn("Incident Reference: AX-7842", report)
        self.assertIn("Classification: INTERNAL", report)
        self.assertIn("AXUM-INCIDENT-03", report)
        self.assertIn("Verification token:", report)

    def test_utf8_flag_roundtrip(self):
        flag = "AXUM{cl\u00e9s_secr\u00e8te_\u00e9}"
        data = build_bundle(flag)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            report = archive.read(EVIDENCE_PATH).decode("utf-8")
        self.assertIn(flag, report)
        validate_bundle(data, flag)

    def test_different_flags_produce_different_archives(self):
        self.assertNotEqual(build_bundle("GZCTF{one}"), build_bundle("GZCTF{two}"))

    def test_same_flag_is_deterministic(self):
        self.assertEqual(build_bundle(FLAG), build_bundle(FLAG))

    def test_payload_spans_multiple_tcp_segments(self):
        # The FTP data connection must actually exercise segmentation.
        self.assertGreater(len(build_bundle(FLAG)), 1200)

    def test_archive_size_is_reasonable(self):
        size = len(build_bundle(FLAG))
        self.assertGreater(size, 1024)
        self.assertLess(size, 32 * 1024)

    def test_validate_bundle_reports_metadata(self):
        data = build_bundle(FLAG)
        summary = validate_bundle(data, FLAG)
        self.assertEqual(summary["members"], [EVIDENCE_PATH])
        self.assertEqual(summary["bytes"], len(data))

    def test_validate_rejects_wrong_flag(self):
        with self.assertRaises(ArtifactError):
            validate_bundle(build_bundle(FLAG), "GZCTF{a_different_flag}")

    def test_validate_rejects_empty_archive(self):
        with self.assertRaises(ArtifactError):
            validate_bundle(b"", FLAG)

    def test_validate_rejects_corrupt_archive(self):
        data = bytearray(build_bundle(FLAG))
        data[60:70] = b"\x00" * 10
        with self.assertRaises((ArtifactError, zipfile.BadZipFile)):
            validate_bundle(bytes(data), FLAG)

    def test_empty_flag_is_rejected(self):
        with self.assertRaises(ArtifactError):
            build_bundle("")

    def test_non_string_flag_is_rejected(self):
        with self.assertRaises(ArtifactError):
            build_bundle(b"GZCTF{bytes}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
