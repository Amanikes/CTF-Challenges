"""Configuration, flag handling and confidentiality tests for NET-03."""

import os
import subprocess
import sys
import tempfile
import unittest

import support  # noqa: F401 - adjusts sys.path

from config import DEFAULT_PORT, ConfigError, load_config

SRC = support.SRC
FLAG = "GZCTF{NET03_TEST_FLAG}"


class ConfigTests(unittest.TestCase):
    def test_missing_flag_is_rejected(self):
        with self.assertRaises(ConfigError) as context:
            load_config({})
        self.assertIn("GZCTF_FLAG is missing or empty", str(context.exception))

    def test_empty_flag_is_rejected(self):
        with self.assertRaises(ConfigError):
            load_config({"GZCTF_FLAG": "   "})

    def test_default_port(self):
        self.assertEqual(load_config({"GZCTF_FLAG": FLAG}).port, DEFAULT_PORT)
        self.assertEqual(DEFAULT_PORT, 8080)

    def test_custom_port(self):
        self.assertEqual(load_config({"GZCTF_FLAG": FLAG, "PORT": "9001"}).port, 9001)

    def test_invalid_ports_are_rejected(self):
        for value in ("abc", "0", "65536", "-5"):
            with self.assertRaises(ConfigError):
                load_config({"GZCTF_FLAG": FLAG, "PORT": value})

    def test_default_capture_path(self):
        self.assertEqual(
            load_config({"GZCTF_FLAG": FLAG}).capture_path, "/app/artifacts/capture.pcap"
        )

    def test_capture_path_override(self):
        config = load_config({"GZCTF_FLAG": FLAG, "PCAP_PATH": "/tmp/x.pcap"})
        self.assertEqual(config.capture_path, "/tmp/x.pcap")

    def test_log_level_validation(self):
        self.assertEqual(load_config({"GZCTF_FLAG": FLAG, "LOG_LEVEL": "debug"}).log_level, "DEBUG")
        with self.assertRaises(ConfigError):
            load_config({"GZCTF_FLAG": FLAG, "LOG_LEVEL": "CHATTY"})

    def test_repr_never_contains_the_flag(self):
        config = load_config({"GZCTF_FLAG": "GZCTF{super_secret_token}"})
        self.assertNotIn("super_secret_token", repr(config))

    def test_web_process_does_not_require_the_flag(self):
        self.assertIsNone(load_config({}, require_flag=False).flag)


class FlagConfidentialityTests(unittest.TestCase):
    def run_generator(self, environment):
        return subprocess.run(
            [sys.executable, os.path.join(SRC, "generate_capture.py")],
            capture_output=True,
            text=True,
            env=environment,
            timeout=300,
        )

    def test_generator_fails_without_flag(self):
        directory = tempfile.mkdtemp()
        environment = {k: v for k, v in os.environ.items() if k != "GZCTF_FLAG"}
        environment["PCAP_PATH"] = os.path.join(directory, "capture.pcap")

        process = self.run_generator(environment)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("GZCTF_FLAG is missing or empty", process.stderr)
        self.assertFalse(os.path.exists(environment["PCAP_PATH"]))

    def test_generator_fails_with_blank_flag(self):
        directory = tempfile.mkdtemp()
        environment = dict(os.environ, GZCTF_FLAG="  ", PCAP_PATH=os.path.join(directory, "capture.pcap"))

        process = self.run_generator(environment)
        self.assertNotEqual(process.returncode, 0)
        self.assertFalse(os.path.exists(environment["PCAP_PATH"]))

    def test_generator_does_not_log_the_flag(self):
        directory = tempfile.mkdtemp()
        flag = "GZCTF{never_log_this_value}"
        environment = dict(
            os.environ, GZCTF_FLAG=flag, PCAP_PATH=os.path.join(directory, "capture.pcap")
        )

        process = self.run_generator(environment)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertNotIn(flag, process.stdout)
        self.assertNotIn(flag, process.stderr)
        self.assertTrue(os.path.exists(environment["PCAP_PATH"]))

    def test_utf8_flag_is_supported(self):
        directory = tempfile.mkdtemp()
        flag = "AXUM{transmission_\u00e9t\u00e9_2026}"
        environment = dict(
            os.environ, GZCTF_FLAG=flag, PCAP_PATH=os.path.join(directory, "capture.pcap")
        )

        process = self.run_generator(environment)
        self.assertEqual(process.returncode, 0, process.stderr)

        from scapy.all import rdpcap
        import generate_capture

        payload = generate_capture.recover_ftp_payload(rdpcap(environment["PCAP_PATH"]))
        import io
        import zipfile

        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            report = archive.read("evidence/incident_summary.txt").decode("utf-8")
        self.assertIn(flag, report)

    def test_flag_only_reachable_through_the_archive(self):
        """The flag must not appear in DNS, HTTP or FTP control in the capture."""
        directory = tempfile.mkdtemp()
        flag = "GZCTF{confidentiality_probe_42}"
        environment = dict(
            os.environ, GZCTF_FLAG=flag, PCAP_PATH=os.path.join(directory, "capture.pcap")
        )
        self.assertEqual(self.run_generator(environment).returncode, 0)

        from scapy.all import DNS, rdpcap
        import generate_capture

        packets = rdpcap(environment["PCAP_PATH"])
        commands, replies = generate_capture.recover_ftp_control(packets)
        requests, responses = generate_capture.recover_http_stream(packets)

        self.assertNotIn(flag.encode(), commands + replies)
        self.assertNotIn(flag.encode(), requests + responses)
        for packet in packets:
            if packet.haslayer(DNS) and packet[DNS].qd is not None:
                self.assertNotIn(flag, packet[DNS].qd.qname.decode())


if __name__ == "__main__":
    unittest.main(verbosity=2)
