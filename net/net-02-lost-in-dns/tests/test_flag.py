"""Configuration and flag-handling tests for NET-02 — Lost in DNS."""

import os
import subprocess
import sys
import tempfile
import unittest

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(PROJECT, "src")
sys.path.insert(0, SRC)

from config import DEFAULT_PORT, ConfigError, load_config  # noqa: E402


class ConfigTests(unittest.TestCase):
    def test_missing_flag_is_rejected(self):
        with self.assertRaises(ConfigError) as context:
            load_config({})
        self.assertIn("GZCTF_FLAG is missing or empty", str(context.exception))

    def test_empty_flag_is_rejected(self):
        with self.assertRaises(ConfigError):
            load_config({"GZCTF_FLAG": "   "})

    def test_default_port(self):
        config = load_config({"GZCTF_FLAG": "GZCTF{x}"})
        self.assertEqual(config.port, DEFAULT_PORT)

    def test_custom_port(self):
        self.assertEqual(load_config({"GZCTF_FLAG": "GZCTF{x}", "PORT": "9000"}).port, 9000)

    def test_invalid_port_is_rejected(self):
        for value in ("abc", "0", "70000", "-1"):
            with self.assertRaises(ConfigError):
                load_config({"GZCTF_FLAG": "GZCTF{x}", "PORT": value})

    def test_invalid_log_level_is_rejected(self):
        with self.assertRaises(ConfigError):
            load_config({"GZCTF_FLAG": "GZCTF{x}", "LOG_LEVEL": "LOUD"})

    def test_capture_path_override(self):
        config = load_config({"GZCTF_FLAG": "GZCTF{x}", "PCAP_PATH": "/tmp/custom.pcap"})
        self.assertEqual(config.capture_path, "/tmp/custom.pcap")

    def test_repr_never_contains_the_flag(self):
        config = load_config({"GZCTF_FLAG": "GZCTF{super_secret_value}"})
        self.assertNotIn("super_secret_value", repr(config))

    def test_flag_is_not_required_for_the_web_process(self):
        config = load_config({}, require_flag=False)
        self.assertIsNone(config.flag)


class GeneratorProcessTests(unittest.TestCase):
    def run_generator(self, environment):
        return subprocess.run(
            [sys.executable, os.path.join(SRC, "generate_capture.py")],
            capture_output=True,
            text=True,
            env=environment,
            timeout=300,
        )

    def test_generator_fails_without_flag(self):
        environment = {key: value for key, value in os.environ.items() if key != "GZCTF_FLAG"}
        environment["PCAP_PATH"] = os.path.join(tempfile.mkdtemp(), "capture.pcap")

        process = self.run_generator(environment)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("GZCTF_FLAG is missing or empty", process.stderr)
        self.assertFalse(os.path.exists(environment["PCAP_PATH"]))

    def test_generator_fails_with_blank_flag(self):
        directory = tempfile.mkdtemp()
        environment = dict(os.environ, GZCTF_FLAG="   ", PCAP_PATH=os.path.join(directory, "capture.pcap"))

        process = self.run_generator(environment)
        self.assertNotEqual(process.returncode, 0)
        self.assertFalse(os.path.exists(environment["PCAP_PATH"]))

    def test_generator_does_not_log_the_flag(self):
        directory = tempfile.mkdtemp()
        flag = "GZCTF{log_confidentiality_check}"
        environment = dict(
            os.environ,
            GZCTF_FLAG=flag,
            PCAP_PATH=os.path.join(directory, "capture.pcap"),
        )

        process = self.run_generator(environment)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertNotIn(flag, process.stdout)
        self.assertNotIn(flag, process.stderr)
        self.assertTrue(os.path.exists(environment["PCAP_PATH"]))

    def test_generator_rejects_over_long_flag(self):
        directory = tempfile.mkdtemp()
        environment = dict(
            os.environ,
            GZCTF_FLAG="A" * 600,
            PCAP_PATH=os.path.join(directory, "capture.pcap"),
        )

        process = self.run_generator(environment)
        self.assertNotEqual(process.returncode, 0)
        self.assertNotIn("A" * 600, process.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
