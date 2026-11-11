"""HTTP application and container integration tests for NET-02 — Lost in DNS.

The application tests run the real server in-process against a generated
capture. The integration tests exercise the built image exactly as GZ::CTF
would: a fresh container per team, a synthetic flag, artifact download and
independent decoding.
"""

import http.client
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(PROJECT, "src")
sys.path.insert(0, SRC)

import app as webapp  # noqa: E402
import generate_capture  # noqa: E402
from encoding import SUSPICIOUS_SUFFIX, decode_names  # noqa: E402

IMAGE = os.environ.get("NET02_IMAGE", "net-02-lost-in-dns:test")
FLAG = "GZCTF{NET02_APP_TEST_FLAG}"


def docker_available():
    from shutil import which

    return which("docker") is not None


class AppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.mkdtemp(prefix="net02-app-")
        cls.capture_path = os.path.join(cls.directory, "capture.pcap")
        generate_capture.generate(FLAG, cls.capture_path)

        cls.server = webapp.build_server("127.0.0.1", 0, cls.capture_path)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.1})
        cls.thread.daemon = True
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def get(self, path):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        connection.request("GET", path)
        response = connection.getresponse()
        body = response.read()
        headers = {name.lower(): value for name, value in response.getheaders()}
        connection.close()
        return response.status, headers, body

    def test_landing_page(self):
        status, headers, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["content-type"])
        text = body.decode()
        self.assertIn("Lost in DNS", text)
        self.assertIn("capture.pcap", text)

    def test_landing_page_reports_size(self):
        _, _, body = self.get("/")
        size = os.path.getsize(self.capture_path)
        self.assertIn(f"{size / 1024:.1f} KB", body.decode())

    def test_download(self):
        status, headers, body = self.get("/download")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/vnd.tcpdump.pcap")
        self.assertIn('filename="capture.pcap"', headers["content-disposition"])
        self.assertEqual(body, open(self.capture_path, "rb").read())

    def test_download_payload_decodes_to_the_flag(self):
        _, _, body = self.get("/download")
        from scapy.all import DNS, rdpcap

        packets = rdpcap(io.BytesIO(body))
        names = [
            packet[DNS].qd.qname.decode().rstrip(".")
            for packet in packets
            if packet.haslayer(DNS) and packet[DNS].qr == 0 and packet[DNS].qd is not None
            and packet[DNS].qd.qname.decode().rstrip(".").endswith(SUSPICIOUS_SUFFIX)
        ]
        self.assertEqual(decode_names(names), FLAG)

    def test_health(self):
        status, headers, body = self.get("/health")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["capture"], "ready")

    def test_stylesheet(self):
        status, headers, _ = self.get("/static/style.css")
        self.assertEqual(status, 200)
        self.assertIn("text/css", headers["content-type"])

    def test_unknown_path_is_404(self):
        status, _, body = self.get("/nope")
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body)["error"], "not_found")

    def test_path_traversal_is_prevented(self):
        for path in ("/../src/app.py", "/static/../src/app.py", "/download/../../etc/passwd"):
            status, _, body = self.get(path)
            self.assertEqual(status, 404, path)
            self.assertNotIn(b"import", body)

    def test_landing_page_has_no_flag(self):
        for path in ("/", "/health"):
            _, _, body = self.get(path)
            self.assertNotIn(FLAG.encode(), body)

    def test_no_directory_listing(self):
        for path in ("/static/", "/static", "/runtime/", "/src/"):
            status, _, _ = self.get(path)
            self.assertEqual(status, 404, path)

    def test_missing_artifact_is_handled(self):
        missing = os.path.join(tempfile.mkdtemp(), "capture.pcap")
        server = webapp.build_server("127.0.0.1", 0, missing)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1})
        thread.daemon = True
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            connection.request("GET", "/download")
            response = connection.getresponse()
            body = response.read()
            self.assertEqual(response.status, 503)
            self.assertEqual(json.loads(body)["error"], "capture_unavailable")

            connection.request("GET", "/health")
            response = connection.getresponse()
            self.assertEqual(response.status, 503)
            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


class Container:
    def __init__(self, flag, name):
        self.flag = flag
        self.name = name
        self.port = None

    def __enter__(self):
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)
        create = subprocess.run(
            [
                "docker", "run", "-d", "--name", self.name,
                "-e", f"GZCTF_FLAG={self.flag}",
                "-p", "127.0.0.1::8080",
                IMAGE,
            ],
            capture_output=True,
            text=True,
        )
        if create.returncode != 0:
            raise RuntimeError(f"container failed to start: {create.stderr[-500:]}")

        for _ in range(120):
            mapping = subprocess.run(
                ["docker", "port", self.name, "8080/tcp"], capture_output=True, text=True
            ).stdout.strip()
            if mapping:
                self.port = mapping.rsplit(":", 1)[1]
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("container never published a port")

        for _ in range(90):
            status = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Health.Status}}", self.name],
                capture_output=True, text=True,
            ).stdout.strip()
            if status == "healthy":
                return self
            state = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Status}}", self.name],
                capture_output=True, text=True,
            ).stdout.strip()
            if state == "exited":
                logs = subprocess.run(["docker", "logs", self.name], capture_output=True, text=True)
                raise RuntimeError(f"container exited: {(logs.stdout + logs.stderr)[-800:]}")
            time.sleep(1)

        raise RuntimeError("container never became healthy")

    def __exit__(self, *_exc):
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)
        return False

    def get(self, path):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=30) as response:
            return response.status, dict(response.headers), response.read()

    def logs(self):
        result = subprocess.run(["docker", "logs", self.name], capture_output=True, text=True)
        return (result.stdout or "") + (result.stderr or "")

    def exec(self, script):
        return subprocess.run(
            ["docker", "exec", "-i", self.name, "sh", "-c", script], capture_output=True, text=True
        )


def extract_flag(capture_bytes):
    from scapy.all import DNS, rdpcap

    packets = rdpcap(io.BytesIO(capture_bytes))
    names = [
        packet[DNS].qd.qname.decode().rstrip(".")
        for packet in packets
        if packet.haslayer(DNS) and packet[DNS].qr == 0 and packet[DNS].qd is not None
        and packet[DNS].qd.qname.decode().rstrip(".").endswith(SUSPICIOUS_SUFFIX)
    ]
    return decode_names(names)


@unittest.skipUnless(docker_available(), "docker is not available")
class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True)
        if result.returncode != 0:
            build = subprocess.run(
                ["docker", "build", "-q", "-t", IMAGE, PROJECT], capture_output=True, text=True, timeout=1800
            )
            if build.returncode != 0:
                raise RuntimeError(f"image build failed: {build.stderr[-800:]}")

        cls.flag_a = "GZCTF{NET02_TEAM_A_TEST}"
        cls.flag_b = "GZCTF{NET02_TEAM_B_TEST}"
        cls.team_a = Container(cls.flag_a, f"net02-it-a-{os.getpid()}").__enter__()
        cls.team_b = Container(cls.flag_b, f"net02-it-b-{os.getpid()}").__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.team_a.__exit__(None, None, None)
        cls.team_b.__exit__(None, None, None)

    def test_container_generates_the_capture_at_runtime(self):
        status, _, _ = self.team_a.get("/health")
        self.assertEqual(status, 200)

        result = self.team_a.exec("test -s /app/runtime/capture.pcap && echo present || echo missing")
        self.assertEqual(result.stdout.strip(), "present")

    def test_download_reconstructs_the_exact_injected_flag(self):
        _, headers, body = self.team_a.get("/download")
        self.assertEqual(headers.get("Content-Type"), "application/vnd.tcpdump.pcap")
        self.assertEqual(extract_flag(body), self.flag_a)

    def test_second_team_gets_a_separate_artifact(self):
        _, _, body_a = self.team_a.get("/download")
        _, _, body_b = self.team_b.get("/download")

        self.assertNotEqual(body_a, body_b)
        self.assertEqual(extract_flag(body_a), self.flag_a)
        self.assertEqual(extract_flag(body_b), self.flag_b)

    def test_no_cross_contamination(self):
        _, _, body_a = self.team_a.get("/download")
        _, _, body_b = self.team_b.get("/download")

        self.assertNotIn(self.flag_a.encode(), body_a)
        self.assertNotIn(self.flag_b.encode(), body_a)
        self.assertNotIn(self.flag_a.encode(), body_b)
        self.assertNotIn(self.flag_b.encode(), body_b)

    def test_no_plaintext_flag_in_logs_or_pages(self):
        for container, flag in ((self.team_a, self.flag_a), (self.team_b, self.flag_b)):
            self.assertNotIn(flag, container.logs())
            for path in ("/", "/health"):
                _, _, body = container.get(path)
                self.assertNotIn(flag.encode(), body)

    def test_runs_as_non_root_without_capabilities(self):
        self.assertEqual(self.team_a.exec("id -u").stdout.strip(), "10001")

        inspect = json.loads(
            subprocess.run(
                ["docker", "inspect", self.team_a.name], capture_output=True, text=True
            ).stdout
        )[0]
        host = inspect["HostConfig"]
        self.assertFalse(host["Privileged"])
        self.assertIn(host["Binds"], (None, []))
        self.assertEqual(inspect["Mounts"], [])
        self.assertNotEqual(host["NetworkMode"], "host")

    def test_service_process_has_no_flag(self):
        result = self.team_a.exec("grep -a -c GZCTF_FLAG= /proc/1/environ 2>/dev/null")
        self.assertEqual(result.stdout.strip(), "0")


if __name__ == "__main__":
    unittest.main(verbosity=2)
