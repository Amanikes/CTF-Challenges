"""HTTP application and container integration tests for NET-03.

The application tests run the real server in-process. The integration tests
exercise the built image exactly as GZ::CTF would: one container per team, a
synthetic flag, artifact download, and recovery of the archive from the
downloaded capture alone.
"""

import http.client
import io
import json
import os
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

import support  # noqa: F401 - adjusts sys.path

import app as webapp
import generate_capture
from artifact import EVIDENCE_PATH
from support import IMAGE
from topology import FTP_DATA_PORT

FLAG = "GZCTF{NET03_APP_TEST_FLAG}"


def docker_available():
    from shutil import which

    return which("docker") is not None


def recover_flag_from_capture(path):
    """Full participant path against a capture file on disk."""
    from scapy.all import TCP, rdpcap

    packets = rdpcap(str(path))
    segments = sorted(
        (packet for packet in packets
         if packet.haslayer(TCP) and packet.haslayer("Raw") and packet[TCP].sport == FTP_DATA_PORT),
        key=lambda packet: packet[TCP].seq,
    )
    payload = b"".join(bytes(packet[TCP].payload) for packet in segments)

    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        report = archive.read(EVIDENCE_PATH).decode("utf-8")

    return [line.strip() for line in report.splitlines() if line.strip().startswith("GZCTF{")]


class AppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.mkdtemp(prefix="net03-app-")
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
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
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
        self.assertIn("The Last Transmission", text)
        self.assertIn("capture.pcap", text)
        self.assertIn("Asterion", text)

    def test_landing_page_reports_size(self):
        _, _, body = self.get("/")
        self.assertIn(webapp.format_size(os.path.getsize(self.capture_path)), body.decode())

    def test_download(self):
        status, headers, body = self.get("/download")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/vnd.tcpdump.pcap")
        self.assertIn('filename="capture.pcap"', headers["content-disposition"])
        self.assertEqual(body, Path(self.capture_path).read_bytes())

    def test_download_payload_yields_the_flag(self):
        _, _, body = self.get("/download")
        path = Path(tempfile.mkdtemp()) / "capture.pcap"
        path.write_bytes(body)
        self.assertEqual(recover_flag_from_capture(path), [FLAG])

    def test_health(self):
        status, _, body = self.get("/health")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["capture"], "ready")

    def test_stylesheet_and_favicon(self):
        for path, content_type in (
            ("/static/style.css", "text/css"),
            ("/static/favicon.svg", "image/svg+xml"),
        ):
            status, headers, _ = self.get(path)
            self.assertEqual(status, 200, path)
            self.assertIn(content_type, headers["content-type"])

    def test_unknown_path_is_404(self):
        status, _, body = self.get("/missing")
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body)["error"], "not_found")

    def test_path_traversal_is_prevented(self):
        for path in ("/../src/app.py", "/static/../src/app.py", "/download/../../etc/passwd"):
            status, _, body = self.get(path)
            self.assertEqual(status, 404, path)
            self.assertNotIn(b"import ", body)

    def test_no_directory_listing(self):
        for path in ("/static/", "/static", "/src/", "/artifacts/"):
            status, _, _ = self.get(path)
            self.assertEqual(status, 404, path)

    def test_landing_page_hides_solution_details(self):
        _, _, body = self.get("/")
        text = body.decode()
        for secret in (
            FLAG,
            "GZCTF{",
            "AX-7842",
            "incident_summary",
            "confidential_bundle",
            "50000",
            "archive-access",
            "files-update",
        ):
            self.assertNotIn(secret, text)

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
            self.assertEqual(response.status, 503)
            self.assertEqual(json.loads(response.read())["error"], "capture_unavailable")

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
            ["docker", "run", "-d", "--name", self.name,
             "-e", f"GZCTF_FLAG={self.flag}", "-p", "127.0.0.1::8080", IMAGE],
            capture_output=True, text=True,
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
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=60) as response:
            return response.status, dict(response.headers), response.read()

    def download(self):
        _, _, body = self.get("/download")
        path = Path(tempfile.mkdtemp(prefix="net03-dl-")) / "capture.pcap"
        path.write_bytes(body)
        return path

    def logs(self):
        result = subprocess.run(["docker", "logs", self.name], capture_output=True, text=True)
        return (result.stdout or "") + (result.stderr or "")

    def exec(self, script):
        return subprocess.run(
            ["docker", "exec", "-i", self.name, "sh", "-c", script], capture_output=True, text=True
        )


@unittest.skipUnless(docker_available(), "docker is not available")
class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode != 0:
            build = subprocess.run(
                ["docker", "build", "-q", "-t", IMAGE, support.PROJECT],
                capture_output=True, text=True, timeout=1800,
            )
            if build.returncode != 0:
                raise RuntimeError(f"image build failed: {build.stderr[-800:]}")

        cls.flag_a = "GZCTF{NET03_TEAM_A_TEST}"
        cls.flag_b = "GZCTF{NET03_TEAM_B_TEST}"
        cls.team_a = Container(cls.flag_a, f"net03-it-a-{os.getpid()}").__enter__()
        cls.team_b = Container(cls.flag_b, f"net03-it-b-{os.getpid()}").__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.team_a.__exit__(None, None, None)
        cls.team_b.__exit__(None, None, None)

    def test_capture_generated_at_runtime(self):
        self.assertEqual(self.team_a.get("/health")[0], 200)
        result = self.team_a.exec("test -s /app/artifacts/capture.pcap && echo present || echo missing")
        self.assertEqual(result.stdout.strip(), "present")

    def test_download_reconstructs_the_injected_flag(self):
        path = self.team_a.download()
        self.assertEqual(recover_flag_from_capture(path), [self.flag_a])

    def test_teams_get_independent_artifacts(self):
        path_a = self.team_a.download()
        path_b = self.team_b.download()

        self.assertNotEqual(path_a.read_bytes(), path_b.read_bytes())
        self.assertEqual(recover_flag_from_capture(path_a), [self.flag_a])
        self.assertEqual(recover_flag_from_capture(path_b), [self.flag_b])

    def test_no_cross_contamination(self):
        body_a = self.team_a.download().read_bytes()
        body_b = self.team_b.download().read_bytes()
        self.assertNotIn(self.flag_a.encode(), body_b)
        self.assertNotIn(self.flag_b.encode(), body_a)

    def test_no_flag_in_logs_or_pages(self):
        for container, flag in ((self.team_a, self.flag_a), (self.team_b, self.flag_b)):
            self.assertNotIn(flag, container.logs())
            for path in ("/", "/health"):
                self.assertNotIn(flag.encode(), container.get(path)[2])

    def test_runs_as_non_root_without_capabilities(self):
        self.assertEqual(self.team_a.exec("id -u").stdout.strip(), "10001")

        inspect = json.loads(subprocess.run(
            ["docker", "inspect", self.team_a.name], capture_output=True, text=True
        ).stdout)[0]
        host = inspect["HostConfig"]
        self.assertFalse(host["Privileged"])
        self.assertIn(host["Binds"], (None, []))
        self.assertEqual(inspect["Mounts"], [])
        self.assertNotEqual(host["NetworkMode"], "host")
        self.assertIn(host.get("CapAdd"), (None, []))

    def test_service_process_has_no_flag(self):
        result = self.team_a.exec("grep -a -c GZCTF_FLAG= /proc/1/environ 2>/dev/null")
        self.assertEqual(result.stdout.strip(), "0")

    def test_no_docker_socket(self):
        result = self.team_a.exec("test -S /var/run/docker.sock && echo present || echo absent")
        self.assertEqual(result.stdout.strip(), "absent")

    def test_image_contains_no_flag(self):
        result = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint", "sh", IMAGE, "-c",
             f"grep -ralF '{self.flag_a}' /app 2>/dev/null | head -n1"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.stdout.strip(), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
