"""Two-instance isolation and container security tests for NET-01."""

import json
import unittest
import urllib.request

from support import IMAGE, Instance, image_config, run

FLAG_A = "GZCTF{TEAM_A_TEST}"
FLAG_B = "GZCTF{TEAM_B_TEST}"


def parse(path):
    from scapy.all import rdpcap

    return rdpcap(str(path))


class IsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.instance_a = Instance(FLAG_A).__enter__()
        cls.instance_b = Instance(FLAG_B).__enter__()
        cls.capture_a = cls.instance_a.save_capture()
        cls.capture_b = cls.instance_b.save_capture()

    @classmethod
    def tearDownClass(cls):
        cls.instance_a.__exit__(None, None, None)
        cls.instance_b.__exit__(None, None, None)

    def test_each_capture_carries_its_own_flag(self):
        self.assertIn(FLAG_A.encode(), self.capture_a.read_bytes())
        self.assertIn(FLAG_B.encode(), self.capture_b.read_bytes())

    def test_captures_never_cross_contaminate(self):
        self.assertNotIn(FLAG_B.encode(), self.capture_a.read_bytes())
        self.assertNotIn(FLAG_A.encode(), self.capture_b.read_bytes())

    def test_captures_differ(self):
        self.assertNotEqual(self.capture_a.read_bytes(), self.capture_b.read_bytes())

    def test_downloaded_captures_are_valid_pcaps(self):
        for path in (self.capture_a, self.capture_b):
            packets = parse(path)
            self.assertGreater(len(packets), 40)

    def test_each_download_serves_only_its_own_artifact(self):
        # The target request in each capture must carry that instance's flag and
        # nothing else; the other instance's flag must be entirely absent.
        from support import target_request

        for instance, path in ((self.instance_a, self.capture_a), (self.instance_b, self.capture_b)):
            packets = parse(path)
            packet, data = target_request(packets)
            self.assertIsNotNone(packet, "target request missing")
            self.assertIn(instance.flag.encode(), data)

            blob = path.read_bytes()
            self.assertEqual(blob.count(instance.flag.encode()), 1)
            other = self.instance_b.flag if instance is self.instance_a else self.instance_a.flag
            self.assertNotIn(other.encode(), blob)

    def test_logs_do_not_contain_the_flag(self):
        for instance in (self.instance_a, self.instance_b):
            logs = instance.logs()
            self.assertNotIn(instance.flag, logs)

    def test_landing_page_does_not_contain_the_flag_or_header(self):
        for instance in (self.instance_a, self.instance_b):
            with urllib.request.urlopen(f"http://127.0.0.1:{instance.port}/", timeout=20) as response:
                page = response.read().decode("utf-8", "replace")
            self.assertNotIn(instance.flag, page)
            self.assertNotIn("X-Meridian-Session", page)

    def test_health_endpoint_reports_ready(self):
        for instance in (self.instance_a, self.instance_b):
            with urllib.request.urlopen(f"http://127.0.0.1:{instance.port}/health", timeout=20) as response:
                payload = json.loads(response.read())
            self.assertEqual(payload.get("status"), "ok")
            self.assertEqual(payload.get("capture"), "ready")

    def test_download_headers(self):
        instance = self.instance_a
        request = urllib.request.Request(f"http://127.0.0.1:{instance.port}/download")
        with urllib.request.urlopen(request, timeout=30) as response:
            headers = dict(response.headers)
            body = response.read()
        self.assertEqual(headers.get("Content-Type"), "application/vnd.tcpdump.pcap")
        self.assertIn("filename=meridian-traffic.pcap", headers.get("Content-Disposition", ""))
        self.assertTrue(body.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1")))

    def test_unknown_paths_are_404(self):
        instance = self.instance_a
        with self.assertRaises(urllib.error.HTTPError) as context:
            urllib.request.urlopen(f"http://127.0.0.1:{instance.port}/etc/passwd", timeout=10)
        self.assertEqual(context.exception.code, 404)
        context.exception.close()


class ContainerSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.instance = Instance("GZCTF{NET01_SECURITY}").__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.instance.__exit__(None, None, None)

    def test_runs_as_non_root(self):
        self.assertEqual(image_config().get("User"), "node")
        self.assertEqual(self.instance.exec("id -u").stdout.strip(), b"1000")

    def test_container_is_isolated(self):
        inspect = json.loads(run(["docker", "inspect", self.instance.name]).stdout)[0]
        host = inspect["HostConfig"]

        self.assertFalse(host["Privileged"])
        self.assertIn(host["Binds"], (None, []))
        self.assertEqual(inspect["Mounts"], [])
        self.assertNotEqual(host["NetworkMode"], "host")
        self.assertIn(host.get("CapAdd"), (None, []))
        self.assertIn(host.get("CapDrop"), (None, []))

    def test_only_the_http_port_is_published(self):
        published = run(["docker", "port", self.instance.name]).stdout.strip().splitlines()
        self.assertEqual(len(published), 1)
        self.assertIn("3000/tcp", published[0])

    def test_no_docker_socket(self):
        result = self.instance.exec("test -S /var/run/docker.sock && echo present || echo absent")
        self.assertEqual(result.stdout.strip(), b"absent")

    def test_service_process_has_no_flag(self):
        result = self.instance.exec(
            'for p in /proc/[0-9]*; do cmd=$(tr "\\0" " " < $p/cmdline 2>/dev/null); '
            '[ "$cmd" = "node /app/server/server.js " ] && echo "${p##*/}"; done'
        )
        pid = result.stdout.split()[0].decode() if result.stdout.split() else ""
        self.assertTrue(pid, "download service process not found")

        hits = self.instance.exec(f"grep -a -c GZCTF_FLAG= /proc/{pid}/environ 2>/dev/null")
        self.assertEqual(hits.stdout.strip(), b"0")

    def test_image_contains_no_flag(self):
        result = run(
            ["docker", "run", "--rm", "--entrypoint", "sh", IMAGE, "-c",
             "grep -ralF 'GZCTF{NET01_SECURITY}' /app 2>/dev/null | head -n1"]
        )
        self.assertEqual(result.stdout.strip(), "")

    def test_image_config_declares_no_flag(self):
        environment = image_config().get("Env") or []
        self.assertFalse(any(entry.startswith("GZCTF_FLAG=") for entry in environment))


if __name__ == "__main__":
    unittest.main(verbosity=2)
