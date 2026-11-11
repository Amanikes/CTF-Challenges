"""Container security checks for REV-02 — Phantom Protocol.

These verify the build/runtime design rather than relying on a single string
search: the image configuration, the running container's isolation settings and
the process environment are all inspected.
"""

import json
import unittest

from support import (
    ChallengeInstance,
    IMAGE,
    docker_available,
    ensure_image,
    image_config,
    run,
)

FLAG = "AXUM{phantom_security_77}"


@unittest.skipUnless(docker_available(), "docker is not available")
class SecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ensure_image()
        cls.instance = ChallengeInstance(FLAG).__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.instance.__exit__(None, None, None)

    def test_runs_as_non_root_user(self):
        self.assertEqual(image_config().get("User"), "node")
        result = self.instance.exec("id -u")
        self.assertEqual(result.stdout.strip(), b"1000")

    def test_container_is_not_privileged(self):
        inspect = json.loads(run(["docker", "inspect", self.instance.name]).stdout)[0]
        self.assertFalse(inspect["HostConfig"]["Privileged"])
        self.assertIn(inspect["HostConfig"]["Binds"], (None, []))
        self.assertEqual(inspect["Mounts"], [])
        self.assertNotEqual(inspect["HostConfig"]["NetworkMode"], "host")

    def test_only_the_http_port_is_published(self):
        published = run(["docker", "port", self.instance.name]).stdout.strip().splitlines()
        self.assertEqual(len(published), 1)
        self.assertIn("3000/tcp", published[0])

    def test_no_docker_socket_inside_the_container(self):
        result = self.instance.exec("test -S /var/run/docker.sock && echo present || echo absent")
        self.assertEqual(result.stdout.strip(), b"absent")

    def test_no_plaintext_flag_in_the_image(self):
        ensure_image()
        # Scan the image filesystem itself, not a running instance.
        result = run(
            [
                "docker", "run", "--rm", "--entrypoint", "sh", IMAGE,
                "-c",
                f"grep -ralF '{FLAG}' /app 2>/dev/null | head -n1",
            ]
        )
        self.assertEqual(result.stdout.strip(), "")

    def test_image_configuration_has_no_flag(self):
        environment = image_config().get("Env") or []
        self.assertFalse(any(entry.startswith("GZCTF_FLAG=") for entry in environment))

    def test_download_service_process_has_no_flag(self):
        result = self.instance.exec(
            'for p in /proc/[0-9]*; do cmd=$(tr "\\0" " " < $p/cmdline 2>/dev/null); '
            '[ "$cmd" = "node /app/server/server.js " ] && echo "${p##*/}"; done'
        )
        pid = result.stdout.split()[0].decode() if result.stdout.split() else ""
        self.assertTrue(pid, "download service process not found")

        environment = self.instance.exec(f"grep -a -c GZCTF_FLAG= /proc/{pid}/environ 2>/dev/null")
        self.assertEqual(environment.stdout.strip(), b"0")

    def test_logs_do_not_contain_the_flag(self):
        logs = run(["docker", "logs", self.instance.name])
        combined = (logs.stdout or "") + (logs.stderr or "")
        self.assertNotIn(FLAG, combined)


if __name__ == "__main__":
    unittest.main(verbosity=2)
