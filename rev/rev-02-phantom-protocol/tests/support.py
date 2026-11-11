"""Shared helpers for the REV-02 test suite.

The packaged phantom-client is never executed on the host: every binary test
runs inside a container built from the challenge image, which is also how the
platform runs it.
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMAGE = os.environ.get("REV02_IMAGE", "rev-02-phantom-protocol:test")
PACKAGE_DIRECTORY = "phantom-protocol"
ARCHIVE_NAME = "phantom-protocol-package.zip"
CLIENT_CONTAINER_PATH = "/app/bin/phantom-client"
SANDBOX = "/tmp/phantom-sandbox"

_docker_available = None


def docker_available():
    global _docker_available
    if _docker_available is None:
        _docker_available = shutil.which("docker") is not None and subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
        ).returncode == 0
    return _docker_available


def run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def ensure_image():
    if not docker_available():
        raise RuntimeError("docker is not available")

    result = run(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"])
    if result.returncode != 0:
        build = run(["docker", "build", "-q", "-t", IMAGE, str(ROOT)], timeout=1800)
        if build.returncode != 0:
            raise RuntimeError(f"image build failed: {build.stderr[-800:]}")


class ChallengeInstance:
    """A single running challenge container with a known injected flag."""

    def __init__(self, flag, name=None):
        self.flag = flag
        self.name = name or f"rev02-test-{os.getpid()}-{abs(hash(flag)) % 100000}"
        self.port = None

    def __enter__(self):
        ensure_image()
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)
        create = run(
            [
                "docker", "run", "-d", "--name", self.name,
                "-e", f"GZCTF_FLAG={self.flag}",
                "-p", "127.0.0.1::3000",
                IMAGE,
            ]
        )
        if create.returncode != 0:
            raise RuntimeError(f"could not start container: {create.stderr[-500:]}")

        self.port = self._mapped_port()
        self._wait_healthy()
        return self

    def __exit__(self, *_exc):
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)
        return False

    def _mapped_port(self):
        for _ in range(120):
            port = run(["docker", "port", self.name, "3000/tcp"]).stdout.strip()
            if port:
                return port.rsplit(":", 1)[1]
            time.sleep(0.5)
        raise RuntimeError("container never published a port")

    def _wait_healthy(self):
        for _ in range(60):
            status = run(
                ["docker", "inspect", "--format", "{{.State.Health.Status}}", self.name]
            ).stdout.strip()
            if status == "healthy":
                return
            time.sleep(1)
        raise RuntimeError("container never became healthy")

    def fetch_archive(self):
        import urllib.request

        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/download", timeout=30) as response:
            return response.read()

    def exec(self, script, stdin=None):
        return subprocess.run(
            ["docker", "exec", "-i", self.name, "sh", "-c", script],
            input=stdin,
            capture_output=True,
            timeout=120,
        )

    def run_client(self, protocol_bytes, args):
        """Copy the client into a sandbox, install protocol data and run it."""
        self.exec(f"rm -rf {SANDBOX} && mkdir -p {SANDBOX} && cp {CLIENT_CONTAINER_PATH} {SANDBOX}/")
        if protocol_bytes is not None:
            self.exec(f"cat > {SANDBOX}/protocol.dat", stdin=protocol_bytes)

        command = " ".join(args)
        return self.exec(f"cd {SANDBOX} && ./phantom-client {command}".strip())


def quarantine(*keys):
    """Temporarily remove environment keys, restoring them afterwards."""
    class _Guard:
        def __enter__(self):
            self.saved = {key: os.environ.get(key) for key in keys}
            for key in keys:
                os.environ.pop(key, None)
            return self

        def __exit__(self, *_exc):
            for key, value in self.saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
            return False

    return _Guard()


def generate_package(flag, output_dir, executable=None, readme=None):
    """Run the generator as the entrypoint does and return (path, process)."""
    environment = dict(os.environ)
    environment["GZCTF_FLAG"] = flag

    command = [
        "python3",
        str(ROOT / "generator" / "generate_package.py"),
        "--output-dir", str(output_dir),
        "--executable", str(executable or ROOT / "package" / "README.txt"),
        "--readme", str(readme or ROOT / "package" / "README.txt"),
    ]
    process = subprocess.run(command, capture_output=True, text=True, env=environment)
    return Path(output_dir) / ARCHIVE_NAME, process


def read_protocol(archive_path):
    with zipfile.ZipFile(archive_path) as archive:
        return archive.read(f"{PACKAGE_DIRECTORY}/protocol.dat")


# --- independent transformation helpers for the binary tests -----------------

ADD_BASE = 0x2B
ADD_STEP = 0x07
XOR_KEY = b"AegisPhantomKey!"
ROT_BASE = 3
ROT_STEP = 5


def forward_token(token):
    """Forward Phantom Protocol transformation, written independently of the generator."""
    output = bytearray(token)

    for index in range(len(output)):
        addend = (ADD_BASE + index * ADD_STEP) & 0xFF
        value = (output[index] + addend) & 0xFF
        value ^= XOR_KEY[index % len(XOR_KEY)]
        rotation = (ROT_BASE + index * ROT_STEP) & 7
        output[index] = value if rotation == 0 else ((value << rotation) | (value >> (8 - rotation))) & 0xFF

    return bytes(output)


def build_protocol(token, magic=b"PHTM", version=1, declared=None, reserved=0, extra=b""):
    """Build a protocol.dat image, optionally with a deliberately broken header."""
    payload = forward_token(token)
    length = len(payload) if declared is None else declared
    header = bytearray(8)
    header[0:4] = magic
    header[4] = version
    header[5] = length & 0xFF
    header[6] = (reserved >> 8) & 0xFF
    header[7] = reserved & 0xFF
    return bytes(header) + payload + extra


def recover_token(archive_path):
    result = run(
        [
            "python3", str(ROOT / "scripts" / "verify_solution.py"),
            "--archive", str(archive_path), "--quiet",
        ]
    )
    if result.returncode != 0:
        raise RuntimeError(f"recovery failed: {result.stderr.strip()}")
    return result.stdout.strip()


def image_config():
    result = run(["docker", "image", "inspect", IMAGE])
    return json.loads(result.stdout)[0]["Config"]


def tempdir():
    return tempfile.mkdtemp(prefix="rev02-")
