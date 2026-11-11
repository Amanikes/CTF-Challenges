"""Shared helpers for the NET-01 test suite.

Parsing is done with Scapy (the same library the generator uses) and, where
available, cross-checked with tcpdump as an independent parser.
"""

import os
import shutil
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMAGE = os.environ.get("NET01_IMAGE", "net-01-unencrypted-secrets:test")
CAPTURE_NAME = "meridian-traffic.pcap"
GENERATOR = ROOT / "scripts" / "generate_capture.py"

PORTAL = "192.168.10.10"
REPORTING = "192.168.10.20"
WORKSTATION_A = "192.168.10.25"
WORKSTATION_B = "192.168.10.30"
INTERNAL_DNS = "192.168.10.53"
TARGET_HOST = "portal.meridian.internal"
TARGET_PATH = "/internal/api/session"
TARGET_HEADER = "X-Meridian-Session"


def run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def generate(flag, output_dir=None):
    """Run the generator exactly as the entrypoint does; return (path, process)."""
    directory = output_dir or tempfile.mkdtemp(prefix="net01-")
    path = Path(directory) / CAPTURE_NAME

    environment = dict(os.environ)
    environment.pop("GZCTF_FLAG", None)
    if flag is not None:
        environment["GZCTF_FLAG"] = flag

    process = subprocess.run(
        ["python3", str(GENERATOR), "--output", str(path)],
        capture_output=True,
        text=True,
        env=environment,
        timeout=300,
    )
    return path, process


def http_payloads(packets):
    from scapy.all import Raw

    for packet in packets:
        if packet.haslayer(Raw):
            yield packet, bytes(packet[Raw].load)


def target_request(packets):
    for packet, data in http_payloads(packets):
        if TARGET_PATH.encode() in data:
            return packet, data
    return None, None


def reassemble(packets, client, server, client_port, server_port):
    """Rebuild one direction of a TCP conversation from sequence numbers."""
    from scapy.all import IP, TCP, Raw

    segments = []
    for packet in packets:
        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            continue
        if packet[IP].src != client or packet[IP].dst != server:
            continue
        if packet[TCP].sport != client_port or packet[TCP].dport != server_port:
            continue
        segments.append((packet[TCP].seq, bytes(packet[Raw].load)))

    segments.sort(key=lambda item: item[0])
    return b"".join(data for _, data in segments)


def tcpdump_available():
    return shutil.which("tcpdump") is not None


def tcpdump_text(path, extra=None):
    command = ["tcpdump", "-nn", "-r", str(path)]
    if extra:
        command.extend(extra)
    return run(command)


class Instance:
    """One running challenge container."""

    def __init__(self, flag, name=None):
        self.flag = flag
        self.name = name or f"net01-test-{os.getpid()}-{abs(hash(flag)) % 100000}"
        self.port = None

    def __enter__(self):
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
            raise RuntimeError(f"container failed to start: {create.stderr[-500:]}")

        self.port = self._wait_port()
        self._wait_healthy()
        return self

    def __exit__(self, *_exc):
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)
        return False

    def _wait_port(self):
        for _ in range(120):
            mapping = run(["docker", "port", self.name, "3000/tcp"]).stdout.strip()
            if mapping:
                return mapping.rsplit(":", 1)[1]
            time.sleep(0.5)
        raise RuntimeError("container never published a port")

    def _wait_healthy(self):
        for _ in range(90):
            status = run(
                ["docker", "inspect", "--format", "{{.State.Health.Status}}", self.name]
            ).stdout.strip()
            if status == "healthy":
                return
            state = run(["docker", "inspect", "--format", "{{.State.Status}}", self.name]).stdout.strip()
            if state == "exited":
                logs = run(["docker", "logs", self.name])
                raise RuntimeError(f"container exited: {(logs.stdout + logs.stderr)[-800:]}")
            time.sleep(1)
        raise RuntimeError("container never became healthy")

    def fetch_capture(self):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/download", timeout=60) as response:
            return response.read()

    def save_capture(self, directory=None):
        directory = directory or tempfile.mkdtemp(prefix="net01-")
        path = Path(directory) / CAPTURE_NAME
        path.write_bytes(self.fetch_capture())
        return path

    def logs(self):
        result = run(["docker", "logs", self.name])
        return (result.stdout or "") + (result.stderr or "")

    def exec(self, script):
        return subprocess.run(
            ["docker", "exec", "-i", self.name, "sh", "-c", script],
            capture_output=True,
            timeout=120,
        )


def image_config():
    import json

    result = run(["docker", "image", "inspect", IMAGE])
    return json.loads(result.stdout)[0]["Config"]
