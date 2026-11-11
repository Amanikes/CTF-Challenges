"""HTTP stage tests for NET-03 — The Last Transmission."""

import json
import unittest

import support  # noqa: F401 - adjusts sys.path

from scapy.all import IP, Raw, TCP

import generate_capture
import http_traffic
from artifact import ARCHIVE_NAME, build_bundle
from topology import CLIENT_IP, INCIDENT_REFERENCE, SERVER_IP
import timeline

FLAG = "GZCTF{NET03_TEST_FLAG}"


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.archive = build_bundle(FLAG)
        cls.capture, cls.metadata = timeline.build(FLAG, cls.archive)
        cls.packets = cls.capture.ordered()
        cls.requests, cls.responses = generate_capture.recover_http_stream(cls.packets)

    def test_expected_requests_are_present(self):
        for path in (b"GET / ", b"GET /api/status ", b"GET /api/transfer/status ", b"GET /favicon.ico "):
            self.assertIn(path + b"HTTP/1.1", self.requests)

    def test_request_lines_are_well_formed(self):
        for line in self.requests.split(b"\r\n"):
            if not line:
                continue
            if line.startswith(b"GET "):
                method, target, version = line.split(b" ")
                self.assertEqual(method, b"GET")
                self.assertEqual(version, b"HTTP/1.1")
                self.assertTrue(target.startswith(b"/"))

    def test_every_response_is_complete(self):
        # Three 200s and one 404 in the suspicious conversation, plus the
        # background conversation (which is captured separately).
        self.assertGreaterEqual(self.responses.count(b"HTTP/1.1 200 OK"), 3)
        self.assertIn(b"HTTP/1.1 404 Not Found", self.responses)

    def test_content_length_matches_body(self):
        body = http_traffic.transfer_status_body(self.archive)
        expected = f"Content-Length: {len(body)}".encode()
        self.assertIn(expected, self.responses)
        self.assertIn(body.encode(), self.responses)

    def test_incident_reference_recoverable(self):
        self.assertIn(INCIDENT_REFERENCE.encode(), self.responses)

    def test_archive_name_recoverable(self):
        self.assertIn(ARCHIVE_NAME.encode(), self.responses)

    def test_transfer_status_document_is_valid_json(self):
        marker = b"{\n  \"status\": \"completed\""
        start = self.responses.index(marker)
        end = self.responses.index(b"}", start) + 1
        document = json.loads(self.responses[start:end])
        self.assertEqual(document["session"], INCIDENT_REFERENCE)
        self.assertEqual(document["archive"], ARCHIVE_NAME)
        self.assertEqual(document["size_bytes"], len(self.archive))

    def test_stream_is_reconstructable(self):
        # Sequence-number reassembly must produce the same bytes Wireshark shows.
        client_port = None
        for packet in self.packets:
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                if packet[IP].dst == SERVER_IP and packet[TCP].dport == 80:
                    client_port = packet[TCP].sport
                    break
        self.assertIsNotNone(client_port)

        rebuilt = b"".join(
            bytes(packet[Raw].load)
            for packet in sorted(
                (
                    p for p in self.packets
                    if p.haslayer(Raw) and p[IP].src == CLIENT_IP
                    and p[IP].dst == SERVER_IP and p[TCP].dport == 80
                ),
                key=lambda p: p[TCP].seq,
            )
        )
        self.assertEqual(rebuilt, self.requests)

    def test_no_flag_in_http_traffic(self):
        self.assertNotIn(FLAG.encode(), self.requests)
        self.assertNotIn(FLAG.encode(), self.responses)

    def test_background_http_conversation_exists(self):
        background = self.metadata["background_http"]
        self.assertIsNotNone(background)
        self.assertLess(background["first"], self.metadata["phases"]["ftp_control_start"])

    def test_http_precedes_ftp(self):
        phases = self.metadata["phases"]
        self.assertLess(phases["http_start"], phases["ftp_control_start"])

    def test_http_targets_the_resolved_address(self):
        for packet in self.packets:
            if not packet.haslayer(TCP) or not packet.haslayer(Raw):
                continue
            if packet[IP].dst == SERVER_IP and packet[TCP].dport == 80:
                self.assertEqual(packet[IP].dst, self.metadata["server_ip"])
                return
        self.fail("no HTTP traffic to the suspicious server")


if __name__ == "__main__":
    unittest.main(verbosity=2)
