"""Capture generation and PCAP structure tests for NET-02 — Lost in DNS."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from scapy.all import DNS, Ether, IP, UDP, rdpcap  # noqa: E402

import generate_capture  # noqa: E402
from dns_traffic import CLIENT_IP, RESOLVER_IP, NORMAL_QUERIES  # noqa: E402
from encoding import SUSPICIOUS_SUFFIX, decode_names, query_names  # noqa: E402

FLAG = "GZCTF{NET02_TEST_FLAG}"


class CaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.mkdtemp(prefix="net02-capture-")
        cls.path = Path(cls.directory) / "capture.pcap"
        cls.summary = generate_capture.generate(FLAG, str(cls.path))
        cls.packets = rdpcap(str(cls.path))

    def queries(self):
        return [
            packet
            for packet in self.packets
            if packet.haslayer(DNS) and packet[DNS].qr == 0 and packet[DNS].qd is not None
        ]

    def responses(self):
        return [packet for packet in self.packets if packet.haslayer(DNS) and packet[DNS].qr == 1]

    def query_names(self):
        return [packet[DNS].qd.qname.decode().rstrip(".") for packet in self.queries()]

    def test_capture_is_written_and_readable(self):
        self.assertTrue(os.path.exists(self.path))
        self.assertGreater(len(self.packets), 40)
        self.assertIn(self.path.read_bytes()[:4], (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"))

    def test_layer_structure(self):
        for packet in self.packets:
            self.assertTrue(packet.haslayer(Ether), "missing Ethernet layer")
            self.assertTrue(packet.haslayer(IP), "missing IPv4 layer")
            self.assertTrue(packet.haslayer(UDP), "missing UDP layer")
            self.assertTrue(packet.haslayer(DNS), "missing DNS layer")

    def test_dns_destination_port(self):
        for packet in self.queries():
            self.assertEqual(packet[UDP].dport, 53)
            self.assertNotEqual(packet[UDP].sport, 53)

    def test_client_and_resolver_addresses(self):
        sources = {packet[IP].src for packet in self.packets}
        destinations = {packet[IP].dst for packet in self.packets}
        self.assertIn(CLIENT_IP, sources)
        self.assertIn(RESOLVER_IP, destinations)

    def test_normal_traffic_volume(self):
        normal = [name for name in self.query_names() if not name.endswith(SUSPICIOUS_SUFFIX)]
        self.assertGreaterEqual(len(normal), 25)
        self.assertLessEqual(len(normal), 35)

    def test_mixed_query_types(self):
        types = {packet[DNS].qd.qtype for packet in self.queries()}
        self.assertIn(1, types, "no A queries")
        self.assertIn(28, types, "no AAAA queries")

    def test_suspicious_fragment_count_and_order(self):
        suspicious = [name for name in self.query_names() if name.endswith(SUSPICIOUS_SUFFIX)]
        expected = query_names(FLAG, SUSPICIOUS_SUFFIX)
        self.assertEqual(suspicious, expected)

    def test_suspicious_queries_are_txt_type(self):
        for packet in self.queries():
            name = packet[DNS].qd.qname.decode().rstrip(".")
            if name.endswith(SUSPICIOUS_SUFFIX):
                self.assertEqual(packet[DNS].qd.qtype, 16)

    def test_reconstruction_matches_the_flag(self):
        suspicious = [name for name in self.query_names() if name.endswith(SUSPICIOUS_SUFFIX)]
        self.assertEqual(decode_names(suspicious), FLAG)

    def test_no_plaintext_flag_in_capture(self):
        blob = self.path.read_bytes()
        self.assertNotIn(FLAG.encode(), blob)
        for name in self.query_names():
            self.assertNotIn(FLAG, name)

    def test_interleaving(self):
        names = self.query_names()
        positions = [
            index
            for index, name in enumerate(names)
            if name.endswith(SUSPICIOUS_SUFFIX)
        ]
        self.assertGreater(len(positions), 1)
        for first, second in zip(positions, positions[1:]):
            self.assertGreater(second - first, 1, "suspicious queries are not interleaved")

    def test_responses_are_present_for_most_queries(self):
        self.assertGreaterEqual(len(self.responses()), int(len(self.queries()) * 0.7))

    def test_transaction_ids_are_valid(self):
        for packet in self.queries():
            self.assertTrue(0 <= packet[DNS].id <= 0xFFFF)

    def test_timestamps_are_monotonic(self):
        times = [float(packet.time) for packet in self.packets]
        self.assertEqual(times, sorted(times))

    def test_ephemeral_source_ports(self):
        for packet in self.queries():
            self.assertGreaterEqual(packet[UDP].sport, 1024)

    def test_size_is_reasonable(self):
        size = os.path.getsize(self.path)
        self.assertGreaterEqual(size, generate_capture.MIN_SIZE)
        self.assertLessEqual(size, generate_capture.MAX_SIZE)

    def test_normal_query_catalogue_is_plausible(self):
        self.assertGreaterEqual(len(NORMAL_QUERIES), 25)
        self.assertLessEqual(len(NORMAL_QUERIES), 35)

    def test_validation_rejects_a_wrong_flag(self):
        with self.assertRaises(generate_capture.CaptureError):
            generate_capture.validate_capture(str(self.path), "GZCTF{something_else}")

    def test_atomic_publish_leaves_no_temporary_files(self):
        leftovers = [name for name in os.listdir(self.directory) if name.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_missing_flag_cannot_generate(self):
        with self.assertRaises(generate_capture.CaptureError):
            generate_capture.generate("", os.path.join(self.directory, "other.pcap"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
