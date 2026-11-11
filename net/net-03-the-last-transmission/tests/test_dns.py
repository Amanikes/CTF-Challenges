"""DNS stage tests for NET-03 — The Last Transmission."""

import unittest

import support  # noqa: F401 - adjusts sys.path

from scapy.all import DNS, IP, UDP

import dns_traffic
import timeline
from artifact import build_bundle
from topology import SERVER_HOSTNAME, SERVER_IP

FLAG = "GZCTF{NET03_TEST_FLAG}"


class DnsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture, cls.metadata = timeline.build(FLAG, build_bundle(FLAG))
        cls.dns = [p for p in cls.capture.frames if p.haslayer(DNS)]

    def test_dns_layers(self):
        for packet in self.dns:
            self.assertTrue(packet.haslayer(IP))
            self.assertTrue(packet.haslayer(UDP))

    def test_queries_use_port_53(self):
        for packet in self.dns:
            if packet[DNS].qr == 0:
                self.assertEqual(packet[UDP].dport, 53)
                self.assertGreater(packet[UDP].sport, 1023)

    def test_responses_come_from_port_53(self):
        for packet in self.dns:
            if packet[DNS].qr == 1:
                self.assertEqual(packet[UDP].sport, 53)

    def test_suspicious_query_exists(self):
        names = [
            packet[DNS].qd.qname.decode().rstrip(".")
            for packet in self.dns
            if packet[DNS].qr == 0 and packet[DNS].qd is not None
        ]
        self.assertIn(SERVER_HOSTNAME, names)

    def test_suspicious_response_resolves_the_server(self):
        answers = []
        for packet in self.dns:
            if packet[DNS].qr != 1 or packet[DNS].qd is None:
                continue
            if packet[DNS].qd.qname.decode().rstrip(".") != SERVER_HOSTNAME:
                continue
            for record in packet[DNS].an:
                answers.append(str(record.rdata))
        self.assertEqual(answers, [SERVER_IP])

    def test_authoritative_flags_on_response(self):
        for packet in self.dns:
            if packet[DNS].qr == 1:
                self.assertEqual(packet[DNS].aa, 1)
                self.assertEqual(packet[DNS].rd, 1)

    def test_recursion_desired_on_query(self):
        for packet in self.dns:
            if packet[DNS].qr == 0:
                self.assertEqual(packet[DNS].rd, 1)

    def test_background_traffic_present(self):
        self.assertGreaterEqual(len(self.dns), 30)
        names = {
            packet[DNS].qd.qname.decode().rstrip(".")
            for packet in self.dns
            if packet[DNS].qd is not None
        }
        self.assertIn("portal.asterion.internal", names)
        self.assertIn("mail.asterion.internal", names)

    def test_a_and_aaaa_lookups_both_present(self):
        types = {packet[DNS].qd.qtype for packet in self.dns if packet[DNS].qr == 0}
        self.assertIn(1, types, "no A lookups")
        self.assertIn(28, types, "no AAAA lookups")

    def test_transaction_ids_are_valid(self):
        for packet in self.dns:
            self.assertTrue(0 <= packet[DNS].id <= 0xFFFF)

    def test_no_flag_in_dns_names(self):
        for packet in self.dns:
            if packet[DNS].qd is not None:
                self.assertNotIn(FLAG, packet[DNS].qd.qname.decode())

    def test_suspicious_lookup_precedes_http(self):
        phases = self.metadata["phases"]
        self.assertLess(phases["dns_query"], phases["http_start"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
