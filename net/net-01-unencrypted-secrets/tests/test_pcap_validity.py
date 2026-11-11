"""Protocol-level validation of the generated capture for NET-01."""

import unittest

from support import (
    INTERNAL_DNS,
    PORTAL,
    REPORTING,
    TARGET_HEADER,
    TARGET_PATH,
    WORKSTATION_A,
    WORKSTATION_B,
    generate,
    http_payloads,
    reassemble,
    run,
    target_request,
    tcpdump_available,
)

FLAG = "GZCTF{NET01_TEST_FLAG}"


class ProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from scapy.all import rdpcap

        cls.path, process = generate(FLAG)
        if process.returncode != 0:
            raise RuntimeError(process.stderr)
        cls.packets = rdpcap(str(cls.path))

    def test_dns_query_and_response_exist(self):
        from scapy.all import DNS

        dns = [packet for packet in self.packets if packet.haslayer(DNS)]
        queries = [packet for packet in dns if packet[DNS].qr == 0]
        responses = [packet for packet in dns if packet[DNS].qr == 1]

        self.assertGreaterEqual(len(queries), 2)
        self.assertGreaterEqual(len(responses), 2)

        names = [packet[DNS].qd.qname.decode().rstrip(".") for packet in queries]
        self.assertIn("portal.meridian.internal", names)

        answers = {}
        for packet in responses:
            question = packet[DNS].qd.qname.decode().rstrip(".")
            answers[question] = packet[DNS].an.rdata if packet[DNS].an is not None else None
        self.assertEqual(str(answers.get("portal.meridian.internal")), PORTAL)

    def test_dns_traffic_uses_the_internal_resolver(self):
        from scapy.all import DNS, IP

        dns = [packet for packet in self.packets if packet.haslayer(DNS)]
        self.assertTrue(any(packet[IP].dst == INTERNAL_DNS for packet in dns))
        self.assertTrue(any(packet[IP].src == INTERNAL_DNS for packet in dns))

    def test_tcp_three_way_handshake_exists(self):
        from scapy.all import IP, TCP

        syn = [p for p in self.packets if p.haslayer(TCP) and p[TCP].flags == "S"]
        syn_ack = [p for p in self.packets if p.haslayer(TCP) and p[TCP].flags == "SA"]
        ack = [p for p in self.packets if p.haslayer(TCP) and p[TCP].flags == "A"]

        self.assertGreaterEqual(len(syn), 4)
        self.assertGreaterEqual(len(syn_ack), 4)
        self.assertGreaterEqual(len(ack), 4)

        portal_syn = [p for p in syn if p[IP].dst == PORTAL and p[TCP].dport == 80]
        self.assertTrue(portal_syn, "no handshake towards the portal on port 80")

        # The SYN/ACK must acknowledge the client's sequence number plus one.
        for packet in portal_syn:
            matching = [
                candidate
                for candidate in syn_ack
                if candidate[IP].src == PORTAL
                and candidate[TCP].sport == 80
                and candidate[TCP].dport == packet[TCP].sport
            ]
            self.assertTrue(matching)
            self.assertEqual(matching[0][TCP].ack, (packet[TCP].seq + 1) & 0xFFFFFFFF)

    def test_addresses_match_the_documented_topology(self):
        from scapy.all import IP

        hosts = {packet[IP].src for packet in self.packets if packet.haslayer(IP)}
        hosts |= {packet[IP].dst for packet in self.packets if packet.haslayer(IP)}

        expected = {PORTAL, REPORTING, WORKSTATION_A, WORKSTATION_B, INTERNAL_DNS}
        self.assertTrue(expected.issubset(hosts), f"missing hosts: {expected - hosts}")
        for host in hosts:
            self.assertTrue(host.startswith("192.168.10."), f"unexpected host {host}")

    def test_http_request_and_response_are_reconstructed(self):
        payloads = list(http_payloads(self.packets))
        requests = [data for _, data in payloads if data.startswith(b"GET ") or data.startswith(b"POST ")]
        responses = [data for _, data in payloads if data.startswith(b"HTTP/1.1 ")]

        self.assertGreaterEqual(len(requests), 5)
        self.assertGreaterEqual(len(responses), 5)

        joined = b"".join(requests)
        self.assertIn(b"GET / HTTP/1.1", joined)
        self.assertIn(b"Host: portal.meridian.internal", joined)

    def test_segmented_response_is_captured_as_multiple_segments(self):
        from scapy.all import IP, TCP, Raw

        segments = [
            packet
            for packet in self.packets
            if packet.haslayer(TCP)
            and packet.haslayer(Raw)
            and packet[IP].src == PORTAL
            and len(packet[Raw].load) == 1460
        ]
        self.assertTrue(segments, "no full-MSS response segment; payload was not segmented")

    def test_target_request_is_reconstructable(self):
        packet, data = target_request(self.packets)
        self.assertIsNotNone(packet, "target request not found")
        self.assertTrue(data.startswith(b"GET " + TARGET_PATH.encode() + b" HTTP/1.1\r\n"))
        self.assertIn(f"Host: portal.meridian.internal".encode(), data)
        self.assertIn(b"User-Agent: MeridianDesktop/2.4", data)

    def test_target_header_is_present_and_carries_the_flag(self):
        _, data = target_request(self.packets)
        request = data.decode("latin-1")
        self.assertIn(f"{TARGET_HEADER}: {FLAG}", request)
        self.assertIn("\r\n\r\n", request, "request is not terminated with a blank line")

    def test_follow_tcp_stream_reassembles_the_full_request(self):
        from scapy.all import IP, TCP

        packet, data = target_request(self.packets)
        stream = reassemble(
            self.packets,
            packet[IP].src,
            packet[IP].dst,
            packet[TCP].sport,
            packet[TCP].dport,
        )
        # A reassembled stream from sequence numbers must contain the contiguous
        # request, which is what Wireshark's Follow TCP Stream shows.
        self.assertEqual(stream, data)
        self.assertIn(f"{TARGET_HEADER}: {FLAG}".encode(), stream)

    def test_tcpdump_can_extract_the_header(self):
        if not tcpdump_available():
            self.skipTest("tcpdump is not available")
        result = run(["tcpdump", "-nn", "-A", "-r", str(self.path)])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"{TARGET_HEADER}: {FLAG}", result.stdout)

    def test_no_retransmissions_or_out_of_order_segments(self):
        if not tcpdump_available():
            self.skipTest("tcpdump is not available")
        result = run(["tcpdump", "-nn", "-r", str(self.path)])
        combined = result.stdout + result.stderr
        for marker in (
            "retransmission",
            "Previous segment not captured",
            "out-of-order",
            "BAD checksum",
            "packet exceeded",
        ):
            self.assertNotIn(marker, combined, f"tcpdump reported: {marker}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
