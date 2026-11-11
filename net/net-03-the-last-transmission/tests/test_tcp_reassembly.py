"""TCP builder and reassembly tests for NET-03 — The Last Transmission."""

import unittest

import support  # noqa: F401 - adjusts sys.path

from scapy.all import IP, Raw, TCP

import timeline
from artifact import build_bundle
from tcp_builder import Capture, TCPFlow, reassemble
from topology import GATEWAY_MAC, SERVER_IP

FLAG = "GZCTF{NET03_TEST_FLAG}"

CLIENT_IP = "10.10.20.15"
CLIENT_MAC = "02:00:5e:0a:14:0f"


def make_flow(payload=b"", start=1.0, mss=1200, close=True):
    capture = Capture(1_700_000_000.0)
    flow = TCPFlow(
        capture,
        client_ip=CLIENT_IP,
        client_mac=CLIENT_MAC,
        server_ip=SERVER_IP,
        server_mac=GATEWAY_MAC,
        client_port=50000,
        server_port=9000,
        client_isn=1000,
        server_isn=500000,
        start=start,
        mss=mss,
    )
    flow.handshake()
    if payload:
        flow.receive(payload)
    if close:
        flow.close()
    return capture, flow


class TcpBuilderTests(unittest.TestCase):
    def test_three_way_handshake(self):
        capture, flow = make_flow()
        packets = capture.ordered()
        syn, synack, ack = packets[0], packets[1], packets[2]

        self.assertEqual(syn[TCP].flags, "S")
        self.assertEqual(syn[TCP].seq, 1000)
        self.assertEqual(synack[TCP].flags, "SA")
        self.assertEqual(synack[TCP].seq, 500000)
        self.assertEqual(synack[TCP].ack, 1001)
        self.assertEqual(ack[TCP].flags, "A")
        self.assertEqual(ack[TCP].seq, 1001)
        self.assertEqual(ack[TCP].ack, 500001)

    def test_sequence_numbers_advance_by_payload_length(self):
        payload = b"x" * 500
        capture, flow = make_flow(payload, close=False)
        segments = [
            packet for packet in capture.ordered()
            if packet.haslayer(Raw) and packet[TCP].sport == 9000
        ]
        self.assertEqual(len(segments), 1)
        self.assertEqual(segments[0][TCP].seq, 500001)
        self.assertEqual(flow.server_next, 500001 + len(payload))

    def test_segmentation_at_mss(self):
        payload = bytes(range(256)) * 12  # 3072 bytes
        capture, flow = make_flow(payload, mss=1200)
        segments = [
            packet for packet in capture.ordered()
            if packet.haslayer(Raw) and packet[TCP].sport == 9000
        ]
        self.assertEqual([len(bytes(p[Raw].load)) for p in segments], [1200, 1200, 672])

    def test_acknowledgements_follow_each_segment(self):
        payload = b"a" * 2500
        capture, _ = make_flow(payload, mss=1200)
        packets = capture.ordered()
        acks = [
            packet for packet in packets
            if packet.haslayer(TCP) and packet[TCP].flags == "A"
            and packet[TCP].dport == 9000
        ]
        self.assertGreaterEqual(len(acks), 2)

    def test_reassembly_preserves_binary_payload(self):
        payload = bytes(range(256)) * 12
        capture, flow = make_flow(payload, mss=1200)
        rebuilt = reassemble(
            capture.ordered(), src_ip=SERVER_IP, dst_ip=CLIENT_IP, sport=9000, dport=50000
        )
        self.assertEqual(rebuilt, payload)

    def test_binary_payload_is_not_text_converted(self):
        payload = bytes([0x00, 0xFF, 0x0D, 0x0A, 0x1A, 0x80])
        capture, _ = make_flow(payload)
        rebuilt = reassemble(
            capture.ordered(), src_ip=SERVER_IP, dst_ip=CLIENT_IP, sport=9000, dport=50000
        )
        self.assertEqual(rebuilt, payload)

    def test_fin_termination(self):
        capture, _ = make_flow()
        packets = capture.ordered()
        self.assertEqual(packets[-3][TCP].flags, "FA")
        self.assertEqual(packets[-2][TCP].flags, "FA")
        self.assertEqual(packets[-1][TCP].flags, "A")

    def test_no_overlapping_payloads(self):
        payload = bytes(range(200)) * 20
        capture, flow = make_flow(payload, mss=1200)
        seen = {}
        for packet in capture.ordered():
            if not packet.haslayer(Raw) or packet[TCP].sport != 9000:
                continue
            seq = packet[TCP].seq
            data = bytes(packet[Raw].load)
            self.assertNotIn(seq, seen, "duplicate sequence number")
            seen[seq] = data

            for other_seq, other_data in seen.items():
                if other_seq == seq:
                    continue
                start, end = seq, seq + len(data)
                other_start, other_end = other_seq, other_seq + len(other_data)
                if start < other_end and other_start < end:
                    self.fail("overlapping TCP payload segments")

    def test_independent_conversations_do_not_interfere(self):
        capture = Capture(1_700_000_000.0)
        first = TCPFlow(
            capture, client_ip=CLIENT_IP, client_mac=CLIENT_MAC, server_ip=SERVER_IP,
            server_mac=GATEWAY_MAC, client_port=40001, server_port=80,
            client_isn=1, server_isn=2, start=1.0,
        )
        second = TCPFlow(
            capture, client_ip=CLIENT_IP, client_mac=CLIENT_MAC, server_ip=SERVER_IP,
            server_mac=GATEWAY_MAC, client_port=40002, server_port=21,
            client_isn=900000, server_isn=800000, start=1.0,
        )
        first.handshake()
        second.handshake()

        first.send(b"GET / HTTP/1.1\r\n\r\n")
        greeting = b"220 ready\r\n"
        second.receive(greeting)

        self.assertEqual(first.client_next, 1 + 1 + len(b"GET / HTTP/1.1\r\n\r\n"))
        self.assertEqual(second.server_next, 800000 + 1 + len(greeting))

    def test_timestamps_are_monotonic_after_sorting(self):
        capture, _ = make_flow(b"z" * 3000)
        times = [float(packet.time) for packet in capture.ordered()]
        self.assertEqual(times, sorted(times))

    def test_real_capture_has_no_retransmissions(self):
        capture, metadata = timeline.build(FLAG, build_bundle(FLAG))
        packets = capture.ordered()

        seen = {}
        for packet in packets:
            if not packet.haslayer(TCP) or not packet.haslayer(Raw):
                continue
            key = (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport)
            seq = packet[TCP].seq
            self.assertNotIn((key, seq), seen, f"duplicate segment on {key}")
            seen[(key, seq)] = True


if __name__ == "__main__":
    unittest.main(verbosity=2)
