"""PCAP generation and end-to-end acceptance tests for NET-03.

The acceptance test deliberately ignores the in-memory archive: it generates the
capture, re-reads it, rebuilds the ZIP from the FTP data connection's TCP
payload and extracts the flag from the evidence file.
"""

import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

import support  # noqa: F401 - adjusts sys.path

from scapy.all import DNS, Ether, IP, TCP, UDP, rdpcap

import artifact
import generate_capture
from artifact import ARCHIVE_NAME, EVIDENCE_PATH
from topology import CLIENT_IP, FTP_DATA_PORT, INCIDENT_REFERENCE, SERVER_HOSTNAME, SERVER_IP

FLAG = "GZCTF{NET03_TEST_FLAG}"


class CaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.mkdtemp(prefix="net03-capture-")
        cls.path = Path(cls.directory) / "capture.pcap"
        cls.summary = generate_capture.generate(FLAG, str(cls.path))
        cls.packets = rdpcap(str(cls.path))

    def test_capture_written_and_readable(self):
        self.assertTrue(self.path.exists())
        self.assertIn(self.path.read_bytes()[:4], (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"))
        self.assertGreater(len(self.packets), 60)

    def test_packet_layers(self):
        for packet in self.packets:
            self.assertTrue(packet.haslayer(Ether))
            if packet.haslayer("ARP"):
                continue
            self.assertTrue(packet.haslayer(IP))
            self.assertTrue(packet.haslayer(TCP) or packet.haslayer(UDP))

    def test_dns_precedes_http(self):
        self.assertLess(self.summary["phases"]["dns_response"], self.summary["phases"]["http_start"])

    def test_http_precedes_ftp(self):
        phases = self.summary["phases"]
        self.assertLess(phases["http_start"], phases["ftp_control_start"])

    def test_ftp_control_precedes_data(self):
        phases = self.summary["phases"]
        self.assertLess(phases["ftp_control_start"], phases["ftp_data_start"])
        self.assertLess(phases["ftp_data_start"], phases["ftp_end"])

    def test_background_traffic_is_interleaved(self):
        from generate_capture import _payloads

        critical_ports = set()
        for packet in self.packets:
            if packet.haslayer(TCP) and (
                packet[IP].src == SERVER_IP or packet[IP].dst == SERVER_IP
            ):
                critical_ports.add(packet[TCP].sport)
                critical_ports.add(packet[TCP].dport)

        unrelated = [
            float(packet.time)
            for packet in self.packets
            if not (
                packet.haslayer(TCP)
                and packet[TCP].sport in critical_ports
                and packet[TCP].dport in critical_ports
            )
        ]
        self.assertTrue(unrelated, "no unrelated traffic at all")
        http_times = [
            float(packet.time)
            for packet, _ in _payloads(self.packets, dst=SERVER_IP, dport=80)
        ]
        self.assertTrue(any(moment < min(http_times) for moment in unrelated))
        self.assertTrue(any(moment > max(http_times) for moment in unrelated))

    def test_all_tcp_conversations_have_a_handshake(self):
        triples = {}
        for packet in self.packets:
            if not packet.haslayer(TCP):
                continue
            key = (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport)
            triples.setdefault(key, set()).add(str(packet[TCP].flags))

        payload_flows = {
            (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport)
            for packet in self.packets
            if packet.haslayer(TCP) and packet.haslayer("Raw")
        }
        for flow in payload_flows:
            reverse = (flow[2], flow[3], flow[0], flow[1])
            flags = triples.get(flow, set()) | triples.get(reverse, set())
            self.assertIn("S", flags, f"flow {flow} has no SYN")
            self.assertIn("SA", flags, f"flow {flow} has no SYN/ACK")

    def test_size_is_reasonable(self):
        size = os.path.getsize(self.path)
        self.assertGreaterEqual(size, 8 * 1024)
        self.assertLessEqual(size, 4 * 1024 * 1024)

    def test_no_temporary_file_left_behind(self):
        leftovers = [name for name in os.listdir(self.directory) if name.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_validation_rejects_wrong_archive(self):
        with self.assertRaises(generate_capture.CaptureError):
            generate_capture.validate_capture(str(self.path), FLAG, b"PK\x03\x04not-the-archive")

    def test_generation_is_deterministic_for_the_same_flag(self):
        other = Path(tempfile.mkdtemp(prefix="net03-repeat-")) / "capture.pcap"
        generate_capture.generate(FLAG, str(other))
        self.assertEqual(self.path.read_bytes(), other.read_bytes())

    def test_second_flag_produces_a_different_capture(self):
        other = Path(tempfile.mkdtemp(prefix="net03-other-")) / "capture.pcap"
        generate_capture.generate("GZCTF{a_different_team_flag}", str(other))
        self.assertNotEqual(self.path.read_bytes(), other.read_bytes())

    def test_no_flag_in_dns_http_or_control(self):
        commands, replies = generate_capture.recover_ftp_control(self.packets)
        requests, responses = generate_capture.recover_http_stream(self.packets)

        self.assertNotIn(FLAG.encode(), commands + replies)
        self.assertNotIn(FLAG.encode(), requests + responses)

        for packet in self.packets:
            if packet.haslayer(DNS) and packet[DNS].qd is not None:
                self.assertNotIn(FLAG, packet[DNS].qd.qname.decode())


class EndToEndAcceptanceTests(unittest.TestCase):
    """Mandatory acceptance test: recover the archive from the capture only."""

    @classmethod
    def setUpClass(cls):
        cls.flag = "GZCTF{NET03_ACCEPTANCE_FLAG}"
        cls.directory = tempfile.mkdtemp(prefix="net03-acceptance-")
        cls.path = Path(cls.directory) / "capture.pcap"
        generate_capture.generate(cls.flag, str(cls.path))

    def test_recover_archive_and_flag_from_the_capture(self):
        packets = rdpcap(str(self.path))

        # 1. Identify the FTP passive data connection: server -> client on 50000.
        data_segments = [
            packet
            for packet in packets
            if packet.haslayer(TCP)
            and packet.haslayer("Raw")
            and packet[TCP].sport == FTP_DATA_PORT
        ]
        self.assertTrue(data_segments, "FTP data connection not found in the capture")

        # 2. Reassemble by sequence number, exactly as Wireshark would.
        ordered = sorted(data_segments, key=lambda packet: packet[TCP].seq)
        payload = b"".join(bytes(packet[TCP].payload) for packet in ordered)

        # 3. The payload must be the transferred ZIP.
        self.assertTrue(payload.startswith(b"PK\x03\x04"))
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            self.assertIsNone(archive.testzip())
            self.assertEqual(archive.namelist(), [EVIDENCE_PATH])

            # 4. Read the evidence file and recover the flag.
            report = archive.read(EVIDENCE_PATH).decode("utf-8")

        self.assertIn(INCIDENT_REFERENCE, report)
        self.assertIn("AXUM-INCIDENT-03", report)
        self.assertIn(self.flag, report)

        # 5. The recovered value is the injected flag.
        recovered = [
            line.strip()
            for line in report.splitlines()
            if line.strip().startswith("GZCTF{")
        ]
        self.assertEqual(recovered, [self.flag])

    def test_payload_matches_the_generated_archive(self):
        packets = rdpcap(str(self.path))
        payload = generate_capture.recover_ftp_payload(packets)
        self.assertEqual(payload, artifact.build_bundle(self.flag))

    def test_correlation_evidence_is_reachable(self):
        packets = rdpcap(str(self.path))

        hostnames = {
            packet[DNS].qd.qname.decode().rstrip(".")
            for packet in packets
            if packet.haslayer(DNS) and packet[DNS].qd is not None
        }
        self.assertIn(SERVER_HOSTNAME, hostnames)

        commands, replies = generate_capture.recover_ftp_control(packets)
        self.assertIn(ARCHIVE_NAME.encode(), commands)
        self.assertIn(ARCHIVE_NAME.encode(), replies)

        requests, responses = generate_capture.recover_http_stream(packets)
        self.assertIn(INCIDENT_REFERENCE.encode(), responses)

    def test_data_connection_targets_the_resolved_address(self):
        packets = rdpcap(str(self.path))
        syns = [
            packet
            for packet in packets
            if packet.haslayer(TCP)
            and packet[TCP].flags == "S"
            and packet[TCP].dport == FTP_DATA_PORT
        ]
        self.assertEqual(len(syns), 1)
        self.assertEqual(syns[0][IP].src, CLIENT_IP)
        self.assertEqual(syns[0][IP].dst, SERVER_IP)


if __name__ == "__main__":
    unittest.main(verbosity=2)
