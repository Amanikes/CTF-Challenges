"""FTP stage tests for NET-03 — The Last Transmission."""

import io
import unittest
import zipfile

import support  # noqa: F401 - adjusts sys.path

from scapy.all import IP, Raw, TCP

import generate_capture
import timeline
from artifact import EVIDENCE_PATH, build_bundle
from topology import CLIENT_IP, FTP_CONTROL_PORT, FTP_DATA_PORT, SERVER_IP

FLAG = "GZCTF{NET03_TEST_FLAG}"


class FtpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.archive = build_bundle(FLAG)
        cls.capture, cls.metadata = timeline.build(FLAG, cls.archive)
        cls.packets = cls.capture.ordered()
        cls.commands, cls.replies = generate_capture.recover_ftp_control(cls.packets)
        cls.payload = generate_capture.recover_ftp_payload(cls.packets)

    def test_control_uses_port_21(self):
        for packet in self.packets:
            if not packet.haslayer(TCP):
                continue
            if packet[TCP].dport == FTP_CONTROL_PORT or packet[TCP].sport == FTP_CONTROL_PORT:
                self.assertEqual(packet[IP].dst, SERVER_IP) if packet[TCP].dport == 21 else None
                return
        self.fail("no FTP control traffic")

    def test_greeting_and_login_sequence(self):
        transcript = self.replies.decode()
        self.assertIn("220 Asterion Transfer Service ready", transcript)
        self.assertIn("331 Password required for evidence", transcript)
        self.assertIn("230 Login successful.", transcript)

        commands = self.commands.decode()
        self.assertIn("USER evidence", commands)
        self.assertIn("PASS archive-access", commands)

    def test_login_order_is_correct(self):
        commands = self.commands.decode()
        self.assertLess(commands.index("USER "), commands.index("PASS "))
        replies = self.replies.decode()
        self.assertLess(replies.index("331 "), replies.index("230 "))

    def test_pasv_reply_encodes_port_50000(self):
        self.assertIn("227 Entering Passive Mode (192,0,2,80,195,80)", self.replies.decode())
        self.assertEqual(195 * 256 + 80, FTP_DATA_PORT)

    def test_pasv_precedes_retr(self):
        commands = self.commands.decode()
        self.assertLess(commands.index("PASV"), commands.index("RETR "))

    def test_retr_names_the_archive(self):
        self.assertIn("RETR confidential_bundle.zip", self.commands.decode())

    def test_opening_and_completion_replies(self):
        replies = self.replies.decode()
        self.assertIn("150 Opening BINARY mode data connection", replies)
        self.assertIn("226 Transfer complete.", replies)

    def test_data_connection_is_separate_from_control(self):
        data_ports = {
            packet[TCP].dport
            for packet in self.packets
            if packet.haslayer(TCP) and packet[TCP].dport == FTP_DATA_PORT
        }
        self.assertEqual(data_ports, {FTP_DATA_PORT})
        self.assertNotEqual(FTP_DATA_PORT, FTP_CONTROL_PORT)

    def test_data_connection_initiated_by_client(self):
        syn = [
            packet
            for packet in self.packets
            if packet.haslayer(TCP)
            and packet[TCP].flags == "S"
            and packet[TCP].dport == FTP_DATA_PORT
        ]
        self.assertEqual(len(syn), 1)
        self.assertEqual(syn[0][IP].src, CLIENT_IP)

    def test_data_payload_direction(self):
        from_client = generate_capture._payloads(
            self.packets, src=CLIENT_IP, dport=FTP_DATA_PORT
        )
        self.assertEqual(list(from_client), [], "client must not send payload on the data connection")

        from_server = list(generate_capture._payloads(self.packets, sport=FTP_DATA_PORT))
        self.assertTrue(from_server, "server sends no data payload")

    def test_payload_equals_the_archive(self):
        self.assertEqual(self.payload, self.archive)

    def test_payload_is_binary_zip(self):
        self.assertTrue(self.payload.startswith(b"PK\x03\x04"))

    def test_payload_is_segmented(self):
        segments = [
            packet
            for packet in self.packets
            if packet.haslayer(TCP) and packet.haslayer(Raw) and packet[TCP].sport == FTP_DATA_PORT
        ]
        self.assertGreaterEqual(len(segments), 2, "archive was not segmented")
        for packet in segments:
            self.assertLessEqual(len(bytes(packet[Raw].load)), 1200)

    def test_archive_extracts_to_the_flag(self):
        with zipfile.ZipFile(io.BytesIO(self.payload)) as archive:
            self.assertIsNone(archive.testzip())
            self.assertEqual(archive.namelist(), [EVIDENCE_PATH])
            report = archive.read(EVIDENCE_PATH).decode("utf-8")
        self.assertIn(FLAG, report)

    def test_no_flag_in_control_messages(self):
        self.assertNotIn(FLAG.encode(), self.commands)
        self.assertNotIn(FLAG.encode(), self.replies)

    def test_data_connection_timing(self):
        phases = self.metadata["phases"]
        self.assertLess(phases["ftp_control_start"], phases["ftp_data_start"])
        self.assertLess(phases["ftp_data_start"], phases["ftp_end"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
