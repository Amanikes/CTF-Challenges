"""Flag exposure tests for NET-01 — the flag must appear exactly once."""

import unittest
from unittest import skipIf

from support import (
    TARGET_HEADER,
    TARGET_PATH,
    generate,
    http_payloads,
    target_request,
)

FLAG = "GZCTF{NET01_TEST_FLAG}"


class FlagExposureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from scapy.all import rdpcap

        cls.path, process = generate(FLAG)
        if process.returncode != 0:
            raise RuntimeError(process.stderr)
        cls.packets = rdpcap(str(cls.path))
        cls.flag_bytes = FLAG.encode()

    def carriers(self):
        return [packet for packet in self.packets if self.flag_bytes in bytes(packet)]

    def test_flag_appears_in_exactly_one_packet(self):
        carriers = self.carriers()
        self.assertEqual(len(carriers), 1, f"flag found in {len(carriers)} packets")

    def test_flag_only_in_the_target_request_packet(self):
        carrier = self.carriers()[0]
        _, data = target_request(self.packets)
        self.assertEqual(bytes(carrier), bytes(self.packets[[bytes(p) for p in self.packets].index(bytes(carrier))]))
        self.assertIn(TARGET_PATH.encode(), data)
        self.assertIn(self.flag_bytes, data)

    def test_flag_is_only_in_the_session_header_line(self):
        _, data = target_request(self.packets)
        request = data.decode("latin-1")
        lines = request.split("\r\n")

        self.assertTrue(lines[0].startswith(f"GET {TARGET_PATH} HTTP/1.1"))
        self.assertNotIn(FLAG, lines[0], "flag must not appear in the request line")

        carrying = [line for line in lines if FLAG in line]
        self.assertEqual(len(carrying), 1, f"flag appears in {len(carrying)} header lines")
        self.assertEqual(carrying[0], f"{TARGET_HEADER}: {FLAG}")

    def test_flag_absent_from_dns(self):
        from scapy.all import DNS

        for packet in self.packets:
            if packet.haslayer(DNS) and packet[DNS].qd is not None:
                self.assertNotIn(self.flag_bytes, packet[DNS].qd.qname)

    def test_flag_absent_from_urls(self):
        for _, data in http_payloads(self.packets):
            first_line = data.split(b"\r\n", 1)[0]
            self.assertNotIn(self.flag_bytes, first_line)

    def test_flag_absent_from_http_responses(self):
        for _, data in http_payloads(self.packets):
            if data.startswith(b"HTTP/1.1 "):
                self.assertNotIn(self.flag_bytes, data)

    def test_flag_absent_from_other_request_headers(self):
        for _, data in http_payloads(self.packets):
            if not data.startswith((b"GET ", b"POST ")):
                continue
            if TARGET_PATH.encode() in data:
                continue
            self.assertNotIn(self.flag_bytes, data)

    def test_raw_file_contains_the_flag_once(self):
        blob = self.path.read_bytes()
        # The flag is ASCII and appears verbatim only inside the target request.
        self.assertEqual(blob.count(self.flag_bytes), 1)

    def test_capture_header_is_not_used_to_store_the_flag(self):
        blob = self.path.read_bytes()
        self.assertNotIn(self.flag_bytes, blob[:24], "flag must not be in the PCAP global header")


if __name__ == "__main__":
    unittest.main(verbosity=2)
