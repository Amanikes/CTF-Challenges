"""Incident timeline for NET-03 — The Last Transmission.

Coordinates the three protocol stages plus background noise on one coherent
clock. Packets are held with absolute offsets and sorted when written, so
background traffic interleaves chronologically instead of forming blocks.

00:00  ordinary DNS activity
00:08  suspicious lookup of files-update.example.test
00:09  resolver answers 192.0.2.80
00:15  HTTP connection to the resolved address begins
00:17  /api/transfer/status reveals AX-7842 and confidential_bundle.zip
00:25  FTP control connection begins
00:28  authentication
00:32  passive-mode negotiation (port 50000)
00:35  RETR confidential_bundle.zip
00:36  FTP data connection carries the archive
00:38  transfer complete
00:42  FTP session closes
"""

from scapy.all import ARP, Ether, IP, Raw, UDP

import dns_traffic
import ftp_traffic
import http_traffic
from tcp_builder import Capture, TCPFlow
from topology import (
    BASE_TIME,
    CLIENT_IP,
    CLIENT_MAC,
    DNS_IP,
    DNS_MAC,
    GATEWAY_MAC,
    SERVER_IP,
)

# Values used by the module-level validation and by the tests.
SUSPICIOUS_DNS_AT = dns_traffic.SUSPICIOUS_QUERY_AT
HTTP_START = http_traffic.SUSPICIOUS_START
FTP_START = ftp_traffic.CONTROL_START


def _background_arp(capture):
    request = Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc=CLIENT_MAC, psrc=CLIENT_IP, pdst=DNS_IP
    )
    capture.add(request, 12.020)

    reply = Ether(src=DNS_MAC, dst=CLIENT_MAC) / ARP(
        op=2, hwsrc=DNS_MAC, psrc=DNS_IP, hwdst=CLIENT_MAC, pdst=CLIENT_IP
    )
    capture.add(reply, 12.023)


def _background_https_attempt(capture, server_ip="20.190.151.7"):
    """A TLS connection that is reset before any application data."""
    flow = TCPFlow(
        capture,
        client_ip=CLIENT_IP,
        client_mac=CLIENT_MAC,
        server_ip=server_ip,
        server_mac=GATEWAY_MAC,
        client_port=49604,
        server_port=443,
        client_isn=0x1F2E3D4C,
        server_isn=0x5A6B7C8D,
        start=10.550,
    )
    flow.handshake()
    flow.idle(0.140)
    flow.close()
    return flow


def _background_ntp(capture, server_ip="10.10.20.1"):
    request = (
        Ether(src=CLIENT_MAC, dst=DNS_MAC)
        / IP(src=CLIENT_IP, dst=server_ip, ttl=64)
        / UDP(sport=123, dport=123)
        / Raw(load=b"\x1b" + b"\x00" * 47)
    )
    capture.add(request, 40.100)

    reply = (
        Ether(src=DNS_MAC, dst=CLIENT_MAC)
        / IP(src=server_ip, dst=CLIENT_IP, ttl=64)
        / UDP(sport=123, dport=123)
        / Raw(load=b"\x1c" + b"\x00" * 47)
    )
    capture.add(reply, 40.118)


def build(flag, archive_bytes, seed=0):
    """Assemble the complete capture and return it with timing metadata."""
    capture = Capture(BASE_TIME)

    dns = dns_traffic.build_dns(capture, seed=seed)
    _background_https_attempt(capture)
    _background_arp(capture)

    http = http_traffic.build_suspicious_conversation(capture, archive_bytes)
    background_http = http_traffic.build_background_conversation(capture)

    ftp = ftp_traffic.build_ftp(capture, archive_bytes)

    _background_ntp(capture)

    metadata = {
        "dns": dns,
        "http": http,
        "background_http": background_http,
        "ftp": ftp,
        "phases": {
            "dns_query": dns_traffic.SUSPICIOUS_QUERY_AT,
            "dns_response": dns_traffic.SUSPICIOUS_RESPONSE_AT,
            "http_start": http["first"],
            "ftp_control_start": ftp["first"],
            "ftp_data_start": ftp["data_first"],
            "ftp_end": ftp["last"],
        },
        "server_ip": SERVER_IP,
        "archive_bytes": len(archive_bytes),
    }

    return capture, metadata
