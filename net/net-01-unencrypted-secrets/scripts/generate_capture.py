#!/usr/bin/env python3
"""Meridian Logistics — synthetic traffic capture generator (NET-01).

Builds a realistic, fully synthetic PCAP in memory and writes it to disk. No
packet is ever transmitted: Scapy only serialises layers, so no raw sockets,
NET_RAW/NET_ADMIN or host networking are involved.

The per-team GZCTF_FLAG is placed in exactly one place: the value of the
``X-Meridian-Session`` header in the target request. The resulting capture is
validated before the function returns, and the process exits non-zero if any
check fails.

Usage:
    GZCTF_FLAG=... python3 generate_capture.py --output meridian-traffic.pcap
"""

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timezone

from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    DNSRR,
    Ether,
    IP,
    Raw,
    TCP,
    UDP,
    rdpcap,
    wrpcap,
)

# --- Synthetic topology (RFC 5737-style documentation-free private range) -----

PORTAL = "192.168.10.10"
REPORTING = "192.168.10.20"
WORKSTATION_A = "192.168.10.25"
WORKSTATION_B = "192.168.10.30"
INTERNAL_DNS = "192.168.10.53"
BROADCAST = "192.168.10.255"

PORTAL_HOST = "portal.meridian.internal"
UPDATES_HOST = "updates.meridian.internal"
REPORTING_HOST = "reporting.meridian.internal"
CDN_HOST = "cdn.meridian.internal"

MAC = {
    PORTAL: "02:00:5e:10:0a:0a",
    REPORTING: "02:00:5e:10:0a:14",
    WORKSTATION_A: "02:00:5e:10:0a:19",
    WORKSTATION_B: "02:00:5e:10:0a:1e",
    INTERNAL_DNS: "02:00:5e:10:0a:35",
}
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

BASE_TIME = datetime(2026, 10, 28, 9, 14, 2, tzinfo=timezone.utc).timestamp()
HTTP_DATE = "Wed, 28 Oct 2026 09:14:02 GMT"

MAX_FLAG_BYTES = 200
MSS = 1460
TARGET_HEADER = "X-Meridian-Session"
TARGET_PATH = "/internal/api/session"
MIN_SIZE, MAX_SIZE = 8 * 1024, 4 * 1024 * 1024

SENSITIVE = bytes(f"{TARGET_HEADER}:".encode())


class GenerationError(Exception):
    pass


# --- packet helpers ----------------------------------------------------------

class Capture:
    """Accumulates frames with controlled timestamps."""

    def __init__(self):
        self.frames = []
        self.clock = 0.0

    def advance(self, seconds):
        self.clock += seconds

    def add(self, packet, at=None):
        packet.time = BASE_TIME + (self.clock if at is None else at)
        self.frames.append(packet)
        return packet

    def write(self, path):
        ordered = sorted(self.frames, key=lambda frame: frame.time)
        handle, temporary = tempfile.mkstemp(suffix=".pcap", dir=os.path.dirname(os.path.abspath(path)) or ".")
        os.close(handle)
        try:
            wrpcap(temporary, ordered)
            os.chmod(temporary, 0o644)
            os.replace(temporary, path)
            os.chmod(path, 0o644)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def frame(src, dst, payload, flags, seq, ack, sport, dport, window=64240):
    return (
        Ether(src=MAC[src], dst=MAC[dst])
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=window)
        / payload
    )


class Conversation:
    """A single TCP conversation with correct sequence/acknowledgement numbers."""

    def __init__(self, capture, client, server, client_port, server_port, client_isn, server_isn):
        self.capture = capture
        self.client = client
        self.server = server
        self.client_port = client_port
        self.server_port = server_port
        self.client_next = client_isn + 1
        self.server_next = server_isn + 1

    def open(self):
        self.capture.add(frame(self.client, self.server, "", "S", self.client_next - 1, 0,
                              self.client_port, self.server_port, 64240))
        self.capture.advance(0.011)
        self.capture.add(frame(self.server, self.client, "", "SA", self.server_next - 1, self.client_next,
                              self.server_port, self.client_port, 65160))
        self.capture.advance(0.001)
        self.capture.add(frame(self.client, self.server, "", "A", self.client_next, self.server_next,
                              self.client_port, self.server_port))

    def send(self, payload, label=""):
        data = payload if isinstance(payload, bytes) else payload.encode()
        offset = 0

        while offset < len(data):
            chunk = data[offset:offset + MSS]
            self.capture.advance(0.002)
            self.capture.add(frame(self.client, self.server, Raw(load=chunk), "PA",
                                  self.client_next, self.server_next,
                                  self.client_port, self.server_port))
            self.client_next += len(chunk)
            offset += len(chunk)

            self.capture.advance(0.001)
            self.capture.add(frame(self.server, self.client, "", "A",
                                  self.server_next, self.client_next,
                                  self.server_port, self.client_port))

    def receive(self, payload):
        data = payload if isinstance(payload, bytes) else payload.encode()
        offset = 0

        while offset < len(data):
            chunk = data[offset:offset + MSS]
            self.capture.advance(0.003)
            self.capture.add(frame(self.server, self.client, Raw(load=chunk), "PA",
                                  self.server_next, self.client_next,
                                  self.server_port, self.client_port))
            self.server_next += len(chunk)
            offset += len(chunk)

            self.capture.advance(0.001)
            self.capture.add(frame(self.client, self.server, "", "A",
                                  self.client_next, self.server_next,
                                  self.client_port, self.server_port))

    def close(self):
        self.capture.advance(0.004)
        self.capture.add(frame(self.client, self.server, "", "FA",
                              self.client_next, self.server_next,
                              self.client_port, self.server_port))
        self.client_next += 1

        self.capture.advance(0.002)
        self.capture.add(frame(self.server, self.client, "", "FA",
                              self.server_next, self.client_next,
                              self.server_port, self.client_port))
        self.server_next += 1

        self.capture.advance(0.001)
        self.capture.add(frame(self.client, self.server, "", "A",
                              self.client_next, self.server_next,
                              self.client_port, self.server_port))


def dns_exchange(capture, client, client_port, query_id, host, answer):
    query = (
        Ether(src=MAC[client], dst=MAC[INTERNAL_DNS])
        / IP(src=client, dst=INTERNAL_DNS)
        / UDP(sport=client_port, dport=53)
        / DNS(id=query_id, rd=1, qd=DNSQR(qname=host, qtype="A", qclass="IN"))
    )
    capture.add(query)
    capture.advance(0.008)

    response = (
        Ether(src=MAC[INTERNAL_DNS], dst=MAC[client])
        / IP(src=INTERNAL_DNS, dst=client)
        / UDP(sport=53, dport=client_port)
        / DNS(
            id=query_id,
            qr=1,
            aa=1,
            rd=1,
            ra=1,
            qd=DNSQR(qname=host, qtype="A", qclass="IN"),
            an=DNSRR(rrname=host, type="A", ttl=300, rdata=answer),
        )
    )
    capture.add(response)
    capture.advance(0.004)


def http_response(status, body, content_type="application/json; charset=utf-8"):
    payload = body if isinstance(body, bytes) else body.encode()
    head = (
        f"HTTP/1.1 {status}\r\n"
        f"Date: {HTTP_DATE}\r\n"
        "Server: Meridian-Portal/2.4\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(payload)}\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    ).encode()
    return head + payload


def session_request(flag):
    """The target request. The flag appears only in the X-Meridian-Session header."""
    return (
        f"GET {TARGET_PATH} HTTP/1.1\r\n"
        f"Host: {PORTAL_HOST}\r\n"
        "User-Agent: MeridianDesktop/2.4 (Windows 11; x64)\r\n"
        "Accept: application/json\r\n"
        f"{TARGET_HEADER}: {flag}\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    ).encode()


# --- capture construction ----------------------------------------------------

SHIPMENTS = [
    {"id": f"MRD-2026-{1000 + index}", "customer": customer, "origin": origin,
     "destination": destination, "status": status, "eta": eta}
    for index, (customer, origin, destination, status, eta) in enumerate(
        [
            ("Halden Manufacturing", "Rotterdam", "Leeds", "in_transit", "2026-10-29T11:20:00Z"),
            ("Brightwater Foods", "Gdansk", "Manchester", "delivered", "2026-10-28T08:05:00Z"),
            ("Corvus Medical", "Lyon", "Dublin", "in_transit", "2026-10-30T16:45:00Z"),
            ("Nordkap Energy", "Gothenburg", "Aberdeen", "delayed", "2026-11-01T09:00:00Z"),
            ("Tessier Retail", "Lille", "Southampton", "in_transit", "2026-10-29T18:30:00Z"),
            ("Ostrava Tooling", "Ostrava", "Birmingham", "pending", "2026-11-02T07:15:00Z"),
            ("Marlow Chemicals", "Antwerp", "Hull", "in_transit", "2026-10-31T13:40:00Z"),
            ("Sundby Marine", "Bergen", "Newcastle", "delivered", "2026-10-27T10:10:00Z"),
        ]
    )
]


def build_capture(flag):
    if not flag:
        raise GenerationError("flag is empty")

    capture = Capture()

    # --- Workstation A resolves the portal ---------------------------------
    dns_exchange(capture, WORKSTATION_A, 51512, 0x4a1f, PORTAL_HOST, PORTAL)

    # --- Workstation A: landing page, shipment list, then the session call --
    landing = Conversation(capture, WORKSTATION_A, PORTAL, 51513, 80, 0x1F2A3B4C, 0x7C6D5E4F)
    landing.open()
    landing.send(
        f"GET / HTTP/1.1\r\nHost: {PORTAL_HOST}\r\n"
        "User-Agent: MeridianDesktop/2.4 (Windows 11; x64)\r\n"
        "Accept: text/html,application/xhtml+xml\r\nConnection: keep-alive\r\n\r\n"
    )
    landing.receive(http_response(
        "200 OK",
        "<!doctype html><html><head><title>Meridian Logistics</title></head>"
        "<body><h1>Shipment Tracking</h1><p>Sign in to review active consignments.</p>"
        "</body></html>",
        "text/html; charset=utf-8",
    ))
    capture.advance(0.142)

    shipments_body = json.dumps({"count": len(SHIPMENTS), "shipments": SHIPMENTS}, indent=1)
    landing.send(
        f"GET /api/shipments?window=7d HTTP/1.1\r\nHost: {PORTAL_HOST}\r\n"
        "User-Agent: MeridianDesktop/2.4 (Windows 11; x64)\r\n"
        "Accept: application/json\r\nX-Request-Id: 6f1c2a90\r\nConnection: keep-alive\r\n\r\n"
    )
    landing.receive(http_response("200 OK", shipments_body))
    capture.advance(0.086)
    landing.close()

    # --- Workstation A: authenticated session request (target traffic) ------
    capture.advance(0.240)
    session = Conversation(capture, WORKSTATION_A, PORTAL, 51514, 80, 0x2B4C5D6E, 0x6E5F4A3B)
    session.open()
    capture.advance(0.137)
    session.send(session_request(flag))
    session.receive(http_response(
        "200 OK",
        '{"session":"valid","employee":"j.reinhardt","role":"dispatcher",'
        '"expires_in":3600,"permissions":["shipments:read","shipments:update"]}',
    ))
    capture.advance(0.051)
    session.close()

    # --- Workstation B: background portal usage ----------------------------
    capture.advance(1.180)
    dns_exchange(capture, WORKSTATION_B, 53988, 0x4a20, UPDATES_HOST, PORTAL)
    capture.advance(0.015)

    colleague = Conversation(capture, WORKSTATION_B, PORTAL, 53989, 80, 0x3C5D6E7F, 0x5A4B3C2D)
    colleague.open()
    colleague.send(
        f"GET /api/shipments?status=delivered HTTP/1.1\r\nHost: {PORTAL_HOST}\r\n"
        "User-Agent: MeridianDesktop/2.4 (Windows 11; x64)\r\n"
        "Accept: application/json\r\nConnection: keep-alive\r\n\r\n"
    )
    colleague.receive(http_response(
        "200 OK",
        json.dumps({"count": 2, "shipments": SHIPMENTS[1:2] + SHIPMENTS[7:8]}, indent=1),
    ))
    capture.advance(0.210)
    colleague.send(
        f"GET /api/status HTTP/1.1\r\nHost: {PORTAL_HOST}\r\n"
        "User-Agent: MeridianDesktop/2.4 (Windows 11; x64)\r\n"
        "Accept: application/json\r\nConnection: keep-alive\r\n\r\n"
    )
    colleague.receive(http_response("200 OK", '{"status":"operational","build":"2.4.118"}'))
    capture.advance(0.098)
    colleague.close()

    # --- Reporting service: nightly report collection ----------------------
    capture.advance(0.640)
    dns_exchange(capture, WORKSTATION_A, 51515, 0x4a21, REPORTING_HOST, REPORTING)
    capture.advance(0.020)

    reporting = Conversation(capture, WORKSTATION_A, REPORTING, 51516, 8080, 0x4D5E6F70, 0x3B2C1D0E)
    reporting.open()
    reporting.send(
        f"GET /report/daily HTTP/1.1\r\nHost: {REPORTING_HOST}:8080\r\n"
        "User-Agent: MeridianSync/1.8\r\nAccept: application/json\r\n\r\n"
    )
    reporting.receive(http_response(
        "200 OK",
        json.dumps({"date": "2026-10-28", "consignments": 214, "exceptions": 3,
                    "on_time_rate": 0.977}, indent=1),
    ))
    capture.advance(0.132)
    reporting.close()

    # --- Workstation B: telemetry push -------------------------------------
    capture.advance(0.780)
    telemetry = Conversation(capture, WORKSTATION_B, REPORTING, 53990, 8080, 0x5E6F7081, 0x2C1D0E1F)
    telemetry.open()
    telemetry.send(
        f"POST /telemetry HTTP/1.1\r\nHost: {REPORTING_HOST}:8080\r\n"
        "User-Agent: MeridianSync/1.8\r\nContent-Type: application/json\r\n"
        'Content-Length: 58\r\n\r\n{"client":"ws-b30","events":4,"dropped":0,"uptime_s":84612}'
    )
    telemetry.receive(
        "HTTP/1.1 204 No Content\r\n"
        f"Date: {HTTP_DATE}\r\nServer: Meridian-Reporting/1.8\r\nConnection: keep-alive\r\n\r\n"
    )
    capture.advance(0.044)
    telemetry.close()

    # --- Background noise: CDN lookup, ARP, closed port --------------------
    capture.advance(0.900)
    dns_exchange(capture, WORKSTATION_B, 53991, 0x4a22, CDN_HOST, "192.168.10.40")

    capture.advance(0.050)
    arp_request = (
        Ether(src=MAC[WORKSTATION_B], dst=BROADCAST_MAC)
        / ARP(op=1, hwsrc=MAC[WORKSTATION_B], psrc=WORKSTATION_B, pdst=PORTAL)
    )
    capture.add(arp_request)

    capture.advance(0.002)
    arp_reply = (
        Ether(src=MAC[PORTAL], dst=MAC[WORKSTATION_B])
        / ARP(op=2, hwsrc=MAC[PORTAL], psrc=PORTAL, hwdst=MAC[WORKSTATION_B], pdst=WORKSTATION_B)
    )
    capture.add(arp_reply)

    capture.advance(0.130)
    refused = Conversation(capture, WORKSTATION_A, PORTAL, 51517, 3389, 0x6F708192, 0x1D0E1F20)
    refused.open()
    capture.advance(0.002)
    capture.add(frame(PORTAL, WORKSTATION_A, "", "RA", 0, refused.client_next, 3389, 51517))

    return capture


# --- validation --------------------------------------------------------------

def _http_payloads(packets):
    for packet in packets:
        if packet.haslayer(Raw):
            yield packet, bytes(packet[Raw].load)


def validate_capture(path, flag):
    """Independently re-read the written file and assert all required properties."""
    problems = []

    if not os.path.exists(path):
        raise GenerationError("capture file was not written")

    size = os.path.getsize(path)
    if not MIN_SIZE <= size <= MAX_SIZE:
        problems.append(f"file size {size} is outside {MIN_SIZE}-{MAX_SIZE} bytes")

    packets = rdpcap(path)
    if len(packets) < 40:
        problems.append(f"capture only contains {len(packets)} packets")

    dns = [packet for packet in packets if packet.haslayer(DNS)]
    if not any(packet[DNS].qr == 0 for packet in dns):
        problems.append("no DNS query present")
    if not any(packet[DNS].qr == 1 for packet in dns):
        problems.append("no DNS response present")

    tcp = [packet for packet in packets if packet.haslayer(TCP)]
    if not any(packet[TCP].flags == "S" for packet in tcp):
        problems.append("no TCP SYN present")
    if not any(packet[TCP].flags == "SA" for packet in tcp):
        problems.append("no TCP SYN/ACK present")

    payloads = list(_http_payloads(packets))
    if not any(data.startswith(b"GET ") for _, data in payloads):
        problems.append("no HTTP request present")
    if not any(data.startswith(b"HTTP/1.1 ") for _, data in payloads):
        problems.append("no HTTP response present")

    target = [(packet, data) for packet, data in payloads if TARGET_PATH.encode() in data]
    if not target:
        problems.append("target request is not reconstructable")
    else:
        request = target[0][1].decode("latin-1")
        if f"{TARGET_HEADER}:" not in request:
            problems.append(f"{TARGET_HEADER} header is missing from the target request")
        if f"{TARGET_HEADER}: {flag}" not in request:
            problems.append("target header does not carry the injected flag")

    flag_bytes = flag.encode()
    carriers = [packet for packet in packets if flag_bytes in bytes(packet)]
    if len(carriers) != 1:
        problems.append(f"flag appears in {len(carriers)} packets, expected exactly 1")
    elif not str(carriers[0][IP].src) in (WORKSTATION_A, WORKSTATION_B):
        problems.append("flag appears in an unexpected direction")

    # The flag must never appear in a DNS name, a URL or a response body.
    for packet in packets:
        if packet.haslayer(DNS) and packet[DNS].qd is not None:
            name = packet[DNS].qd.qname
            if flag_bytes in name:
                problems.append("flag appears in a DNS query name")
        if packet.haslayer(Raw):
            data = bytes(packet[Raw].load)
            if data.startswith(b"HTTP/1.1 ") and flag_bytes in data:
                problems.append("flag appears in an HTTP response")

    if problems:
        raise GenerationError("capture validation failed: " + "; ".join(problems))

    return {
        "packets": len(packets),
        "bytes": size,
        "dns": len(dns),
        "tcp": len(tcp),
        "http": len(payloads),
    }


def read_flag():
    flag = os.environ.get("GZCTF_FLAG")

    if flag is None or flag.strip() == "":
        raise GenerationError("GZCTF_FLAG is missing or empty; refusing to start")

    os.environ.pop("GZCTF_FLAG", None)

    if len(flag.encode()) > MAX_FLAG_BYTES:
        raise GenerationError(f"flag length is outside the supported range (1-{MAX_FLAG_BYTES} bytes)")

    if any(ord(character) < 0x20 or ord(character) > 0x7E for character in flag):
        raise GenerationError("flag contains characters outside the supported range")

    return flag


def main():
    parser = argparse.ArgumentParser(description="Generate the Meridian Logistics traffic capture.")
    parser.add_argument("--output", required=True, help="path of the PCAP file to write")
    parser.add_argument("--flag", help=argparse.SUPPRESS)  # test hook; production uses GZCTF_FLAG
    args = parser.parse_args()

    try:
        flag = args.flag if args.flag else read_flag()
        if not flag:
            raise GenerationError("flag is missing or empty")

        capture = build_capture(flag)
        capture.write(args.output)
        summary = validate_capture(args.output, flag)
    except GenerationError as error:
        print(f"[meridian-capture] {error}", file=sys.stderr)
        return 1
    except Exception as error:  # noqa: BLE001 - never surface packet content in the error
        print(f"[meridian-capture] capture generation failed: {error.__class__.__name__}", file=sys.stderr)
        return 1

    print(
        f"[meridian-capture] wrote {os.path.basename(args.output)} "
        f"({summary['bytes']} bytes, {summary['packets']} packets, "
        f"{summary['dns']} DNS, {summary['tcp']} TCP, {summary['http']} HTTP payloads)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
