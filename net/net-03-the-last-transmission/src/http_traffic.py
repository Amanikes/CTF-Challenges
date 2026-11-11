"""Synthetic HTTP traffic for NET-03 — The Last Transmission.

The suspicious conversation provides the incident reference and the archive
name. It never contains the flag: participants must reach the FTP data
connection before the evidence is available.
"""

import json

from tcp_builder import TCPFlow
from topology import (
    ARCHIVE_NAME,
    CLIENT_IP,
    CLIENT_MAC,
    GATEWAY_MAC,
    HTTPS_PORT,
    INCIDENT_REFERENCE,
    SERVER_IP,
)

HTTP_DATE = "Thu, 02 Jul 2026 09:20:00 GMT"
HTML_DATE_HEADERS = {
    "Date": HTTP_DATE,
    "Server": "Transfer-Service/2.3",
    "Connection": "keep-alive",
}

# (offset, client port, first sequence number, server first sequence number)
SUSPICIOUS_PORT = 49612
SUSPICIOUS_CLIENT_ISN = 0x1A2B3C4D
SUSPICIOUS_SERVER_ISN = 0x5E6F7081
SUSPICIOUS_START = 15.0

BACKGROUND_PORT = 49630
BACKGROUND_CLIENT_ISN = 0x2C3D4E5F
BACKGROUND_SERVER_ISN = 0x60718293
BACKGROUND_START = 19.4


def response(status, body, content_type, extra=None):
    """Build a complete HTTP/1.1 response with a correct Content-Length."""
    payload = body if isinstance(body, bytes) else body.encode("utf-8")
    headers = dict(HTML_DATE_HEADERS)
    headers.update(extra or {})
    headers["Content-Type"] = content_type
    headers["Content-Length"] = str(len(payload))

    head = f"HTTP/1.1 {status}\r\n" + "".join(
        f"{name}: {value}\r\n" for name, value in headers.items()
    )
    return head.encode("latin-1") + b"\r\n" + payload


def request(method, path, host, extra=None):
    """Build a complete HTTP/1.1 request."""
    headers = {
        "Host": host,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AsterionBrowser/118.0",
        "Accept": "*/*",
        "Accept-Language": "en-GB,en;q=0.9",
        "Connection": "keep-alive",
    }
    headers.update(extra or {})

    head = f"{method} {path} HTTP/1.1\r\n" + "".join(
        f"{name}: {value}\r\n" for name, value in headers.items()
    )
    return head.encode("latin-1") + b"\r\n"


def transfer_status_body(archive_bytes):
    """The response that correlates the web session with the FTP transfer."""
    return json.dumps(
        {
            "status": "completed",
            "session": INCIDENT_REFERENCE,
            "archive": ARCHIVE_NAME,
            "destination": "transfer-service",
            "size_bytes": len(archive_bytes),
            "completed_at": "2026-07-02T09:20:18Z",
        },
        indent=2,
    )


def build_suspicious_conversation(capture, archive_bytes):
    """Four ordinary-looking requests; the third exposes the transfer details."""
    flow = TCPFlow(
        capture,
        client_ip=CLIENT_IP,
        client_mac=CLIENT_MAC,
        server_ip=SERVER_IP,
        server_mac=GATEWAY_MAC,
        client_port=SUSPICIOUS_PORT,
        server_port=80,
        client_isn=SUSPICIOUS_CLIENT_ISN,
        server_isn=SUSPICIOUS_SERVER_ISN,
        start=SUSPICIOUS_START,
    )
    flow.handshake()

    host_header = f"{SERVER_IP}"

    flow.idle(0.980)
    flow.send(request("GET", "/", host_header))
    flow.receive(
        response(
            "200 OK",
            "<!doctype html><html><head><title>Transfer Service</title></head>"
            "<body><h1>Transfer Service</h1><p>Ready.</p></body></html>",
            "text/html; charset=utf-8",
        )
    )

    flow.idle(0.910)
    flow.send(request("GET", "/api/status", host_header))
    flow.receive(
        response(
            "200 OK",
            json.dumps({"service": "transfer-service", "version": "2.3", "uptime_s": 18422}, indent=2),
            "application/json",
        )
    )

    flow.idle(0.870)
    flow.send(request("GET", "/api/transfer/status", host_header))
    flow.receive(
        response(
            "200 OK",
            transfer_status_body(archive_bytes),
            "application/json",
        )
    )

    flow.idle(0.320)
    flow.send(request("GET", "/favicon.ico", host_header))
    flow.receive(response("404 Not Found", "", "text/plain; charset=utf-8"))

    flow.idle(0.180)
    flow.close()

    return {
        "flow": flow,
        "first": SUSPICIOUS_START,
        "last": flow.end,
        "container": "/api/transfer/status",
    }


def build_background_conversation(capture, internal_host="10.10.20.40"):
    """Unrelated plain HTTP traffic so the relevant conversation is not obvious."""
    flow = TCPFlow(
        capture,
        client_ip=CLIENT_IP,
        client_mac=CLIENT_MAC,
        server_ip=internal_host,
        server_mac=GATEWAY_MAC,
        client_port=BACKGROUND_PORT,
        server_port=80,
        client_isn=BACKGROUND_CLIENT_ISN,
        server_isn=BACKGROUND_SERVER_ISN,
        start=BACKGROUND_START,
    )
    flow.handshake()

    flow.idle(0.240)
    flow.send(request("GET", "/intranet/home", "portal.asterion.internal"))
    flow.receive(
        response(
            "200 OK",
            "<!doctype html><html><head><title>Asterion Intranet</title></head>"
            "<body><h1>Intranet</h1><p>Announcements unavailable.</p></body></html>",
            "text/html; charset=utf-8",
        )
    )

    flow.idle(0.610)
    flow.send(request("GET", "/intranet/assets/logo.png", "portal.asterion.internal"))
    flow.receive(response("200 OK", b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, "image/png"))

    flow.idle(0.190)
    flow.close()

    return {"flow": flow, "first": BACKGROUND_START, "last": flow.end}
