"""Synthetic FTP traffic for NET-03 — The Last Transmission.

Two independent TCP conversations make up a passive-mode transfer:

  control  client:<ephemeral>  -> server:21      commands and replies
  data     client:<ephemeral>  -> server:50000   the archive bytes, server->client

The PASV reply encodes port 50000 as ``195 * 256 + 80``; participants must read
that response to find the data connection.
"""

from tcp_builder import TCPFlow
from topology import (
    ARCHIVE_NAME,
    CLIENT_IP,
    CLIENT_MAC,
    FTP_CONTROL_PORT,
    FTP_DATA_PORT,
    FTP_PASSWORD,
    FTP_USER,
    GATEWAY_MAC,
    PASV_HIGH,
    PASV_LOW,
    SERVER_IP,
)

CONTROL_PORT = 49620
CONTROL_CLIENT_ISN = 0x3D4E5F60
CONTROL_SERVER_ISN = 0x718293A4
CONTROL_START = 25.0

DATA_CLIENT_ISN = 0x4E5F6071
DATA_SERVER_ISN = 0x8293A4B5
DATA_START = 36.0


def _line(text):
    """FTP commands and replies are CRLF terminated."""
    return (text + "\r\n").encode("latin-1")


def _idle_until(flow, moment):
    if moment > flow.clock:
        flow.idle(moment - flow.clock)


def build_ftp(capture, archive_bytes, *, auth_at=28.0, pasv_at=32.0, retr_at=35.0,
              data_start=DATA_START, complete_at=38.2, quit_at=42.0):
    """Build the control and data conversations and return timing metadata."""
    control = TCPFlow(
        capture,
        client_ip=CLIENT_IP,
        client_mac=CLIENT_MAC,
        server_ip=SERVER_IP,
        server_mac=GATEWAY_MAC,
        client_port=CONTROL_PORT,
        server_port=FTP_CONTROL_PORT,
        client_isn=CONTROL_CLIENT_ISN,
        server_isn=CONTROL_SERVER_ISN,
        start=CONTROL_START,
    )
    control.handshake()

    # 220 greeting
    _idle_until(control, CONTROL_START + 0.060)
    control.receive(_line("220 Asterion Transfer Service ready"))

    # USER / PASS
    _idle_until(control, auth_at)
    control.send(_line(f"USER {FTP_USER}"))
    control.receive(_line(f"331 Password required for {FTP_USER}"))

    _idle_until(control, auth_at + 0.420)
    control.send(_line(f"PASS {FTP_PASSWORD}"))
    control.receive(_line("230 Login successful."))

    # Binary mode before the transfer.
    _idle_until(control, auth_at + 0.780)
    control.send(_line("TYPE I"))
    control.receive(_line("200 Type set to I."))

    # Passive-mode negotiation.
    _idle_until(control, pasv_at)
    control.send(_line("PASV"))
    control.receive(
        _line(
            f"227 Entering Passive Mode "
            f"({SERVER_IP.replace('.', ',')},{PASV_HIGH},{PASV_LOW})"
        )
    )

    # Retrieve request.
    _idle_until(control, retr_at)
    control.send(_line(f"RETR {ARCHIVE_NAME}"))
    control.receive(
        _line(
            f"150 Opening BINARY mode data connection for {ARCHIVE_NAME} "
            f"({len(archive_bytes)} bytes)."
        )
    )

    # --- data connection (separate flow, client initiated) ---------------
    data_port = 49648

    data = TCPFlow(
        capture,
        client_ip=CLIENT_IP,
        client_mac=CLIENT_MAC,
        server_ip=SERVER_IP,
        server_mac=GATEWAY_MAC,
        client_port=data_port,
        server_port=FTP_DATA_PORT,
        client_isn=DATA_CLIENT_ISN,
        server_isn=DATA_SERVER_ISN,
        start=data_start,
    )
    data.handshake()
    data.idle(0.040)
    data.receive(archive_bytes)
    data.idle(0.080)
    data.close()

    # --- control connection completes ------------------------------------
    _idle_until(control, complete_at)
    control.receive(_line("226 Transfer complete."))

    _idle_until(control, quit_at)
    control.send(_line("QUIT"))
    control.receive(_line("221 Goodbye."))
    control.idle(0.050)
    control.close()

    return {
        "control": control,
        "data": data,
        "control_port": CONTROL_PORT,
        "data_port": data_port,
        "server_data_port": FTP_DATA_PORT,
        "pasv_reply": f"227 Entering Passive Mode "
                      f"({SERVER_IP.replace('.', ',')},{PASV_HIGH},{PASV_LOW})",
        "first": CONTROL_START,
        "data_first": data_start,
        "last": control.end,
        "archive_bytes": len(archive_bytes),
    }
