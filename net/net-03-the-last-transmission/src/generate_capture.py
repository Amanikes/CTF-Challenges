"""Capture generation, validation and publication for NET-03.

Coordinates the artifact, DNS, HTTP, FTP and timeline modules, then re-reads the
written file and proves the investigation is actually possible: the critical
streams must reconstruct, the FTP data payload must equal the archive, and the
flag must be recoverable from the capture alone.
"""

import logging
import os
import sys

from scapy.all import DNS, IP, Raw, TCP, rdpcap

import artifact
import http_traffic
import timeline
from topology import (
    ARCHIVE_NAME,
    CLIENT_IP,
    FTP_DATA_PORT,
    INCIDENT_REFERENCE,
    SERVER_IP,
    SERVER_HOSTNAME,
)

logger = logging.getLogger("net03.capture")

MIN_PACKETS = 60
MIN_SIZE = 8 * 1024
MAX_SIZE = 4 * 1024 * 1024


class CaptureError(RuntimeError):
    """Raised when the capture cannot be produced or fails validation."""


def _payloads(packets, *, src=None, dst=None, sport=None, dport=None):
    for packet in packets:
        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            continue
        if src is not None and packet[IP].src != src:
            continue
        if dst is not None and packet[IP].dst != dst:
            continue
        if sport is not None and packet[TCP].sport != sport:
            continue
        if dport is not None and packet[TCP].dport != dport:
            continue
        yield packet, bytes(packet[Raw].load)


def recover_ftp_payload(packets):
    """Reassemble the server->client payload of the FTP data connection."""
    segments = {}

    for packet, data in _payloads(packets, dst=CLIENT_IP, sport=FTP_DATA_PORT):
        segments[packet[TCP].seq] = data

    if not segments:
        raise CaptureError("FTP data connection carries no payload")

    return b"".join(segments[seq] for seq in sorted(segments))


def recover_http_stream(packets):
    """Reassemble the suspicious HTTP conversation in both directions."""
    to_server = {}
    to_client = {}

    for packet, data in _payloads(packets, dst=SERVER_IP, dport=80):
        if packet[IP].src == CLIENT_IP:
            to_server[packet[TCP].seq] = data

    client_port = None
    for packet, _ in _payloads(packets, dst=SERVER_IP, dport=80):
        if packet[IP].src == CLIENT_IP:
            client_port = packet[TCP].sport
            break

    if client_port is not None:
        for packet, data in _payloads(packets, src=SERVER_IP, sport=80, dport=client_port):
            to_client[packet[TCP].seq] = data

    requests = b"".join(to_server[seq] for seq in sorted(to_server))
    responses = b"".join(to_client[seq] for seq in sorted(to_client))
    return requests, responses


def recover_ftp_control(packets):
    """Reassemble both directions of the FTP control connection."""
    client_port = None
    for packet, _ in _payloads(packets, dst=SERVER_IP, dport=21):
        client_port = packet[TCP].sport
        break

    if client_port is None:
        raise CaptureError("FTP control connection not found")

    to_server = {}
    to_client = {}

    for packet, data in _payloads(packets, dst=SERVER_IP, dport=21):
        to_server[packet[TCP].seq] = data

    for packet, data in _payloads(packets, src=SERVER_IP, sport=21, dport=client_port):
        to_client[packet[TCP].seq] = data

    commands = b"".join(to_server[seq] for seq in sorted(to_server))
    replies = b"".join(to_client[seq] for seq in sorted(to_client))
    return commands, replies


def validate_capture(path, flag, expected_archive):
    """Re-read the artifact and assert every property the challenge relies on."""
    problems = []

    if not os.path.exists(path):
        raise CaptureError("capture file was not written")

    size = os.path.getsize(path)
    if not MIN_SIZE <= size <= MAX_SIZE:
        problems.append(f"size {size} is outside {MIN_SIZE}-{MAX_SIZE} bytes")

    packets = rdpcap(path)
    if len(packets) < MIN_PACKETS:
        problems.append(f"only {len(packets)} packets present")

    for packet in packets:
        if packet.haslayer("ARP"):
            continue  # link-layer background noise is legitimate
        if not packet.haslayer(IP):
            problems.append("packet without an IPv4 layer")
            break
        if not (packet.haslayer(TCP) or packet.haslayer("UDP")):
            problems.append("packet without a transport layer")
            break

    # --- DNS stage -------------------------------------------------------
    dns_packets = [packet for packet in packets if packet.haslayer(DNS)]
    queries = [
        packet for packet in dns_packets
        if packet[DNS].qr == 0 and packet[DNS].qd is not None
        and packet[DNS].qd.qname.decode().rstrip(".") == SERVER_HOSTNAME
    ]
    responses = [
        packet for packet in dns_packets
        if packet[DNS].qr == 1 and packet[DNS].qd is not None
        and packet[DNS].qd.qname.decode().rstrip(".") == SERVER_HOSTNAME
    ]

    if not queries:
        problems.append(f"no DNS query for {SERVER_HOSTNAME}")
    if not responses:
        problems.append(f"no DNS response for {SERVER_HOSTNAME}")
    elif not any(
        packet[DNS].an is not None
        and any(str(rr.rdata) == SERVER_IP for rr in packet[DNS].an)
        for packet in responses
    ):
        problems.append(f"DNS response does not resolve {SERVER_HOSTNAME} to {SERVER_IP}")

    # --- HTTP stage ------------------------------------------------------
    try:
        http_requests, http_responses = recover_http_stream(packets)
    except CaptureError:
        http_requests, http_responses = b"", b""

    if b"GET /api/transfer/status HTTP/1.1" not in http_requests:
        problems.append("HTTP transfer-status request is missing")
    if INCIDENT_REFERENCE.encode() not in http_responses:
        problems.append("HTTP response does not carry the incident reference")
    if ARCHIVE_NAME.encode() not in http_responses:
        problems.append("HTTP response does not name the archive")

    # --- FTP control stage ----------------------------------------------
    try:
        control_commands, control_replies = recover_ftp_control(packets)
    except CaptureError:
        control_commands, control_replies = b"", b""

    required_commands = [b"USER ", b"PASS ", b"PASV", b"RETR " + ARCHIVE_NAME.encode()]
    for fragment in required_commands:
        if fragment not in control_commands:
            problems.append(f"FTP control commands missing: {fragment.decode()}")

    for expected in (b"220 ", b"331 ", b"230 ", b"227 ", b"150 ", b"226 "):
        if expected not in control_replies:
            problems.append(f"FTP control replies missing: {expected.decode().strip()}")

    expected_pasv = (
        f"227 Entering Passive Mode ({SERVER_IP.replace('.', ',')},"
        f"{FTP_DATA_PORT // 256},{FTP_DATA_PORT % 256})"
    ).encode()
    if expected_pasv not in control_replies:
        problems.append("PASV reply does not encode the expected data port")

    # --- FTP data stage --------------------------------------------------
    try:
        transferred = recover_ftp_payload(packets)
    except CaptureError as error:
        transferred = b""
        problems.append(str(error))

    if transferred and transferred != expected_archive:
        problems.append("recovered FTP payload does not match the expected archive")

    # --- ordering --------------------------------------------------------
    dns_times = [float(packet.time) for packet in queries + responses]
    http_times = [
        float(packet.time)
        for packet, _ in _payloads(packets, dst=SERVER_IP, dport=80)
    ] + [
        float(packet.time)
        for packet, _ in _payloads(packets, src=SERVER_IP, sport=80)
    ]
    control_times = [
        float(packet.time)
        for packet, _ in _payloads(packets, dport=21)
    ] + [
        float(packet.time)
        for packet, _ in _payloads(packets, sport=21)
    ]
    data_times = [
        float(packet.time)
        for packet, _ in _payloads(packets, sport=FTP_DATA_PORT)
    ]

    if dns_times and http_times and min(dns_times) >= min(http_times):
        problems.append("DNS stage does not precede the HTTP stage")
    if http_times and control_times and max(http_times) >= min(control_times):
        problems.append("HTTP stage does not precede the FTP control stage")
    retr_time = None
    opening_time = None
    complete_time = None
    for packet, data in _payloads(packets, dport=21):
        if retr_time is None and b"RETR " in data:
            retr_time = float(packet.time)
    for packet, data in _payloads(packets, sport=21):
        if opening_time is None and b"150 " in data:
            opening_time = float(packet.time)
        if b"226 " in data:
            complete_time = float(packet.time)

    if data_times:
        earliest = min(data_times)
        if retr_time is None or opening_time is None:
            problems.append("FTP negotiation replies are missing around the data connection")
        else:
            if earliest <= opening_time:
                problems.append("FTP data connection opens before the 150 reply")
            if complete_time is not None and max(data_times) >= complete_time:
                problems.append("FTP data connection outlives the 226 completion reply")

    # --- interleaving ----------------------------------------------------
    critical = set()
    for packet in packets:
        if not packet.haslayer(TCP):
            continue
        if packet[IP].dst == SERVER_IP or packet[IP].src == SERVER_IP:
            critical.add(packet[TCP].sport)
            critical.add(packet[TCP].dport)

    unrelated = [
        float(packet.time)
        for packet in packets
        if not (
            packet.haslayer(TCP)
            and (packet[TCP].sport in critical and packet[TCP].dport in critical)
        )
    ]
    first_http = min(http_times) if http_times else 0.0
    last_http = max(http_times) if http_times else 0.0

    if not any(moment < first_http for moment in unrelated):
        problems.append("no background traffic before the HTTP stage")
    if not any(last_http < moment for moment in unrelated):
        problems.append("no background traffic after the HTTP stage")

    # --- flag confidentiality -------------------------------------------
    plaintext = flag.encode("utf-8")
    control_blob = control_commands + control_replies
    if plaintext in control_blob:
        problems.append("plaintext flag appears in FTP control messages")
    if plaintext in http_requests + http_responses:
        problems.append("plaintext flag appears in HTTP traffic")

    for packet in dns_packets:
        if packet[DNS].qd is not None and plaintext in packet[DNS].qd.qname:
            problems.append("plaintext flag appears in a DNS query")
            break

    if problems:
        raise CaptureError("capture validation failed: " + "; ".join(problems))

    return {
        "packets": len(packets),
        "bytes": size,
        "dns": len(dns_packets),
        "http_bytes": len(http_requests) + len(http_responses),
        "ftp_control_bytes": len(control_commands) + len(control_replies),
        "ftp_data_bytes": len(transferred),
    }


def generate(flag, destination, seed=0):
    """Build the archive and capture, validate both, then publish atomically."""
    if not flag:
        raise CaptureError("flag is missing or empty")

    archive = artifact.build_bundle(flag)
    artifact.validate_bundle(archive, flag)

    capture, metadata = timeline.build(flag, archive, seed=seed)
    frame_count = capture.write(destination)

    summary = validate_capture(destination, flag, archive)
    summary["frames"] = frame_count
    summary["archive_bytes"] = len(archive)
    summary["phases"] = metadata["phases"]
    return summary


def main():
    from config import ConfigError, configure_logging, load_config

    try:
        config = load_config()
    except ConfigError as error:
        print(f"[net03] {error}", file=sys.stderr)
        return 1

    configure_logging(config.log_level)

    try:
        summary = generate(config.flag, config.capture_path)
    except (CaptureError, artifact.ArtifactError) as error:
        logger.error("%s", error)
        return 1
    except ValueError as error:
        logger.error("artifact generation failed: %s", error)
        return 1
    except Exception as error:  # noqa: BLE001 - never surface payload content
        logger.error("capture generation failed: %s", error.__class__.__name__)
        return 1

    logger.info(
        "wrote %s (%d bytes, %d packets, %d DNS, %d HTTP bytes, "
        "%d FTP control bytes, %d FTP data bytes)",
        os.path.basename(config.capture_path),
        summary["bytes"],
        summary["packets"],
        summary["dns"],
        summary["http_bytes"],
        summary["ftp_control_bytes"],
        summary["ftp_data_bytes"],
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
