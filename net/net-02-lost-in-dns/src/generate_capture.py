"""Capture generation and validation for NET-02 — Lost in DNS.

The capture is written to a temporary file, re-read and validated, and only then
published atomically as capture.pcap. A partially written or invalid artifact is
never left behind.
"""

import logging
import os
import sys
import tempfile

from scapy.all import DNS, IP, TCP, UDP, rdpcap, wrpcap

from dns_traffic import CLIENT_IP, RESOLVER_IP, build_packets
from encoding import SUSPICIOUS_SUFFIX, decode_names, query_names

logger = logging.getLogger("net02.capture")

MIN_PACKETS = 40
MIN_SIZE = 4 * 1024
MAX_SIZE = 2 * 1024 * 1024


class CaptureError(RuntimeError):
    """Raised when the capture cannot be produced or fails validation."""


def _write(packets, path):
    ordered = sorted(packets, key=lambda packet: packet.time)
    wrpcap(path, ordered)
    os.chmod(path, 0o644)


def validate_capture(path, flag):
    """Re-read the artifact and assert every requirement for NET-02."""
    problems = []

    if not os.path.exists(path):
        raise CaptureError("capture file was not written")

    size = os.path.getsize(path)
    if not MIN_SIZE <= size <= MAX_SIZE:
        problems.append(f"size {size} is outside {MIN_SIZE}-{MAX_SIZE} bytes")

    packets = rdpcap(path)
    if len(packets) < MIN_PACKETS:
        problems.append(f"only {len(packets)} packets present")

    dns_packets = [packet for packet in packets if packet.haslayer(DNS)]
    queries = [packet for packet in dns_packets if packet[DNS].qr == 0]
    responses = [packet for packet in dns_packets if packet[DNS].qr == 1]

    if not queries:
        problems.append("no DNS queries present")
    if not responses:
        problems.append("no DNS responses present")

    expected_names = query_names(flag, SUSPICIOUS_SUFFIX)
    suspicious = []

    for packet in queries:
        question = packet[DNS].qd
        if question is None:
            continue
        name = question.qname.decode("ascii", "replace").rstrip(".")
        if name.endswith(SUSPICIOUS_SUFFIX):
            suspicious.append(name)

    if suspicious != expected_names:
        problems.append(
            f"suspicious query sequence does not match the expected {len(expected_names)} fragments"
        )

    try:
        recovered = decode_names(suspicious, SUSPICIOUS_SUFFIX)
    except Exception:  # noqa: BLE001 - any decode failure is a validation failure
        recovered = None

    if recovered != flag:
        problems.append("suspicious queries do not reconstruct the injected flag")

    plaintext = flag.encode("utf-8")
    leaked = [packet for packet in packets if plaintext in bytes(packet)]
    if leaked:
        problems.append("plaintext flag appears in the capture")

    for packet in dns_packets:
        question = packet[DNS].qd
        if question is not None and plaintext in question.qname:
            problems.append("plaintext flag appears in a DNS query name")
            break

    # Layer sanity: every packet must be Ethernet/IP and carry UDP or TCP.
    for packet in packets:
        if not packet.haslayer(IP):
            problems.append("packet without an IPv4 layer")
            break
        if not (packet.haslayer(UDP) or packet.haslayer(TCP)):
            problems.append("packet without a transport layer")
            break

    for packet in dns_packets:
        if packet.haslayer(UDP) and packet[UDP].dport != 53 and packet[UDP].sport != 53:
            problems.append("DNS traffic does not use port 53")
            break

    # Interleaving: at least one normal query must sit between fragments.
    ordered_queries = [
        packet[DNS].qd.qname.decode("ascii", "replace").rstrip(".")
        for packet in queries
        if packet[DNS].qd is not None
    ]
    missing = [name for name in expected_names if name not in ordered_queries]
    if missing:
        problems.append("expected suspicious queries are missing from the capture")
    elif len(expected_names) > 1:
        positions = [ordered_queries.index(name) for name in expected_names]
        if any(second - first < 2 for first, second in zip(positions, positions[1:])):
            problems.append("suspicious queries are not interleaved with normal traffic")

    if ordered_queries.count(CLIENT_IP) or not any(
        packet.haslayer(IP) and packet[IP].src == CLIENT_IP for packet in packets
    ):
        problems.append("client address is not present in the capture")

    if not any(packet.haslayer(IP) and packet[IP].dst == RESOLVER_IP for packet in packets):
        problems.append("resolver address is not present in the capture")

    if problems:
        raise CaptureError("capture validation failed: " + "; ".join(problems))

    return {
        "packets": len(packets),
        "bytes": size,
        "queries": len(queries),
        "responses": len(responses),
        "fragments": len(expected_names),
    }


def generate(flag, destination):
    """Generate, validate and atomically publish the capture."""
    if not flag:
        raise CaptureError("flag is missing or empty")

    packets = build_packets(flag)

    directory = os.path.dirname(os.path.abspath(destination)) or "."
    os.makedirs(directory, exist_ok=True)

    handle, temporary = tempfile.mkstemp(suffix=".pcap.tmp", dir=directory)
    os.close(handle)

    try:
        _write(packets, temporary)
        summary = validate_capture(temporary, flag)
        os.replace(temporary, destination)
        os.chmod(destination, 0o644)
    except Exception:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise

    return summary


def main():
    from config import ConfigError, configure_logging, load_config

    try:
        config = load_config()
    except ConfigError as error:
        print(f"[net02] {error}", file=sys.stderr)
        return 1

    configure_logging(config.log_level)

    try:
        summary = generate(config.flag, config.capture_path)
    except CaptureError as error:
        logger.error("%s", error)
        return 1
    except Exception as error:  # noqa: BLE001 - never surface packet content
        logger.error("capture generation failed: %s", error.__class__.__name__)
        return 1

    logger.info(
        "wrote %s (%d bytes, %d packets, %d queries, %d responses, %d fragments)",
        os.path.basename(config.capture_path),
        summary["bytes"],
        summary["packets"],
        summary["queries"],
        summary["responses"],
        summary["fragments"],
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
