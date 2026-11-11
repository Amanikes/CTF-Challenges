"""Synthetic DNS traffic for NET-03 — The Last Transmission.

The DNS stage exists for destination identification and correlation only: no
fragment of the flag is ever encoded in a DNS name.
"""

from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, UDP

from topology import (
    BACKUP_HOSTNAME,
    BACKUP_IP,
    CLIENT_IP,
    CLIENT_MAC,
    DNS_IP,
    DNS_MAC,
    SERVER_HOSTNAME,
    SERVER_IP,
)

# (offset in seconds, query name, record type, answer)
BACKGROUND_LOOKUPS = [
    (0.000, "portal.asterion.internal", "A", "10.10.20.40"),
    (0.320, "portal.asterion.internal", "AAAA", None),
    (0.640, "mail.asterion.internal", "A", "10.10.20.41"),
    (1.050, "time.windows.com", "A", "20.101.57.9"),
    (1.480, "login.microsoftonline.com", "A", "20.190.151.7"),
    (1.910, "update.microsoft.com", "A", "13.107.4.50"),
    (2.640, "repo.asterion.internal", "A", "10.10.20.42"),
    (3.170, "cdn.jsdelivr.net", "A", "151.101.1.229"),
    (3.620, "fonts.gstatic.com", "A", "142.250.185.99"),
    (4.410, "print01.asterion.internal", "A", "10.10.20.51"),
    (5.120, "filesvr02.asterion.internal", "A", "10.10.20.52"),
    (6.870, "intranet.asterion.internal", "AAAA", None),
    (21.900, "hr.asterion.internal", "A", "10.10.20.60"),
    (24.100, "mail.asterion.internal", "A", "10.10.20.41"),
    (31.500, "news.example.net", "A", "198.51.100.19"),
    (37.200, "portal.asterion.internal", "A", "10.10.20.40"),
    (43.600, BACKUP_HOSTNAME, "A", BACKUP_IP),
    (44.050, "status.asterion.internal", "A", "10.10.20.43"),
]

SUSPICIOUS_QUERY_AT = 8.0
SUSPICIOUS_RESPONSE_AT = 8.030

SOURCE_PORT_BASE = 51900


def _dns_id(index):
    """Deterministic transaction IDs that look random enough."""
    return (0x2E17 + index * 0x1F31) & 0xFFFF


def _query_packet(source_port, transaction_id, name, qtype):
    return (
        Ether(src=CLIENT_MAC, dst=DNS_MAC)
        / IP(src=CLIENT_IP, dst=DNS_IP, ttl=128)
        / UDP(sport=source_port, dport=53)
        / DNS(id=transaction_id, rd=1, qd=DNSQR(qname=name, qtype=qtype, qclass="IN"))
    )


def _response_packet(source_port, transaction_id, name, qtype, answer):
    if answer is None:
        # NODATA: the query is answered but carries no record.
        return (
            Ether(src=DNS_MAC, dst=CLIENT_MAC)
            / IP(src=DNS_IP, dst=CLIENT_IP, ttl=64)
            / UDP(sport=53, dport=source_port)
            / DNS(
                id=transaction_id,
                qr=1,
                aa=1,
                rd=1,
                ra=1,
                qd=DNSQR(qname=name, qtype=qtype, qclass="IN"),
            )
        )

    record_type = "AAAA" if qtype == "AAAA" else "A"
    return (
        Ether(src=DNS_MAC, dst=CLIENT_MAC)
        / IP(src=DNS_IP, dst=CLIENT_IP, ttl=64)
        / UDP(sport=53, dport=source_port)
        / DNS(
            id=transaction_id,
            qr=1,
            aa=1,
            rd=1,
            ra=1,
            qd=DNSQR(qname=name, qtype=qtype, qclass="IN"),
            an=DNSRR(rrname=name, type=record_type, ttl=300, rdata=answer),
        )
    )


def build_dns(capture, seed=0):
    """Add background lookups and the suspicious resolution to the capture.

    Returns the suspicious query/response packets so the timeline can assert
    their ordering relative to the HTTP and FTP phases.
    """
    packets = []

    for index, (offset, name, qtype, answer) in enumerate(BACKGROUND_LOOKUPS):
        source_port = SOURCE_PORT_BASE + index * 7 + seed
        transaction_id = _dns_id(index)

        query = _query_packet(source_port, transaction_id, name, qtype)
        capture.add(query, offset)
        packets.append(query)

        if answer is not None or qtype == "AAAA":
            response = _response_packet(source_port, transaction_id, name, qtype, answer)
            capture.add(response, offset + 0.021)
            packets.append(response)

    source_port = SOURCE_PORT_BASE + 900 + seed
    transaction_id = _dns_id(900)

    suspicious_query = _query_packet(source_port, transaction_id, SERVER_HOSTNAME, "A")
    suspicious_response = _response_packet(
        source_port, transaction_id, SERVER_HOSTNAME, "A", SERVER_IP
    )

    capture.add(suspicious_query, SUSPICIOUS_QUERY_AT)
    capture.add(suspicious_response, SUSPICIOUS_RESPONSE_AT)

    return {
        "query": suspicious_query,
        "response": suspicious_response,
        "all": packets + [suspicious_query, suspicious_response],
    }
