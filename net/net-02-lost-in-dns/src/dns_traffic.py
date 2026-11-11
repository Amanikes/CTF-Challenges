"""Synthetic DNS traffic for NET-02 — Lost in DNS.

All packets are assembled in memory with Scapy; nothing is transmitted and no
raw sockets or elevated privileges are needed.
"""

import random

from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, UDP

from encoding import SUSPICIOUS_SUFFIX, query_names

CLIENT_IP = "10.20.4.77"
RESOLVER_IP = "10.20.0.53"
CLIENT_MAC = "02:00:5e:14:04:4d"
RESOLVER_MAC = "02:00:5e:14:00:35"

BASE_TIME = 1_782_648_000.0  # 2026-07-02T09:20:00Z

# Ordinary destinations used for background traffic. The tuples are
# (name, record type, answer or None).
NORMAL_QUERIES = [
    ("portal.meridian.internal", "A", "10.20.4.10"),
    ("mail.meridian.internal", "A", "10.20.4.11"),
    ("repo.meridian.internal", "A", "10.20.4.12"),
    ("intranet.meridian.internal", "A", "10.20.4.13"),
    ("portal.meridian.internal", "AAAA", None),
    ("cdn.jsdelivr.net", "A", "151.101.1.229"),
    ("fonts.googleapis.com", "A", "142.250.187.202"),
    ("fonts.googleapis.com", "AAAA", None),
    ("api.github.com", "A", "140.82.121.6"),
    ("docs.python.org", "A", "151.101.64.223"),
    ("pypi.org", "A", "151.101.0.223"),
    ("files.pythonhosted.org", "A", "151.101.64.223"),
    ("registry.npmjs.org", "A", "104.16.24.34"),
    ("slack.com", "A", "13.107.42.14"),
    ("outlook.office365.com", "A", "52.97.146.130"),
    ("update.microsoft.com", "A", "13.107.4.50"),
    ("time.windows.com", "A", "20.101.57.9"),
    ("teams.microsoft.com", "AAAA", None),
    ("vault.meridian.internal", "A", "10.20.4.20"),
    ("git.meridian.internal", "A", "10.20.4.21"),
    ("metrics.meridian.internal", "A", "10.20.4.22"),
    ("search.meridian.internal", "A", "10.20.4.23"),
    ("status.meridian.internal", "A", "10.20.4.24"),
    ("ntp.meridian.internal", "A", "10.20.4.25"),
    ("print01.meridian.internal", "A", "10.20.4.31"),
    ("filesvr02.meridian.internal", "A", "10.20.4.32"),
    ("telemetry.vendor-metrics.net", "A", "203.0.113.44"),
    ("weather.example.org", "A", "198.51.100.7"),
    ("news.example.net", "A", "198.51.100.19"),
    ("cdn.static-assets.example", "A", "198.51.100.31"),
    ("auth.example-sso.com", "A", "203.0.113.78"),
    ("maps.example-services.net", "A", "203.0.113.91"),
]


def _normal_response(query, answer):
    """Build a plausible response for one normal query."""
    if answer is None:
        # No AAAA record: NODATA answer with an empty answer section.
        return DNS(
            id=query[DNS].id,
            qr=1,
            aa=0,
            rd=1,
            ra=1,
            qd=query[DNS].qd,
        )

    rr_type = "AAAA" if query[DNS].qd.qtype == 28 else "A"
    return DNS(
        id=query[DNS].id,
        qr=1,
        aa=0,
        rd=1,
        ra=1,
        qd=query[DNS].qd,
        an=DNSRR(rrname=query[DNS].qd.qname, type=rr_type, ttl=300, rdata=answer),
    )


def dns_a_and_aaaa_queries(count=None):
    """Deterministic subset of the ordinary query catalogue."""
    queries = NORMAL_QUERIES if count is None else NORMAL_QUERIES[:count]
    return list(queries)


def build_packets(flag, seed=20260702):
    """Return the ordered packet list for one team.

    The per-team flag only affects the suspicious queries; the surrounding
    traffic is deterministic for a given seed so builds are reproducible.
    """
    rng = random.Random(seed)
    suspicious = query_names(flag, SUSPICIOUS_SUFFIX)

    # Every suspicious query is separated by one or two ordinary lookups so the
    # fragments never form a contiguous block.
    ordinary = dns_a_and_aaaa_queries()
    timeline = []
    ordinary_index = 0

    for position, name in enumerate(suspicious):
        gap = rng.choice((1, 1, 2))
        for _ in range(gap):
            if ordinary_index < len(ordinary):
                timeline.append(("normal", ordinary[ordinary_index]))
                ordinary_index += 1
        timeline.append(("suspicious", name))

    while ordinary_index < len(ordinary):
        timeline.append(("normal", ordinary[ordinary_index]))
        ordinary_index += 1

    packets = []
    clock = 0.0
    source_port = 49152 + rng.randrange(0, 2048)

    for kind, payload in timeline:
        clock += round(rng.uniform(0.040, 2.400), 3)
        source_port = 49152 + ((source_port - 49152 + rng.randrange(3, 97)) % 16000)
        transaction_id = rng.randrange(0x1000, 0xFFFF)

        if kind == "suspicious":
            name = payload
            qtype = "TXT"
            query = (
                Ether(src=CLIENT_MAC, dst=RESOLVER_MAC)
                / IP(src=CLIENT_IP, dst=RESOLVER_IP, ttl=128)
                / UDP(sport=source_port, dport=53)
                / DNS(id=transaction_id, rd=1, qd=DNSQR(qname=name, qtype=qtype, qclass="IN"))
            )
            # SERVFAIL keeps the capture honest: the exfiltration channel never
            # actually resolves, which is what makes the queries stand out.
            response = (
                Ether(src=RESOLVER_MAC, dst=CLIENT_MAC)
                / IP(src=RESOLVER_IP, dst=CLIENT_IP, ttl=64)
                / UDP(sport=53, dport=source_port)
                / DNS(id=transaction_id, qr=1, aa=0, rd=1, ra=1, rcode=2, qd=DNSQR(
                    qname=name, qtype=qtype, qclass="IN"))
            )
        else:
            name, qtype, answer = payload
            query = (
                Ether(src=CLIENT_MAC, dst=RESOLVER_MAC)
                / IP(src=CLIENT_IP, dst=RESOLVER_IP, ttl=128)
                / UDP(sport=source_port, dport=53)
                / DNS(id=transaction_id, rd=1, qd=DNSQR(qname=name, qtype=qtype, qclass="IN"))
            )
            response = (
                Ether(src=RESOLVER_MAC, dst=CLIENT_MAC)
                / IP(src=RESOLVER_IP, dst=CLIENT_IP, ttl=64)
                / UDP(sport=53, dport=source_port)
                / _normal_response(query, answer)
            )

        query.time = BASE_TIME + clock
        clock += round(rng.uniform(0.008, 0.090), 3)
        response.time = BASE_TIME + clock

        packets.append(query)
        # A small share of lookups is left unanswered to look like a real capture.
        if rng.random() > 0.08:
            packets.append(response)

    return packets
