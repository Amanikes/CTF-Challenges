# NET-01 — Unencrypted Secrets

| | |
|---|---|
| Category | Network traffic analysis (GZ::CTF `Forensics` — see note) |
| Difficulty | Easy |
| Points | 100 |
| Flag format | `AXUM{...}` |
| Platform | GZ::CTF 1.9.x, `DynamicContainer` |
| Per-team flag | Yes (`GZCTF_FLAG`) |
| Artifact | Per-team PCAP (`meridian-traffic.pcap`) |
| Sensitivity | Credential in a plaintext HTTP request header |
| Guidance | Guided (3 hints) |
| Expected solve time | 10–20 minutes |

> **Category note:** GZ::CTF 1.9.1 has no *Network* category. Its verified
> `ChallengeCategory` enum is `Misc, Crypto, Pwn, Web, Reverse, Blockchain,
> Forensics, Hardware, Mobile, PPC, AI, Pentest, OSINT`, so the challenge is
> configured as `Forensics` — the closest verified value for packet-capture
> analysis. The participant-facing text still frames it as network traffic.

> **Warning:** the capture is synthetic and generated for training. It contains
> no real traffic, hosts or credentials.

## Overview

Meridian Logistics recovered a traffic capture from its internal
shipment-tracking environment. Several sessions between employee workstations
and internal services are present. One request carries a session token in a
custom header over plaintext HTTP; that token is the team's dynamic flag.

## Topology

| Device | Address |
|---|---|
| Meridian portal | `192.168.10.10` |
| Reporting service | `192.168.10.20` |
| Workstation A | `192.168.10.25` |
| Workstation B | `192.168.10.30` |
| Internal DNS | `192.168.10.53` |

## Architecture

```text
GZ::CTF flag (per team)
        |
        v
generate_capture.py ── builds Ethernet/IP/TCP/DNS/HTTP frames in memory
        |              (no raw sockets, no interface access)
        |── validate_capture() re-reads the file and asserts 12 properties
        v
meridian-traffic.pcap  (exactly one packet carries the flag)
        |
        v
download service (Express, port 3000)  ← never receives the flag
        |
        v
participant → Wireshark / tshark → X-Meridian-Session → submit
```

## Layout

```text
net-01-unencrypted-secrets/
├── challenge.yml            # authoritative GZ::CTF value set (no flag)
├── README.md
├── Dockerfile               # node:22-alpine + python3 + scapy, non-root
├── .dockerignore
├── requirements.txt         # scapy==2.8.0
├── entrypoint.sh            # flag validation → generate → validate → serve
├── scripts/generate_capture.py
├── server/{package.json, package-lock.json, server.js}
├── public/{index.html, styles.css, favicon.svg}
├── tests/
│   ├── support.py
│   ├── test_generation.py
│   ├── test_pcap_validity.py
│   ├── test_flag_exposure.py
│   ├── test_isolation.py
│   ├── gzctf_e2e.py
│   └── run-tests.sh
└── organizer/
    ├── WRITEUP.md
    ├── DEPLOYMENT.md
    └── TESTING.md
```

## Build and run

```bash
docker build -t net-01-unencrypted-secrets:dev .

docker run --rm -d --name net-01 \
  -e 'GZCTF_FLAG=GZCTF{NET01_TEST_FLAG}' \
  -p 127.0.0.1:3000:3000 \
  net-01-unencrypted-secrets:dev

curl http://127.0.0.1:3000/health
curl -OJ http://127.0.0.1:3000/download
tcpdump -nn -A -r meridian-traffic.pcap | grep X-Meridian-Session
```

## Capture contents

74 packets, ~10 KB, five TCP conversations plus DNS and ARP:

* Workstation A resolves and browses the portal (landing page, shipment list).
* Workstation A performs the authenticated session request — **the target**.
* Workstation B browses deliveries and pushes telemetry to reporting.
* Workstation A pulls the daily report from reporting.
* Background: CDN lookup, ARP resolution, a refused connection.

The shipment list response is ~1.7 KB, so it spans two segments and exercises
TCP reassembly.

## Solve path

```bash
tshark -r meridian-traffic.pcap -Y 'http.request' -T fields -e http.request.uri
tshark -r meridian-traffic.pcap -Y 'http.request.method=="GET"' -T fields \
       -e http.request.uri -e http.user_agent -e http.x_meridian_session
```

Or in Wireshark: `http.request` → the request to `/internal/api/session` →
Follow → TCP Stream → read `X-Meridian-Session`.

## Tests

```bash
./tests/run-tests.sh          # 47 tests across 4 suites
python3 tests/gzctf_e2e.py --base-url http://127.0.0.1:3000 \
  --admin-user Admin --admin-pass '<password>' \
  --image net-01-unencrypted-secrets:dev
```

Results in [organizer/TESTING.md](organizer/TESTING.md).

## Documentation

* [organizer/WRITEUP.md](organizer/WRITEUP.md) — generation architecture, packet flow, solve steps, filters, lessons
* [organizer/DEPLOYMENT.md](organizer/DEPLOYMENT.md) — build, GZ::CTF configuration, troubleshooting
* [organizer/TESTING.md](organizer/TESTING.md) — executed test results
