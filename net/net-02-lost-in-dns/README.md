# NET-02 — Lost in DNS

| | |
|---|---|
| Category | Network traffic analysis (GZ::CTF `Forensics` — see note) |
| Difficulty | Easy |
| Points | 50 |
| Flag format | `AXUM{...}` |
| Protocol | DNS over UDP/53 |
| Encoding | Hexadecimal fragments in DNS query subdomains |
| Artifact | `capture.pcap`, generated per team |
| Platform | GZ::CTF 1.9.x, `DynamicContainer` |
| Guidance | Guided (4 hints) |

> **Category note:** GZ::CTF 1.9.1 has no *Network* category. Its verified
> `ChallengeCategory` enum is `Misc, Crypto, Pwn, Web, Reverse, Blockchain,
> Forensics, Hardware, Mobile, PPC, AI, Pentest, OSINT`, so this challenge uses
> `Forensics` — consistent with NET-01 and inside verified values.

> **Warning:** all DNS traffic is synthetic and generated offline. This
> challenge does not implement DNS exfiltration, a tunnel, or any live
> command-and-control behaviour, and no packet ever leaves the container.

## Overview

A monitoring system flagged unusual DNS activity from an internal workstation.
The capture looks ordinary at first glance: routine A and AAAA lookups for
internal and public names. Hidden among them are TXT queries whose subdomains
carry hex-encoded fragments of the team's flag.

```text
001.475a4354467b4c4f53545f49.telemetry.example.test
002.4e5f444e535f4558414d504c.telemetry.example.test
003.455f464c41477d.telemetry.example.test
```

Concatenating the fragments in sequence order and hex-decoding yields the flag.

## Architecture

```text
GZCTF_FLAG
    │
    ├─ src/encoding.py        flag → UTF-8 → hex → 24-char fragments → query names
    ├─ src/dns_traffic.py     Scapy frames: normal lookups + fragments interleaved
    ├─ src/generate_capture.py  write temp file → validate → atomic rename
    │
    v
/app/runtime/capture.pcap
    │
    v
src/app.py (Python stdlib HTTP server, PORT 8080)  ← never receives the flag
    │
    v
participant → Wireshark / tshark → submit
```

## Layout

```text
net-02-lost-in-dns/
├── challenge.yml            # authorititative GZ::CTF value set (no flag)
├── docker-compose.yml       # local development only
├── Dockerfile               # python:3.12-alpine3.21, non-root uid 10001
├── requirements.txt         # scapy==2.8.0
├── .dockerignore
├── README.md
├── src/
│   ├── app.py               # download service
│   ├── config.py            # environment validation
│   ├── dns_traffic.py       # synthetic DNS traffic
│   ├── encoding.py          # hex encoding and fragmentation
│   └── generate_capture.py  # capture generation + validation
├── templates/index.html
├── static/{style.css, favicon.svg}
├── docs/{challenge.md, writeup.md, deployment.md, testing.md}
└── tests/
    ├── test_encoding.py
    ├── test_capture.py
    ├── test_flag.py
    ├── test_app.py
    ├── gzctf_e2e.py
    └── run-tests.sh
```

## Local setup

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

export GZCTF_FLAG='GZCTF{LOCAL_TEST_FLAG}'
export PCAP_PATH=/tmp/net02/capture.pcap
python3 src/generate_capture.py     # writes and validates the capture
python3 src/app.py                  # serves on http://127.0.0.1:8080
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `GZCTF_FLAG` | — (required) | Injected by GZ::CTF; consumed only by the generator |
| `PORT` | `8080` | HTTP listen port |
| `PCAP_PATH` | `/app/runtime/capture.pcap` | Artifact location |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |

Invalid values abort startup. Values are never printed, and there is no
fallback flag.

## Docker usage

```bash
docker build -t net-02-lost-in-dns:dev .

docker run --rm -d --name net-02 \
  -e 'GZCTF_FLAG=GZCTF{LOCAL_TEST_FLAG}' \
  -p 127.0.0.1:8080:8080 \
  net-02-lost-in-dns:dev

curl http://127.0.0.1:8080/health
curl -OJ http://127.0.0.1:8080/download
```

Local compose (development only):

```bash
docker compose up --build
```

## Runtime generation behaviour

1. Reject a missing, empty or blank `GZCTF_FLAG`.
2. Encode the flag, split it into 24-hex-character fragments and build the
   query names.
3. Generate 25–35 ordinary lookups plus the fragment queries, interleaved.
4. Write to a temporary file, re-read it with Scapy and validate.
5. Publish atomically as `capture.pcap` (mode 0644).
6. `unset GZCTF_FLAG`, then start the HTTP server.

If validation fails the container exits non-zero and no artifact is published.

## Testing

```bash
./tests/run-tests.sh                      # 79 tests across 4 suites
python3 tests/gzctf_e2e.py --base-url http://127.0.0.1:3000 \
  --admin-user Admin --admin-pass '<password>' \
  --image net-02-lost-in-dns:dev
```

Executed results are recorded in [docs/testing.md](docs/testing.md).

## Documentation

* [docs/challenge.md](docs/challenge.md) — organizer metadata, description, hints
* [docs/writeup.md](docs/writeup.md) — full solution with Wireshark, Python and tshark
* [docs/deployment.md](docs/deployment.md) — GZ::CTF deployment, limits, troubleshooting
* [docs/testing.md](docs/testing.md) — executed test report
