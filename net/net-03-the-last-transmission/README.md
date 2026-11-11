# NET-03 — The Last Transmission

| | |
|---|---|
| Category | Network traffic analysis (GZ::CTF `Forensics` — see note) |
| Difficulty | Medium |
| Points | 150 |
| Protocols | DNS (UDP/53), HTTP (TCP/80), FTP passive (TCP/21 + TCP/50000) |
| Transferred artifact | `confidential_bundle.zip` inside the FTP data connection |
| Flag placement | Inside `evidence/incident_summary.txt` in the archive |
| Capture | `capture.pcap`, generated per team |
| Platform | GZ::CTF 1.9.x, `DynamicContainer` |
| Guidance | Guided (4 hints) |

> **Category note:** GZ::CTF 1.9.1 has no *Network* category. Its verified
> `ChallengeCategory` enum is `Misc, Crypto, Pwn, Web, Reverse, Blockchain,
> Forensics, Hardware, Mobile, PPC, AI, Pentest, OSINT`, so this challenge uses
> `Forensics`, consistent with NET-01 and NET-02.

> **Warning:** all traffic is synthetic and generated offline. No DNS query,
> HTTP request or FTP transfer ever leaves the container.

## Overview

Asterion Technologies reported a suspected breach. The capture contains 130
packets: ordinary DNS lookups, a suspicious resolution, a short series of HTTP
requests, and an FTP session that transfers a ZIP archive over a *separate*
passive data connection. The flag lives only inside that archive.

The solution requires all three protocols:

1. DNS reveals `files-update.example.test` → `192.0.2.80`.
2. HTTP to that address returns the incident reference `AX-7842` and the
   archive name `confidential_bundle.zip`.
3. FTP control shows `PASV` encoding port `50000` (`195 * 256 + 80`), then
   `RETR confidential_bundle.zip`; the data connection on port 50000 carries
   the ZIP, which is reconstructed with Follow TCP Stream.

## Architecture

```text
GZCTF_FLAG
    │
    ├─ src/artifact.py      ZIP with evidence/incident_summary.txt (uncompressed, 3 TCP segments)
    ├─ src/dns_traffic.py   18 background lookups + the suspicious resolution
    ├─ src/tcp_builder.py   TCPFlow: handshake, segmentation, ACKs, FIN, reassembly
    ├─ src/http_traffic.py  4 requests incl. /api/transfer/status + background HTTP
    ├─ src/ftp_traffic.py   control (21) + passive data (50000)
    ├─ src/timeline.py      one clock, phases at 00:08 / 00:15 / 00:25 / 00:36
    └─ src/generate_capture.py  build → validate → atomic publish
    │
    v
/app/artifacts/capture.pcap
    │
    v
src/app.py (stdlib HTTP server, PORT 8080)  ← never receives the flag
```

## Layout

```text
net-03-the-last-transmission/
├── challenge.yml
├── docker-compose.yml       # local development only
├── Dockerfile               # python:3.12-alpine3.21, non-root uid 10001
├── requirements.txt         # scapy==2.8.0
├── .dockerignore
├── entrypoint.sh
├── src/
│   ├── app.py · config.py · topology.py
│   ├── artifact.py · timeline.py
│   ├── dns_traffic.py · http_traffic.py · ftp_traffic.py
│   ├── tcp_builder.py
│   └── generate_capture.py
├── templates/index.html
├── static/{style.css, favicon.svg}
├── docs/{challenge.md, writeup.md, deployment.md, testing.md}
└── tests/  (8 suites + gzctf_e2e.py + run-tests.sh)
```

## Dependencies

`scapy==2.8.0` only. Everything else is the Python standard library, so the
runtime image is `python:3.12-alpine3.21` plus Scapy — no Node, no web framework.

## Environment variables

| Variable | Default | Notes |
|---|---|---|
| `GZCTF_FLAG` | — (required) | Injected by GZ::CTF; used only by the generator |
| `PORT` | `8080` | Must match the challenge *Service Port* |
| `PCAP_PATH` | `/app/artifacts/capture.pcap` | Must be writable by UID 10001 |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |

## Local setup

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

export GZCTF_FLAG='GZCTF{LOCAL_TEST_FLAG}'
export PCAP_PATH=/tmp/net03/capture.pcap
python3 src/generate_capture.py     # writes and validates the capture
python3 src/app.py                  # serves on http://127.0.0.1:8080
```

## Docker

```bash
docker build -t net-03-the-last-transmission:dev .

docker run --rm -d --name net-03 \
  -e 'GZCTF_FLAG=GZCTF{LOCAL_TEST_FLAG}' \
  -p 127.0.0.1:8080:8080 \
  net-03-the-last-transmission:dev

curl http://127.0.0.1:8080/health
curl -OJ http://127.0.0.1:8080/download
```

Local compose (development only, stricter sandbox):

```bash
docker compose up --build
```

## Runtime generation behaviour

1. Reject a missing, empty or blank `GZCTF_FLAG`.
2. Build the ZIP in memory and validate it.
3. Assemble DNS, HTTP, FTP control and FTP data packets on one clock.
4. Write to a temporary file, re-read with Scapy and validate 13 properties —
   including that the FTP data payload equals the archive and that no plaintext
   flag appears in DNS, HTTP or FTP control.
5. Publish atomically as `capture.pcap` (mode 0644).
6. `unset GZCTF_FLAG`, then start the HTTP server.

If any check fails the container exits non-zero and `/health` never becomes
ready.

## Testing

```bash
./tests/run-tests.sh                      # 8 suites
python3 tests/gzctf_e2e.py --base-url http://127.0.0.1:3000 \
  --admin-user Admin --admin-pass '<password>' \
  --image net-03-the-last-transmission:dev
```

Executed results are in [docs/testing.md](docs/testing.md).

## Documentation

* [docs/challenge.md](docs/challenge.md) — organizer metadata, description, hints, learning objectives
* [docs/writeup.md](docs/writeup.md) — full investigation, filters, tshark workflow, common mistakes
* [docs/deployment.md](docs/deployment.md) — GZ::CTF configuration, limits, troubleshooting
* [docs/testing.md](docs/testing.md) — executed test report
