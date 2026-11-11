# REV-02 — Phantom Protocol

| | |
|---|---|
| Category | Reverse Engineering |
| Difficulty | Hard |
| Points | 300 |
| Flag format | `AXUM{...}` |
| Platform | GZ::CTF 1.9.x, `DynamicContainer` |
| Per-team flag | Yes (`GZCTF_FLAG`) |
| Technique | Reversible multi-stage transformation (add → XOR → rotate) |
| Guidance | Moderate (3 hints) |
| Expected solve time | 30–45 minutes |

> **Warning:** this challenge is deliberately reversible by design. It is
> competition material and must never be presented as a real licensing or
> authentication scheme.

## Overview

Aegis Communications decommissioned its Phantom Protocol access pilot. A field
intercept recovered the client binary and the protocol data file it consumes,
but the accepted access token is not recorded anywhere.

The token is the team's dynamic GZ::CTF flag. It appears only inside
`protocol.dat`, transformed by three reversible stages. Participants reverse the
client to recover it.

```text
GZ::CTF flag (per team) → generate_package.py → add → XOR → rotate
        → protocol.dat (inside the ZIP) → participant analysis → token → submit
```

## Transformation

| Stage | Forward | Inverse |
|---|---|---|
| 1 | `b[i] = b[i] + (0x2B + 7*i) mod 256` | `b[i] = b[i] - (0x2B + 7*i) mod 256` |
| 2 | `b[i] = b[i] XOR KEY[i mod 16]` | same (XOR is its own inverse) |
| 3 | `b[i] = rotl8(b[i], (3 + 5*i) mod 8)` | `b[i] = rotr8(b[i], (3 + 5*i) mod 8)` |

`KEY = "AegisPhantomKey!"`, compiled into the executable at `0x408290`. The
inverse is applied in reverse stage order: rotate → XOR → subtract.

## Protocol data format

| Offset | Size | Field |
|---|---|---|
| `0x00` | 4 | magic `PHTM` |
| `0x04` | 1 | version `1` |
| `0x05` | 1 | payload length (`1..128`) |
| `0x06` | 2 | reserved, must be zero |
| `0x08` | *n* | transformed payload |

The client rejects a wrong magic, unsupported version, zero or excessive length,
non-zero reserved bytes, truncated files and trailing bytes, all with one generic
message.

## Layout

```text
rev-02-phantom-protocol/
├── challenge.yml              # authoritative GZ::CTF value set (no flag)
├── README.md
├── Dockerfile                 # alpine build stage + node:22-alpine runtime
├── entrypoint.sh              # flag validation, generation, then download service
├── src/phantom_client.c
├── generator/generate_package.py
├── server/{package.json,server.js}
├── public/{index.html,styles.css,favicon.svg}
├── package/README.txt         # participant README placed inside the ZIP
├── scripts/verify_solution.py # organizer recovery
├── tests/
│   ├── support.py
│   ├── test_generation.py
│   ├── test_validation.py
│   ├── test_isolation.py
│   ├── test_security.py
│   ├── gzctf_e2e.py
│   └── run-tests.sh
└── organizer/
    ├── WRITEUP.md
    ├── TESTING.md
    └── DEPLOYMENT.md
```

## Build and run

```bash
docker build -t rev-02-phantom-protocol:dev .

docker run --rm -d --name rev-02 \
  -e 'GZCTF_FLAG=AXUM{local_test_token}' \
  -p 127.0.0.1:3000:3000 \
  rev-02-phantom-protocol:dev

curl http://127.0.0.1:3000/health
curl -OJ http://127.0.0.1:3000/download
```

Organizer recovery against the downloaded package:

```bash
python3 scripts/verify_solution.py --archive phantom-protocol-package.zip
# recovered token  : AXUM{local_test_token}
```

## Tests

```bash
./tests/run-tests.sh                                   # 44 tests across 4 suites
python3 tests/gzctf_e2e.py --base-url http://127.0.0.1:3000 \
  --admin-user Admin --admin-pass '<password>' \
  --image rev-02-phantom-protocol:dev
```

Executed results are recorded in [organizer/TESTING.md](organizer/TESTING.md).

## Documentation

* [organizer/WRITEUP.md](organizer/WRITEUP.md) — analysis, constants, inverse pipeline, recovery script, lessons
* [organizer/DEPLOYMENT.md](organizer/DEPLOYMENT.md) — build, GZ::CTF configuration, troubleshooting
* [organizer/TESTING.md](organizer/TESTING.md) — executed test results
