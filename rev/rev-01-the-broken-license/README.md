# REV-01 — The Broken License

| | |
|---|---|
| Category | Reverse Engineering |
| Difficulty | Easy |
| Points | 100 |
| Flag format | `AXUM{...}` |
| Platform | GZ::CTF 1.9.x, `DynamicContainer` |
| Per-team flag | Yes (`GZCTF_FLAG`) |
| Technique | Repeating-key XOR |
| Guidance | Guided (3 hints) |
| Expected solve time | 10–20 minutes |

> **Warning:** this challenge is deliberately reversible by design. It is
> competition material and must never be presented as a real licensing scheme.

## Overview

Northstar Systems recovered a legacy Linux licensing utility. Participants
download a per-team ZIP containing an ELF64 executable and its encoded
`license.dat`, then recover the accepted license key — which is the team's
dynamic GZ::CTF flag.

The accepted key is never stored in the binary. The executable holds only the
fixed XOR key; `license.dat` holds the encoded license.

## Architecture

```text
GZ::CTF dynamic flag (per team)
        |
        v
container start -> generate-artifact.js
        |              |  XOR-encode the flag with the fixed key
        |              v
        |        license.dat (encoded bytes only)
        |              |
        |              v
        |        northstar-license-package.zip
        v
download service (Express, port 3000)  <- never receives the flag
        |
        v
participant -> unzip -> reverse -> recovered key -> submit
```

The generator runs once, inherits `GZCTF_FLAG`, packages the archive and exits.
`entrypoint.sh` then `unset`s the variable and starts the download service, so
the long-lived HTTP process never holds the flag.

## Layout

```text
rev-01-the-broken-license/
├── challenge.yml              # authoritative GZ::CTF value set (no flag)
├── README.md
├── source/
│   ├── Dockerfile             # alpine build stage + node:22-alpine runtime
│   ├── entrypoint.sh          # flag validation, generation, then server
│   ├── server.js              # download service (/ /download /health)
│   ├── src/
│   │   ├── northstar-license.c
│   │   └── northstar_xor.h    # key literal + documented spec
│   ├── shared/xor-spec.json   # authoritative key, limits, test vector
│   ├── scripts/generate-artifact.js
│   ├── package/README.txt     # participant-facing readme in the ZIP
│   └── public/                # download page
├── tests/
│   ├── run-local-docker-tests.sh
│   ├── recover-flag.py        # independent static recovery
│   └── gzctf_e2e.py
└── organizer/
    ├── WRITEUP.md
    ├── SOLUTION.md
    ├── DEPLOYMENT.md
    └── TESTING.md
```

## Quick start

```bash
cd source
docker build -t rev-01-broken-license:dev .

docker run --rm -d --name rev-01 \
  -e 'GZCTF_FLAG=GZCTF{local_test_flag}' \
  -p 127.0.0.1:3000:3000 \
  rev-01-broken-license:dev

curl http://127.0.0.1:3000/health
curl -OJ http://127.0.0.1:3000/download
```

Recover the key the way a participant would:

```bash
unzip northstar-license-package.zip
cd northstar-license-package
python3 ../../tests/recover-flag.py --binary northstar-license --data license.dat
# xor key recovered : NorthstarK3y (12 bytes)
# accepted license  : GZCTF{local_test_flag}
```

## The transformation

```
C[i] = P[i] XOR K[i % n]
P[i] = C[i] XOR K[i % n]
```

* `K` — fixed key, `NorthstarK3y`, compiled into the executable as a C string
  literal and therefore visible in `.rodata`.
* `P` — the plaintext license (the team's dynamic flag).
* `C` — the bytes stored in `license.dat`.

The authoritative copy of the key, the maximum length (128 bytes) and a test
vector live in [source/shared/xor-spec.json](source/shared/xor-spec.json). The
local suite asserts that the compiled binary accepts data encoded with those
bytes, so a mismatch fails before deployment.

## Testing

```bash
./tests/run-local-docker-tests.sh            # 66 checks
python3 tests/gzctf_e2e.py --base-url http://127.0.0.1:3000 \
  --admin-user Admin --admin-pass '<password>' \
  --image rev-01-broken-license:dev
```

Results for both runs are recorded in [organizer/TESTING.md](organizer/TESTING.md).

## Documentation

* [organizer/WRITEUP.md](organizer/WRITEUP.md) — analysis, key location, recovery script, verify steps
* [organizer/SOLUTION.md](organizer/SOLUTION.md) — condensed solve guide
* [organizer/DEPLOYMENT.md](organizer/DEPLOYMENT.md) — build, GZ::CTF configuration, troubleshooting
* [organizer/TESTING.md](organizer/TESTING.md) — executed test results
