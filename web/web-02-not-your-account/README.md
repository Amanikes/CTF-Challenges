# WEB-02 — Not Your Account

| | |
|---|---|
| Category | Web Exploitation |
| Difficulty | Easy |
| Points | 50 |
| Flag format | `AXUM{...}` |
| Platform | GZ::CTF 1.9.x, `DynamicContainer` |
| Per-team flag | Yes (`GZCTF_FLAG`) |
| Vulnerability | IDOR / Broken Object-Level Authorization |
| Expected solve time | 10–20 minutes |

> **Warning:** this application is intentionally vulnerable. It contains an
> insecure direct object reference in the account API and must only be run for
> the competition, never as a real banking service.

## Overview

Northstar Bank's customer portal is a small Express application. Participants
sign in with the provided test account, browse their own dashboard, then notice
that `/api/accounts/<id>` performs no ownership check and read another
customer's account — which carries the runtime-injected flag.

Fictional accounts:

| Account | Customer | Purpose |
|---|---|---|
| 1001 | Alex Morgan | participant account (`alex` / `Northstar@2026`) |
| 1002 | Jordan Lee | target account, returns the dynamic flag |

## Project layout

```
web-02-not-your-account/
├── README.md
├── challenge.yml                 # deployment values mapped to GZ::CTF fields
├── source/
│   ├── Dockerfile
│   ├── package.json
│   ├── package-lock.json
│   ├── entrypoint.sh
│   ├── src/
│   │   ├── server.js             # routes + intentional IDOR handlers
│   │   ├── auth.js               # scrypt credentials, in-memory sessions
│   │   ├── accounts.js           # account store + flag injection
│   │   └── data.js               # fictional seed data
│   └── public/                   # login, dashboard, account, transactions
├── organizer/                    # ⚠ spoilers — never ship to players
│   ├── WRITEUP.md
│   ├── TESTING.md
│   └── DEPLOYMENT.md
├── release/
│   └── README.txt
└── tests/
    ├── run-local-docker-tests.sh
    └── gzctf_e2e.py
```

## Prerequisites

* Node.js 22+ (Docker image uses `node:22-alpine`)
* Docker (for the container workflow)
* `curl`, `unzip`/Python for the test scripts

## Environment variable

| Variable | Required | Description |
|---|---|---|
| `GZCTF_FLAG` | yes | Per-team flag injected by GZ::CTF. The app exits with status 1 when it is missing or empty. |
| `PORT` | no | Listen port, default `3000`. Use the same value as the platform's *Service Port*. |

## Build and run locally

```bash
cd source
docker build -t web-02-not-your-account:dev .

docker run --rm -d --name web02 \
  -e 'GZCTF_FLAG=AXUM{local_test_flag}' \
  -p 127.0.0.1:3000:3000 \
  web-02-not-your-account:dev
```

Open <http://127.0.0.1:3000/> and sign in with `alex` / `Northstar@2026`.

Without Docker:

```bash
cd source
npm ci
GZCTF_FLAG='AXUM{local_test_flag}' PORT=3000 npm start
```

## Tests

```bash
./tests/run-local-docker-tests.sh          # functional + security + isolation
python3 tests/gzctf_e2e.py --help          # two-team platform validation
```

Executed results are recorded in [organizer/TESTING.md](organizer/TESTING.md).

## Documentation

* [organizer/WRITEUP.md](organizer/WRITEUP.md) — vulnerability, exploit, remediation
* [organizer/TESTING.md](organizer/TESTING.md) — test cases and results
* [organizer/DEPLOYMENT.md](organizer/DEPLOYMENT.md) — GZ::CTF setup and team isolation
* [release/README.txt](release/README.txt) — release note for packaging

## Session-store limitation

Sessions live in an in-memory `Map` inside the Node process. That is deliberate:
each GZ::CTF instance is a single ephemeral container and sessions do not need to
survive a restart. A production deployment would use a shared store (Redis,
database) and would not keep sessions in process memory.
