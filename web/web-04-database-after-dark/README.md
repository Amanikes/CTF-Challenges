# WEB-04 — Database After Dark

| | |
|---|---|
| Category | Web Exploitation |
| Difficulty | Easy |
| Points | 100 |
| Flag format | `AXUM{...}` |
| Platform | GZ::CTF 1.9.x, `DynamicContainer` |
| Per-team flag | Yes (`GZCTF_FLAG`) |
| Vulnerability | SQL injection (CWE-89), UNION-based |
| Expected solve time | 15–25 minutes |

> **Warning:** this application is intentionally vulnerable. The `category`
> query parameter is concatenated straight into a SQL statement and must only be
> run for the competition, never as a real inventory service.

## Overview

Blackstone Commerce is a small Express + SQLite inventory portal. Participants
browse a catalogue of twelve products and may filter by category. The public
keyword search is parameterised; the category filter is not, which allows a
UNION-based injection against the projected four columns and exposes the
`internal_records` table — including the runtime-injected flag.

Data model created at container start:

| Table | Contents |
|---|---|
| `products` | 12 public catalogue rows (`id, name, category, description, price, stock`) |
| `internal_records` | one restricted deployment record; its `flag` column holds `GZCTF_FLAG` |

The search endpoint projects `id, name, category, description` — four columns,
matching the four columns of the injected row.

## Project layout

```
web-04-database-after-dark/
├── README.md
├── challenge.yml                 # deployment values mapped to GZ::CTF fields
├── source/
│   ├── Dockerfile
│   ├── .dockerignore
│   ├── package.json
│   ├── package-lock.json
│   ├── entrypoint.sh
│   ├── src/
│   │   ├── server.js             # routes, fail-closed flag check
│   │   ├── database.js           # schema, seed data, flag injection
│   │   ├── products.js           # parameterised catalogue queries
│   │   └── search.js             # ⚠ intentional SQL injection
│   └── public/                   # catalogue UI (grid + table views)
├── organizer/                    # ⚠ spoilers — never ship to players
│   ├── WRITEUP.md
│   ├── SOLUTION.md
│   └── QA-CHECKLIST.md
└── tests/
    ├── run-local-docker-tests.sh
    └── gzctf_e2e.py
```

## Prerequisites

* Node.js 22+ (Docker image uses `node:22-alpine`)
* Docker (for the container workflow)
* `curl` and Python 3 for the test scripts

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `GZCTF_FLAG` | yes | Per-team flag injected by GZ::CTF. Startup aborts with status 1 when it is missing, empty, or whitespace-only. |
| `PORT` | no | Listen port, default `3000`. Keep it equal to the platform's *Service Port*. |
| `DB_PATH` | no | SQLite file, default `/app/data/inventory.db`. |

## Build and run locally

```bash
cd source
docker build -t web-04-database-after-dark:dev .

docker run --rm -d --name web04 \
  -e 'GZCTF_FLAG=AXUM{local_test_flag}' \
  -p 127.0.0.1:3000:3000 \
  web-04-database-after-dark:dev
```

Open <http://127.0.0.1:3000/>.

Without Docker:

```bash
cd source
npm ci
GZCTF_FLAG='AXUM{local_test_flag}' PORT=3000 npm start
```

`better-sqlite3` is a native module: the image installs `python3`, `make`, and
`g++` in the build stage so `node-gyp` can compile it. Those build tools are not
present in the runtime stage.

## Endpoints

| Method | Path | Notes |
|---|---|---|
| GET | `/` | catalogue UI |
| GET | `/api/products` | 12 catalogue rows |
| GET | `/api/products/search?q=` | parameterised keyword search |
| GET | `/api/products/search?category=` | ⚠ concatenated filter (injectable) |
| GET | `/api/categories` | distinct category names |
| GET | `/health`, `/healthz` | `{"status":"ok","service":"blackstone-inventory"}` |

Unmatched `GET` paths fall through to the catalogue shell, so `/api/<unknown>`
returns the HTML page rather than JSON. This is the SPA fallback and is not part
of the challenge.

## Tests

```bash
./tests/run-local-docker-tests.sh          # functional + injection + security + isolation
python3 tests/gzctf_e2e.py --help          # two-team platform validation
```

Executed results are recorded in [organizer/QA-CHECKLIST.md](organizer/QA-CHECKLIST.md).

## Documentation

* [organizer/WRITEUP.md](organizer/WRITEUP.md) — vulnerability, exploit, remediation
* [organizer/SOLUTION.md](organizer/SOLUTION.md) — step-by-step solve
* [organizer/QA-CHECKLIST.md](organizer/QA-CHECKLIST.md) — executed checks and results

## Deliberate limitations

The SQLite database is deleted and recreated on every container start so each
team instance begins from identical seed data and cannot inherit another team's
state. That is safe because a GZ::CTF instance is a single ephemeral container;
a real deployment would use a migration path instead of dropping the file.
