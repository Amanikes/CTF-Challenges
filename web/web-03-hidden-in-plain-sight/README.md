# WEB-03 — Hidden in Plain Sight

| | |
|---|---|
| Category | Web Exploitation |
| Difficulty | Easy |
| Points | 50 |
| Flag format | `AXUM{...}` |
| Platform | GZ::CTF 1.9.x, `DynamicContainer` |
| Per-team flag | Yes (`GZCTF_FLAG`) |
| Vulnerability | Client-side information disclosure / exposed internal API |
| Authentication | Not required |
| Expected solve time | 10–15 minutes |

> **Warning:** this application intentionally exposes an internal API endpoint.
> It is competition material and must never be deployed as a real service.

## Overview

Meridian Technologies runs a project-management portal. The dashboard looks like
an ordinary enterprise SaaS product and loads its JavaScript bundle with a
normal `<script src="/assets/app.js">` reference.

That bundle still carries a disabled *internal preview* client together with the
route it talks to. Nothing in the interface shows the route and the page never
calls it, but anyone who opens the bundle in DevTools can read it:

```
internalPreview: '/api/internal/project-preview'
```

Requesting that route returns the pre-release "Orion Internal Platform" record
and the per-team flag injected at container start.

| Surface | Behaviour |
|---|---|
| `/` | dashboard |
| `/assets/app.js` | public bundle, contains the internal route |
| `/assets/style.css` | styles |
| `/api/projects` | public portfolio data |
| `/api/internal/project-preview` | **intentionally exposed** internal record + flag |
| `/health` | minimal health status |

## Project layout

```
web-03-hidden-in-plain-sight/
├── README.md
├── challenge.yml                 # deployment values mapped to GZ::CTF fields
├── source/
│   ├── Dockerfile
│   ├── .dockerignore
│   ├── package.json
│   ├── package-lock.json
│   ├── entrypoint.sh
│   ├── src/
│   │   ├── server.js             # routes + intentional internal endpoint
│   │   └── data.js               # synthetic portfolio data
│   └── public/
│       ├── index.html
│       └── assets/
│           ├── app.js            # bundle containing the internal route
│           ├── style.css
│           └── favicon.svg
├── organizer/                    # ⚠ spoilers — never ship to players
│   ├── WRITEUP.md
│   ├── TESTING.md
│   └── DEPLOYMENT.md
├── release/
│   └── README.txt
└── tests/
    ├── run-local-docker-tests.sh
    ├── check-no-autoload.js
    └── gzctf_e2e.py
```

`organizer/` and `tests/` live outside `source/`, so they never enter the Docker
build context.

## Prerequisites

* Node.js 22+ (image uses `node:22-alpine`)
* Docker for the container workflow
* `curl` and Python 3 for the test scripts

## Runtime flag setup

| Variable | Required | Description |
|---|---|---|
| `GZCTF_FLAG` | yes | Per-team flag injected by GZ::CTF. The app exits with status 1 when it is missing or empty. |
| `PORT` | no | Listen port, default `3000`. Must match the platform's *Service Port*. |

The flag is read once at startup, kept in server memory, and returned only by
`/api/internal/project-preview`. It never appears in HTML, JS, CSS, source maps,
image layers, logs or `/health`.

## Build and run locally

```bash
cd source
docker build -t web-03-hidden-in-plain-sight:dev .

docker run --rm -d --name web03 \
  -e 'GZCTF_FLAG=AXUM{local_test_flag}' \
  -p 127.0.0.1:3000:3000 \
  web-03-hidden-in-plain-sight:dev
```

Open <http://127.0.0.1:3000/>. Without Docker:

```bash
cd source
npm ci
GZCTF_FLAG='AXUM{local_test_flag}' PORT=3000 npm start
```

## Tests

```bash
./tests/run-local-docker-tests.sh          # functional, leakage, isolation, security
node tests/check-no-autoload.js source/public/assets/app.js
python3 tests/gzctf_e2e.py --help          # two-team platform validation
```

Executed results are recorded in [organizer/TESTING.md](organizer/TESTING.md).

## Documentation

* [organizer/WRITEUP.md](organizer/WRITEUP.md) — vulnerability, solve path, remediation
* [organizer/TESTING.md](organizer/TESTING.md) — test cases and actual results
* [organizer/DEPLOYMENT.md](organizer/DEPLOYMENT.md) — GZ::CTF setup, port mapping, team isolation
* [release/README.txt](release/README.txt) — release note for packaging
