# WEB-05 — The Internal Gateway

| | |
|---|---|
| Category | Web Exploitation |
| Difficulty | Hard |
| Points | 300 |
| Flag format | `AXUM{...}` |
| Platform | GZ::CTF 1.9.x, `DynamicContainer` |
| Per-team flag | Yes (`GZCTF_FLAG`) |
| Vulnerability | Response-based SSRF in a URL preview feature |
| Authentication | Not required |
| Expected solve time | 35–50 minutes |

> **Warning:** this application intentionally proxies server-side requests to
> arbitrary destinations. It is competition material and must never be deployed
> as a real service.

## Overview

Meridian Technologies runs an **Integration Console**: an enterprise portal used
to preview remote endpoints before connecting them to internal systems. The
preview is performed by the gateway process, not by the browser, and there is no
destination allowlist — which makes it a textbook SSRF primitive.

The flag lives in a diagnostics record served by an internal API that binds
`127.0.0.1:9000` inside the same container. That API is never published and is
unreachable from a browser or from any other container.

## Deployment topology (verified)

GZ::CTF 1.9.1 supports **one image and one exposed port per dynamic container**:

```csharp
// src/GZCTF/Models/Internal/ContainerConfig.cs
public string Image { get; set; } = string.Empty;
public int ExposedPort { get; set; }
```

There is no multi-container or compose field on `ChallengeType`
(`StaticAttachment`, `StaticContainer`, `DynamicAttachment`, `DynamicContainer`
only). The challenge therefore uses the **single-container, two-process
fallback**:

```text
participant
    |  HTTP (published port)
    v
gateway            0.0.0.0:3000   <- the only process that talks to players
    |  HTTP
    v
internal API       127.0.0.1:9000 <- holds GZCTF_FLAG, never published
```

`entrypoint.sh` starts the internal process with `GZCTF_FLAG` in its
environment, waits for `/internal/health`, then `unset GZCTF_FLAG` and starts the
gateway, which consequently never inherits the flag. Either process exiting
stops the other.

## Layout

```text
web-05-the-internal-gateway/
├── challenge.yml          # authoritative GZ::CTF value set (no flag)
├── README.md
├── source/
│   ├── Dockerfile         # node:22-alpine, non-root, no EXPOSE
│   ├── entrypoint.sh      # flag injection, readiness, supervision
│   ├── gateway/           # public Express application (port 3000)
│   ├── internal/          # diagnostics HTTP service (127.0.0.1:9000)
│   └── public/            # participant portal (HTML/CSS/JS)
├── tests/
│   ├── run-local-docker-tests.sh
│   ├── gzctf_e2e.py
│   └── fixtures/upstream-server.js
└── organizer/
    ├── WRITEUP.md
    ├── SOLUTION.md
    ├── DEPLOYMENT.md
    └── TESTING.md
```

## Quick start

```bash
cd source
docker build -t web-05-internal-gateway:dev .

docker run --rm -d --name web-05 \
  -e 'GZCTF_FLAG=AXUM{local_test_flag}' \
  -p 127.0.0.1:3000:3000 \
  web-05-internal-gateway:dev

curl http://127.0.0.1:3000/health
```

Then open <http://127.0.0.1:3000>, or reproduce the solve path directly:

```bash
curl -s -X POST http://127.0.0.1:3000/api/integrations/preview \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://127.0.0.1:9000/internal/diagnostics/record"}'
```

## Testing

```bash
./tests/run-local-docker-tests.sh      # 66 local checks
python3 tests/gzctf_e2e.py --base-url http://127.0.0.1:3000 \
  --admin-user Admin --admin-pass '<password>' \
  --image web-05-internal-gateway:dev
```

Results for both runs are recorded in [organizer/TESTING.md](organizer/TESTING.md).

## Documentation

* [organizer/WRITEUP.md](organizer/WRITEUP.md) — design, root cause, verified request sequence, remediation
* [organizer/SOLUTION.md](organizer/SOLUTION.md) — condensed solve guide
* [organizer/DEPLOYMENT.md](organizer/DEPLOYMENT.md) — build, GZ::CTF configuration, troubleshooting
* [organizer/TESTING.md](organizer/TESTING.md) — executed test results
