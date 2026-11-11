# NET-01 — Deployment

Verified against GZ::CTF **1.9.1** (`23ccbbaa`) with the Docker container
provider and `PortMappingType: Default`.

## 1. Prerequisites

* GZ::CTF with the Docker container provider.
* A registry the platform can pull from (or a local image on the platform host).
* No extra privileges: the container runs as UID 1000, with no added
  capabilities (`NET_ADMIN` / `NET_RAW` are neither requested nor granted), no
  mounts and no Docker socket.

## 2. Build and publish

```bash
docker build -t registry.axumsec.example/ctf/net-01-unencrypted-secrets:1.0.0 .
docker push registry.axumsec.example/ctf/net-01-unencrypted-secrets:1.0.0
```

The image contains no flag and is built once for the whole event. Do not pass
`GZCTF_FLAG` as a build argument.

| Stage | Base | Purpose |
|---|---|---|
| `deps` | `node:22-alpine` | production dependencies via `npm ci` |
| runtime | `node:22-alpine` + `python3`, `py3-pip`, `scapy==2.8.0` | capture generator + download service |

## 3. Runtime flow

| Step | Action |
|---|---|
| 1 | Reject a missing, empty or blank `GZCTF_FLAG` |
| 2 | `python3 scripts/generate_capture.py --output $RUNTIME_DIR/meridian-traffic.pcap` |
| 3 | The generator builds and **validates** the capture; exit code ≠ 0 aborts the container |
| 4 | The generator pops `GZCTF_FLAG` from its own environment and exits |
| 5 | `unset GZCTF_FLAG` |
| 6 | `exec node server/server.js` — the service starts only after step 3 succeeded |

## 4. Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `GZCTF_FLAG` | — (required) | Injected by GZ::CTF. Used only by the generator. |
| `PORT` | `3000` | Download service port. Must match the challenge *Service Port*. |
| `RUNTIME_DIR` | `/app/runtime` | Capture output directory; must be writable by UID 1000. |

## 5. Local run

```bash
docker build -t net-01-unencrypted-secrets:dev .

docker run --rm -d --name net-01 \
  -e 'GZCTF_FLAG=GZCTF{NET01_TEST_FLAG}' \
  -p 127.0.0.1:3000:3000 \
  net-01-unencrypted-secrets:dev

curl http://127.0.0.1:3000/health
curl -OJ http://127.0.0.1:3000/download
tcpdump -nn -A -r meridian-traffic.pcap | grep X-Meridian-Session
docker logs net-01
```

Expected log lines (no flag anywhere):

```text
[meridian-capture] wrote meridian-traffic.pcap (10475 bytes, 74 packets, 8 DNS, 64 TCP, 15 HTTP payloads)
[meridian-download] listening on http://0.0.0.0:3000
```

## 6. Download service

| Route | Behaviour |
|---|---|
| `GET /` | Landing page |
| `GET /download` | Fixed path `/app/runtime/meridian-traffic.pcap`, `application/vnd.tcpdump.pcap`, attachment filename `meridian-traffic.pcap` |
| `GET /health` | `200` + `capture: ready`, or `503` + `capture: missing` |
| `GET /assets/*` | Static CSS/favicon only |

No directory listing, no path parameters, no environment inspection, no debug
route and no flag route.

## 7. Port conventions and public entry

The image declares **no `EXPOSE`**: GZ::CTF maps `Service Port` (`3000`) to a
random host port per instance. `ContainerProvider.PublicEntry` should be set:

```json
{
  "ContainerProvider": {
    "PublicEntry": "ctf.axumsec.example"
  }
}
```

Verified behaviour in 1.9.1: `Container.Entry` is
`${PublicEntry ?? containerIP}:${PublicPort ?? port}`; without it the reported
address is not reachable from outside.

## 8. Configure the challenge in the admin UI

1. **Admin → Games → New Game** (or reuse the event game). The game must be
   running, or Practice Mode enabled, for containers to launch.
2. Inside the game, **Add Challenge**:
   * Title: `Unencrypted Secrets`
   * Category: **Forensics** (documented deviation — 1.9.1 has no Network
     category; `Forensics` is the closest verified value)
   * Type: **DynamicContainer** (fixed at creation time)
3. Fill in:

| UI field (en-US) | Value |
|---|---|
| Challenge Content | the description from `challenge.yml` → `public.description` |
| Score | `100` |
| Minimum Score Ratio | `1.0` |
| Difficulty Factor | `1.0` (score coefficient, not the display difficulty) |
| Flag Template | `AXUM{unencrypted_secrets_[TEAM_HASH]}` |
| Container Image | `registry.axumsec.example/ctf/net-01-unencrypted-secrets:1.0.0` |
| Service Port | `3000` |
| Memory Limit (MB) | `128` |
| CPU Limit (0.1 CPUs) | `1` |
| Storage Limit (MB) | `64` |
| Network Mode | `Open` |
| Traffic Capture | off |
| Hints | the three markdown hints from `challenge.yml` → `public.hints` |

### Equivalent API calls

```bash
curl -sb cookies.txt -H 'Content-Type: application/json' \
  -X POST http://<platform>/api/Edit/Games -d '{
    "title": "AxumSec Network Analysis",
    "hidden": false, "summary": "", "content": "",
    "acceptWithoutReview": true, "practiceMode": true,
    "start": "2026-11-10T00:00:00Z", "end": "2026-11-17T00:00:00Z",
    "teamMemberCountLimit": 0, "containerCountLimit": 3, "bloodBonus": 0
  }'

curl -sb cookies.txt -H 'Content-Type: application/json' \
  -X POST http://<platform>/api/Edit/Games/<gameId>/Challenges \
  -d '{"title":"Unencrypted Secrets","category":"Forensics","type":"DynamicContainer"}'

curl -sb cookies.txt -H 'Content-Type: application/json' \
  -X PUT http://<platform>/api/Edit/Games/<gameId>/Challenges/<challengeId> -d '{
    "title": "Unencrypted Secrets",
    "content": "Meridian Logistics traffic capture review.",
    "category": "Forensics",
    "flagTemplate": "AXUM{unencrypted_secrets_[TEAM_HASH]}",
    "hints": [
      "**Hint 1 — Identify the protocol**\n\nStart by identifying the protocols present in the capture. Look for traffic that is not protected by TLS.",
      "**Hint 2 — Inspect HTTP communication**\n\nWireshark can filter HTTP requests and display their headers. Look for communication involving the Meridian portal.",
      "**Hint 3 — Follow the stream**\n\nThe information you need is part of an HTTP request header. Following the relevant TCP stream should make it easier to inspect."
    ],
    "isEnabled": true,
    "containerImage": "registry.axumsec.example/ctf/net-01-unencrypted-secrets:1.0.0",
    "exposePort": 3000, "memoryLimit": 128, "cpuCount": 1, "storageLimit": 64,
    "networkMode": "Open", "enableTrafficCapture": false,
    "originalScore": 100, "minScoreRate": 1.0, "difficulty": 1.0, "submissionLimit": 0
  }'
```

Smoke test before the game opens:

```bash
curl -sb cookies.txt -X POST \
  http://<platform>/api/Edit/Games/<gameId>/Challenges/<challengeId>/Container
```

## 9. Per-team isolation

* One container per team, each with its own `GZCTF_FLAG`.
* The capture is generated inside the container, so each team downloads a
  different PCAP.
* The download service holds no flag and serves one fixed path.
* Cross-team submissions are rejected by the platform (verified).

## 10. Verify the deployment

```bash
python3 tests/gzctf_e2e.py \
  --base-url https://ctf.axumsec.example \
  --admin-user <admin> --admin-pass '<password>' \
  --image registry.axumsec.example/ctf/net-01-unencrypted-secrets:1.0.0
```

Creates a throw-away game, registers two players, starts one container per team,
downloads both captures, reassembles the target stream and extracts the header,
asserts the tokens differ and match `AXUM{unencrypted_secrets_<12 hex>}`,
submits each team's own token (`Accepted`) and the opposite team's token
(rejected), then deletes the game.

## 11. Reset and redeploy

* **One team:** player UI → *Destroy* then *Launch*; the capture is regenerated
  from the newly injected flag.
* **Everything:** disable and re-enable the challenge, then relaunch.
* **New image version:** push a new tag, update *Container Image*, destroy and
  relaunch instances.

## 12. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Container exits with `GZCTF_FLAG is missing or empty` | Challenge is not a `DynamicContainer`, or the platform injected nothing. |
| Log shows `flag length is outside the supported range` | Flag exceeded 200 bytes — shorten the template. |
| Log shows `capture validation failed: …` | The generator refused to serve an invalid capture; the message names the failing property. |
| `/health` returns 503 with `capture: missing` | Generation never ran or wrote elsewhere; check `RUNTIME_DIR`. |
| Download returns 404/503 | Wait for the health check to pass; the service starts only after generation. |
| Entry URL reports a `172.x` address | `ContainerProvider.PublicEntry` is not configured. |
| Participant sees no HTTP in Wireshark | They are probably filtering on `http` while Wireshark reassembly is disabled; the capture itself contains valid HTTP on port 80. |
| Container stays `Pending` | Platform cannot pull the image. |

## 13. Unverified platform details

* Kubernetes provider deployment — **NOT TESTED** (single-container topology).
* Traffic capture (`enableTrafficCapture: true`) — **NOT TESTED**; disabled by
  design and unnecessary for this challenge.
* `linux/arm64` image — **NOT TESTED**; the challenge targets x86_64 (the
  capture itself is architecture-independent, as the generator is pure Python).
