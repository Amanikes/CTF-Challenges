# WEB-05 — Deployment

Verified against GZ::CTF **1.9.1** (`23ccbbaa`) with the Docker container
provider and `PortMappingType: Default`.

## 1. Prerequisites

* GZ::CTF with the Docker container provider.
* A registry the platform can pull from (or a local image on the platform host).
* No extra privileges: the container runs as UID 1000 with no mounts, no
  capabilities and no Docker socket access.
* `ContainerProvider.PublicEntry` set to the address players use to reach the
  platform host (recommended, see section 6).

## 2. Build and publish

```bash
cd source
docker build -t registry.axumsec.example/ctf/web-05-internal-gateway:1.0.0 .
docker push registry.axumsec.example/ctf/web-05-internal-gateway:1.0.0
```

The image contains no flag, so it is built once and reused for the whole event.
Do not pass `GZCTF_FLAG` as a build argument.

Multi-architecture:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t registry.axumsec.example/ctf/web-05-internal-gateway:1.0.0 --push .
```

## 3. Runtime environment

| Variable | Default | Meaning |
|---|---|---|
| `GZCTF_FLAG` | — (required) | Injected by GZ::CTF. Consumed only by the internal process; the entrypoint removes it before starting the gateway. Startup fails if it is missing or blank. |
| `PORT` | `3000` | Gateway listen port. Must match the challenge's *Service Port*. |
| `INTERNAL_PORT` | `9000` | Internal diagnostics port, bound to `127.0.0.1`. |

Only `PORT` is published. `INTERNAL_PORT` never leaves the container.

## 4. Local run

```bash
cd source
docker build -t web-05-internal-gateway:dev .

docker run --rm -d --name web-05 \
  -e 'GZCTF_FLAG=AXUM{local_test_flag}' \
  -p 127.0.0.1:3000:3000 \
  web-05-internal-gateway:dev

curl http://127.0.0.1:3000/health
docker logs web-05
docker stop web-05
```

Smoke-test the intended path:

```bash
curl -s -X POST http://127.0.0.1:3000/api/integrations/preview \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://127.0.0.1:9000/internal/diagnostics/record"}' \
  | jq -r '.body' | jq -r '.record.verification_token'
# AXUM{local_test_flag}
```

## 5. Configure the challenge in the admin UI

1. **Admin → Games → New Game** (or reuse the event game). The game must be
   running, or Practice Mode must be enabled, for containers to launch.
2. Inside the game, **Add Challenge**:
   * Title: `The Internal Gateway`
   * Category: `Web`
   * Type: **DynamicContainer** (fixed at creation time)
3. Fill in the editor:

| UI field (en-US) | Value |
|---|---|
| Challenge Content | the description from `challenge.yml` → `public.description` |
| Score | `300` |
| Minimum Score Ratio | `1.0` |
| Difficulty Factor | `1.0` (score coefficient, not the display difficulty) |
| Flag Template | `AXUM{internal_gateway_[TEAM_HASH]}` |
| Container Image | `registry.axumsec.example/ctf/web-05-internal-gateway:1.0.0` |
| Service Port | `3000` |
| Memory Limit (MB) | `128` |
| CPU Limit (0.1 CPUs) | `1` |
| Storage Limit (MB) | `64` |
| Network Mode | `Open` |
| Traffic Capture | off |
| Hints | the three markdown hints from `challenge.yml` → `public.hints` |

4. Enable the challenge. GZ::CTF creates one `GameInstance` per participating
   team and injects a distinct `GZCTF_FLAG` into each container.

Do **not** add static flags to a DynamicContainer challenge.

### Equivalent API calls

```bash
# create the game
curl -sb cookies.txt -H 'Content-Type: application/json' \
  -X POST http://<platform>/api/Edit/Games -d '{
    "title": "AxumSec Web Exploitation",
    "hidden": false,
    "summary": "",
    "content": "",
    "acceptWithoutReview": true,
    "practiceMode": true,
    "start": "2026-11-10T00:00:00Z",
    "end": "2026-11-17T00:00:00Z",
    "teamMemberCountLimit": 0,
    "containerCountLimit": 3,
    "bloodBonus": 0
  }'

# create the challenge (type is fixed here)
curl -sb cookies.txt -H 'Content-Type: application/json' \
  -X POST http://<platform>/api/Edit/Games/<gameId>/Challenges \
  -d '{"title":"The Internal Gateway","category":"Web","type":"DynamicContainer"}'

# configure and enable it
curl -sb cookies.txt -H 'Content-Type: application/json' \
  -X PUT http://<platform>/api/Edit/Games/<gameId>/Challenges/<challengeId> -d '{
    "title": "The Internal Gateway",
    "content": "Meridian integration console endpoint preview.",
    "category": "Web",
    "flagTemplate": "AXUM{internal_gateway_[TEAM_HASH]}",
    "hints": [
      "**Hint 1 — The preview**\n\nThe preview feature does more than validate a URL. Pay attention to where the request is actually performed.",
      "**Hint 2 — The network boundary**\n\nA service that your browser cannot reach may still be reachable from the server handling your request.",
      "**Hint 3 — The internal API**\n\nInvestigate the HTTP services accessible from the gateway. Look for diagnostics-related routes and inspect their JSON responses."
    ],
    "isEnabled": true,
    "containerImage": "registry.axumsec.example/ctf/web-05-internal-gateway:1.0.0",
    "exposePort": 3000,
    "memoryLimit": 128,
    "cpuCount": 1,
    "storageLimit": 64,
    "networkMode": "Open",
    "enableTrafficCapture": false,
    "originalScore": 300,
    "minScoreRate": 1.0,
    "difficulty": 1.0,
    "submissionLimit": 0
  }'
```

Smoke-test the image before the game opens:

```bash
curl -sb cookies.txt -X POST \
  http://<platform>/api/Edit/Games/<gameId>/Challenges/<challengeId>/Container
```

## 6. Port conventions and public entry

The image declares **no `EXPOSE`**: GZ::CTF maps `Service Port` (`3000`) to a
random host port per instance, and extra declarations would reserve ports for
every dynamic container.

`ContainerProvider.PublicEntry` (in `appsettings.json`) controls the address
shown to players:

```json
{
  "ContainerProvider": {
    "PublicEntry": "ctf.axumsec.example"
  }
}
```

Verified behaviour in 1.9.1: `Container.Entry` is
`${PublicEntry ?? containerIP}:${PublicPort ?? port}`. With `PublicEntry` empty
the platform reports the container network address combined with the published
host port, which is not reachable from outside. Always set it for an event.

## 7. Internal service topology

```text
container
├── gateway        node /app/gateway/server.js     0.0.0.0:3000  (published)
└── internal API   node /app/internal/server.js    127.0.0.1:9000 (loopback only)
```

* `entrypoint.sh` starts the internal service with `GZCTF_FLAG`, polls
  `/internal/health` until it answers, then `unset GZCTF_FLAG` and starts the
  gateway.
* If either process exits, the other is terminated and the container exits
  non-zero; `SIGTERM`/`SIGINT` are forwarded to both.
* The internal service is unreachable from other containers on the same Docker
  network because it binds loopback (verified).

## 8. Resource and isolation requirements

| Resource | Value |
|---|---|
| CPU | 1 × 0.1 = 0.1 CPU |
| Memory | 128 MB |
| Storage | 64 MB |
| Network mode | `Open` (only port 3000 published) |
| Traffic capture | off |

No Docker socket, no host mounts, no privileged mode, no host networking.

## 9. Verify the deployment

```bash
python3 tests/gzctf_e2e.py \
  --base-url https://ctf.axumsec.example \
  --admin-user <admin> --admin-pass '<password>' \
  --image registry.axumsec.example/ctf/web-05-internal-gateway:1.0.0
```

The script creates a throw-away game, registers two players, starts one
container per team, performs the full SSRF solve path against each instance,
asserts the flags differ and match `AXUM{internal_gateway_<12 hex>}`, submits
each team's own flag (must be `Accepted`) and the opposite team's flag (must be
rejected), then deletes the game.

## 10. Reset and redeploy

* **One team:** player UI → *Destroy* then *Launch*, or
  `DELETE /api/Game/<gameId>/Container/<challengeId>` followed by
  `POST /api/Game/<gameId>/Container/<challengeId>`. The record is rebuilt from
  the injected flag on every start.
* **Everything:** disable and re-enable the challenge, then relaunch.
* **New image version:** push a new tag, update *Container Image*, destroy and
  relaunch instances. The challenge keeps no persistent state.

## 11. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Container shows "Container Config Error" | `Container Image` or `Service Port` is empty. |
| "Challenge flag too trivial" on save | The template must contain `[TEAM_HASH]` or `[GUID]`. |
| Container exits immediately, log shows `GZCTF_FLAG is missing` | The challenge is not a `DynamicContainer`, or the platform did not inject the flag. |
| Portal loads but every preview returns `502 request_failed` | Upstream unreachable from the container; for internal URLs check the internal process is running (`docker logs`). |
| Internal probe returns `ECONNREFUSED` | `INTERNAL_PORT` changed without updating the probe URL in `gateway/routes/integrations.js`. |
| Entry URL reports a `172.x` address | `ContainerProvider.PublicEntry` is not configured. |
| Container stays `Pending` | The platform cannot pull the image; check the tag and platform logs. |

## 12. Unverified platform details

The following were **not** re-verified for this challenge and should be checked
before a live event:

* Kubernetes provider behaviour for the two-process container (expected to work
  unchanged, since the topology is internal to one pod, but not executed here).
* Traffic-capture proxy behaviour with `networkMode: Open` — capture is disabled
  for this challenge, so it was not exercised.
