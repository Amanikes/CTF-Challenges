# WEB-03 — Deployment (GZ::CTF 1.9.x)

Verified against GZ::CTF **1.9.1** (`23ccbbaa`) with the Docker container
provider and `PortMappingType: Default`. The conventions match WEB-01 and
WEB-02.

## 1. Build and publish the image

```bash
cd source
docker build -t registry.axumsec.example/ctf/web-03-hidden-in-plain-sight:1.0.0 .
docker push registry.axumsec.example/ctf/web-03-hidden-in-plain-sight:1.0.0
```

The image contains no flag, so it is safe to build once and reuse for the whole
event. Never pass `GZCTF_FLAG` as a build argument.

Multi-arch:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t registry.axumsec.example/ctf/web-03-hidden-in-plain-sight:1.0.0 --push .
```

## 2. Configure the challenge in the admin UI

1. **Admin → Games → New Game** (or the event game). The game must be running
   (current time inside `start`/`end`) for containers to launch.
2. Inside the game, **Add Challenge**:
   * Title: `Hidden in Plain Sight`
   * Category: `Web`
   * Type: **DynamicContainer** (type is fixed at creation)
3. In the challenge editor:

| UI field (en-US, 1.9.1) | Value |
|---|---|
| Challenge Content | participant description from `challenge.yml` |
| Score | `50` |
| Minimum Score Ratio | `1.0` |
| Difficulty Factor | `1.0` (score coefficient, not display difficulty) |
| Flag Template | `AXUM{hidden_in_plain_sight_[TEAM_HASH]}` |
| Container Image | `registry.axumsec.example/ctf/web-03-hidden-in-plain-sight:1.0.0` |
| Service Port | `3000` |
| Memory Limit (MB) | `128` |
| CPU Limit (0.1 CPUs) | `1` |
| Storage Limit (MB) | `64` |
| Network Mode | `Open` |
| Traffic Capture | off |

4. Enable the challenge. GZ::CTF creates one `GameInstance` per participating
   team, including teams that join later.

Do not add static flags to a DynamicContainer challenge.

### Equivalent API calls (executed)

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
  -d '{"title":"Hidden in Plain Sight","category":"Web","type":"DynamicContainer"}'

# configure and enable it
curl -sb cookies.txt -H 'Content-Type: application/json' \
  -X PUT http://<platform>/api/Edit/Games/<gameId>/Challenges/<challengeId> -d '{
    "title": "Hidden in Plain Sight",
    "content": "Meridian Technologies project portal.",
    "category": "Web",
    "flagTemplate": "AXUM{hidden_in_plain_sight_[TEAM_HASH]}",
    "isEnabled": true,
    "containerImage": "registry.axumsec.example/ctf/web-03-hidden-in-plain-sight:1.0.0",
    "exposePort": 3000,
    "memoryLimit": 128,
    "cpuCount": 1,
    "storageLimit": 64,
    "networkMode": "Open",
    "enableTrafficCapture": false,
    "originalScore": 50,
    "minScoreRate": 1.0,
    "difficulty": 1.0,
    "submissionLimit": 0
  }'
```

If **API Encryption** is enabled, password/flag fields must be encrypted with the
platform public key (`GET /api/Config` → `apiPublicKey`, X25519 + SHA-256 +
AES-GCM). The test instance had encryption disabled.

Smoke-test before the game opens:

```bash
curl -sb cookies.txt -X POST \
  http://<platform>/api/Edit/Games/<gameId>/Challenges/<challengeId>/Container
```

Destroy it with `DELETE /api/Edit/Games/<gameId>/Challenges/<challengeId>/Container`.

## 3. Port exposure

The image has **no `EXPOSE`**. GZ::CTF maps `Service Port` (`3000`) to a random
host port per instance, as the official templates recommend. The app listens on
`0.0.0.0:3000`; `PORT` can override it but must then match `Service Port`.

## 4. Public entry

Set `ContainerProvider.PublicEntry` in `appsettings.json` to the host players
use, e.g. `"PublicEntry": "ctf.axumsec.example"`.

`Container.Entry` is `${PublicIP ?? containerIP}:${PublicPort ?? port}`. Without
`PublicEntry` players see the container network address with the published port,
which is not usable from outside (the port itself is reachable on the platform
host — the e2e script falls back to it).

## 5. Runtime flag injection and team isolation

1. GZ::CTF derives the per-team flag from
   `AXUM{hidden_in_plain_sight_[TEAM_HASH]}` (12 hex characters).
2. On container start the platform sets `GZCTF_FLAG=<team flag>`.
3. `src/server.js` reads it once, exits with status 1 when missing, and stores it
   in the in-memory internal project record.
4. Only `GET /api/internal/project-preview` returns it.

Isolation is provided by the platform: every team gets its own container with
its own `GZCTF_FLAG`, and the app has no shared state or external storage.
Verified with two teams — see `organizer/TESTING.md` §5.

## 6. Recommended resource limits

| Resource | Value | Rationale |
|---|---|---|
| CPU | `1` (0.1 CPU) | static dashboard plus small JSON responses |
| Memory | `128 MB` | Node.js runtime plus Express |
| Storage | `64 MB` | nothing is written to disk |

## 7. Reset and redeploy

* **Restart one team's instance:** destroy and relaunch (UI, or
  `DELETE`/`POST /api/Game/<gameId>/Container/<challengeId>`). A new container
  receives the flag injected at start.
* **Restart all instances:** disable and re-enable the challenge.
* **Image update:** push a new tag, change *Container Image*, relaunch instances.
  The application is stateless.
* **Deleted game in 1.9.1:** database records are removed but running containers
  can survive until the manager reaps them; remove them explicitly with
  `docker ps --filter name=web-03-hidden-in-plain-sight_` when cleaning a host.

## 8. Packaging and import

GZ::CTF does not import challenge YAML. To hand the challenge over:

1. Ship this directory (without `organizer/` for players).
2. Build and push `source/` and record the tag.
3. Recreate the game/challenge with the values in `challenge.yml` (UI or API).
4. Optionally export the configured game from the platform (**Admin → Games →
   Export Game**), which produces a `GZCTF-GAME` ZIP (`manifest.json`,
   `game.json`, `challenges/*.json`) importable on another 1.9.x instance. That
   ZIP — not `challenge.yml` — is the native portable format.

## 9. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| "Container Config Error" | Container Image or Service Port empty. |
| "Challenge flag too trivial" on save | Template must contain `[TEAM_HASH]` or `[GUID]`. |
| Container stays `Pending` | Image cannot be pulled; check platform logs and `docker pull` manually. |
| Container exits immediately | `GZCTF_FLAG` not injected (challenge not `DynamicContainer`). Log: `GZCTF_FLAG is missing or empty; refusing to start`. |
| Player sees `172.x.x.x:<port>` | `ContainerProvider.PublicEntry` not configured. |
| Internal route returns 404 | Wrong path; the exact value is `/api/internal/project-preview` and it is also visible in `/assets/app.js`. |
| Flag rejected although it came from the endpoint | Instance was recreated with a new flag; relaunch and read it again. |
