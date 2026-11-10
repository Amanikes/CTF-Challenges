# WEB-01 — Deployment

Verified against GZ::CTF **1.9.1** (`23ccbbaa`) with the Docker container
provider and `PortMappingType: Default`.

## 1. Prerequisites

* GZ::CTF with the Docker container provider (or Kubernetes, see section 8).
* A registry the platform can pull from.
* The platform host must be able to run the image as UID 1000; no extra
  capabilities, mounts or privileges are required.
* `ContainerProvider.PublicEntry` set to the address players use to reach the
  platform host (recommended, see section 5).

## 2. Build and publish the image

```bash
cd source
docker build -t registry.axumsec.example/ctf/web-01-forgotten-backup:1.0.0 .
docker push registry.axumsec.example/ctf/web-01-forgotten-backup:1.0.0
```

The image does not contain a flag, so it is safe to build once and reuse for the
whole event. Do not pass `GZCTF_FLAG` as a build argument.

For a multi-architecture registry:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t registry.axumsec.example/ctf/web-01-forgotten-backup:1.0.0 --push .
```

## 3. Configure the challenge in the admin UI

1. **Admin → Games → New Game** (or reuse the event game). The game must be
   running (current time inside `start`/`end`) for containers to launch.
2. Inside the game, **Add Challenge**:
   * Title: `The Forgotten Backup`
   * Category: `Web`
   * Type: **DynamicContainer**
     (`ChallengeType` can only be chosen when the challenge is created; the
     update model has no type field.)
3. Open the challenge editor and fill in:

| UI field (en-US) | Value |
|---|---|
| Challenge Content | the player description from `challenge.yml` → `public.description` |
| Score | `50` |
| Minimum Score Ratio | `1.0` |
| Difficulty Factor | `1.0` (this is a score coefficient, not the display difficulty) |
| Flag Template | `AXUM{forgotten_backup_[TEAM_HASH]}` |
| Container Image | `registry.axumsec.example/ctf/web-01-forgotten-backup:1.0.0` |
| Service Port | `3000` |
| Memory Limit (MB) | `128` |
| CPU Limit (0.1 CPUs) | `1` |
| Storage Limit (MB) | `64` |
| Network Mode | `Open` |
| Traffic Capture | off |

4. Enable the challenge. GZ::CTF creates one `GameInstance` per participating
   team (and creates instances for later joiners automatically).

Do **not** add static flags to a DynamicContainer challenge: the platform
generates the flag from the template and injects it as `GZCTF_FLAG`.

### Equivalent API calls

All routes below were exercised against 1.9.1. Authentication is the admin web
session cookie. If **API Encryption** is enabled in the platform settings, the
password/flag fields must be encrypted with the platform public key
(`GET /api/Config` → `apiPublicKey`, X25519 + SHA-256 + AES-GCM); with API
encryption disabled the plaintext values are accepted.

```bash
# create the game (the model binds Start/End as "start"/"end")
curl -sb cookies.txt -H 'Content-Type: application/json' \
  -X POST http://<platform>/api/Edit/Games -d '{
    "title": "AxumSec Web Exploitation",
    "hidden": false,
    "summary": "",
    "content": "",
    "acceptWithoutReview": true,
    "practiceMode": true,
    "start": "2025-11-10T00:00:00Z",
    "end": "2025-11-17T00:00:00Z",
    "teamMemberCountLimit": 0,
    "containerCountLimit": 3,
    "bloodBonus": 0
  }'

# create the challenge (type is fixed here)
curl -sb cookies.txt -H 'Content-Type: application/json' \
  -X POST http://<platform>/api/Edit/Games/<gameId>/Challenges \
  -d '{"title":"The Forgotten Backup","category":"Web","type":"DynamicContainer"}'

# configure and enable it
curl -sb cookies.txt -H 'Content-Type: application/json' \
  -X PUT http://<platform>/api/Edit/Games/<gameId>/Challenges/<challengeId> -d '{
    "title": "The Forgotten Backup",
    "content": "Northstar Systems migration leftovers.",
    "category": "Web",
    "flagTemplate": "AXUM{forgotten_backup_[TEAM_HASH]}",
    "isEnabled": true,
    "containerImage": "registry.axumsec.example/ctf/web-01-forgotten-backup:1.0.0",
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

To smoke-test the image before the game opens:

```bash
curl -sb cookies.txt -X POST \
  http://<platform>/api/Edit/Games/<gameId>/Challenges/<challengeId>/Container
```

This starts a container with a platform-generated test flag and returns
`{"status":"Running","entry":"...","startedAt":...}`. Destroy it with
`DELETE /api/Edit/Games/<gameId>/Challenges/<challengeId>/Container`.

## 4. Port conventions

The image deliberately has **no `EXPOSE`**. GZ::CTF maps `Service Port`
(`exposePort`, here `3000`) to a random host port per instance, exactly as the
official templates recommend. Adding `EXPOSE` would reserve additional ports
per container and is explicitly discouraged by the upstream project.

The application binds `0.0.0.0:3000` (`PORT` can override the port, but the
platform must then be configured to match).

## 5. Public entry

`ContainerProvider.PublicEntry` (in `appsettings.json`) controls the address
shown to players. Set it to the externally reachable host without a scheme,
e.g. `"PublicEntry": "ctf.axumsec.example"`.

Verified behaviour in 1.9.1: `Container.Entry` is
`${PublicIP ?? containerIP}:${PublicPort ?? port}`. When `PublicEntry` is empty
the platform reports the container network address combined with the published
host port. The published port remains reachable on the platform host, but the
reported address is not usable from outside, so always configure `PublicEntry`
for an event.

## 6. Verify the deployment

Run the two-team check from a machine that can reach the platform:

```bash
python3 tests/gzctf_e2e.py \
  --base-url https://ctf.axumsec.example \
  --admin-user <admin> --admin-pass '<password>' \
  --image registry.axumsec.example/ctf/web-01-forgotten-backup:1.0.0
```

It creates a throw-away game, registers two players, starts one container per
team, downloads both archives, asserts the flags differ and match
`AXUM{forgotten_backup_<12 hex>}`, submits each team's own flag (must be
`Accepted`) and each team's opposite flag (must be rejected), then deletes the
game. The script refuses to run if the platform rejects any step.

## 7. Reset and redeploy

* **Restart one team's instance:** player UI → *Destroy* then *Launch*, or
  `DELETE /api/Game/<gameId>/Container/<challengeId>` followed by
  `POST /api/Game/<gameId>/Container/<challengeId>`. The new container rebuilds
  the archive from the flag the platform injects at start.
* **Restart everything:** stop/delete the platform-created containers, or
  disable and re-enable the challenge (destroys all instances), then relaunch.
* **New image version:** push a new tag, update *Container Image*, then destroy
  and relaunch instances. Containers are recreated from scratch; the challenge
  keeps no persistent state.
* **Deleted game in 1.9.1:** deleting a game removes its database records but
  running containers may survive until the container manager reaps them
  (default lifetime 120 minutes). Stop them explicitly if you need the host
  clean immediately (`docker ps --filter name=web-01-forgotten-backup_`).

## 8. Kubernetes provider

The image is provider-agnostic. Set *Container Image* and *Service Port* as
above; GZ::CTF passes `GZCTF_FLAG` through a pod environment variable in the
same way. No extra manifests are required. Ensure the pod security context runs
as a non-root user; the image already defaults to UID 1000.

## 9. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Challenge shows "Container Config Error" | `Container Image` or `Service Port` empty. |
| "Challenge flag too trivial" on save | The flag template must contain `[TEAM_HASH]` or `[GUID]` (ours does). Do not remove the placeholder. |
| Container stays `Pending` / creation failed | Platform cannot pull the image, or the image tag does not exist. Check the platform logs and `docker pull` manually. |
| Container starts then exits | `GZCTF_FLAG` was not injected. Confirm the challenge type is `DynamicContainer`, not `StaticContainer`. The entrypoint logs `GZCTF_FLAG is not set; refusing to start`. |
| Player sees `172.x.x.x:<port>` | `ContainerProvider.PublicEntry` is not configured (section 5). |
| `/backups/` directory listing empty | The generator did not run. Check container logs for `[backup]` output. |
| Flag rejected although it came from the archive | The player submitted a flag from another team's instance, or the platform recreated the container with a new flag after the player copied the old one. Relaunch and re-download. |

## 10. Security checklist before the event

* [ ] `challenge.yml`, `organizer/` and `tests/` are **not** distributed to players.
* [ ] The image on the registry contains no flag (`docker run --rm --entrypoint sh <image> -c 'grep -r "AXUM{" /app'`).
* [ ] The challenge is `DynamicContainer`; the flag template contains `[TEAM_HASH]`.
* [ ] `PublicEntry` is configured and instances are reachable from outside.
* [ ] Two teams receive different flags (run `tests/gzctf_e2e.py`).
* [ ] Cross-team submissions are rejected.
* [ ] The player-facing description contains no hint of `backups` or the archive name.
