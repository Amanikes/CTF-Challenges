# REV-01 — Deployment

Verified against GZ::CTF **1.9.1** (`23ccbbaa`) with the Docker container
provider and `PortMappingType: Default`.

## 1. Prerequisites

* GZ::CTF with the Docker container provider.
* A registry the platform can pull from (or a local image on the platform host).
* No extra privileges: the container runs as UID 1000 with no mounts, no
  capabilities and no Docker socket access.
* `ContainerProvider.PublicEntry` set to the address players use (recommended,
  see section 6).

## 2. Build and publish

```bash
cd source
docker build -t registry.axumsec.example/ctf/rev-01-broken-license:1.0.0 .
docker push registry.axumsec.example/ctf/rev-01-broken-license:1.0.0
```

The image contains no flag, so it is built once and reused for the whole event.
Do not pass `GZCTF_FLAG` as a build argument.

The build is multi-stage:

| Stage | Base | Purpose |
|---|---|---|
| `build` | `alpine:3.20` + `build-base` | compiles `northstar-license`, strips DWARF |
| `deps` | `node:22-alpine` | installs production dependencies with `npm ci` |
| runtime | `node:22-alpine` | download service, generator, packaged binary |

The C toolchain never reaches the runtime stage.

Multi-architecture note: the executable is linked against musl with `-static`,
so it runs on any Linux x86_64 host. Building for `linux/arm64` would produce an
aarch64 ELF; build for `linux/amd64` for this challenge:

```bash
docker buildx build --platform linux/amd64 \
  -t registry.axumsec.example/ctf/rev-01-broken-license:1.0.0 --push .
```

## 3. Runtime artifact generation

`entrypoint.sh` runs before the download service:

| Step | Action |
|---|---|
| 1 | Reject a missing, empty or blank `GZCTF_FLAG` |
| 2 | `node scripts/generate-artifact.js` (inherits the flag) |
| 3 | Generator validates length 1–128 bytes and bytes `0x20`–`0x7e` |
| 4 | XOR-encodes the flag with the key from `shared/xor-spec.json` |
| 5 | Writes `license.dat`, builds `northstar-license-package.zip` |
| 6 | Generator exits (only process that ever held the plaintext) |
| 7 | `unset GZCTF_FLAG` |
| 8 | `exec node server.js` |

The archive is written to `${ARTIFACT_DIR}` (default `/app/runtime`), owned by
`node`. `license.dat` is deleted from the artifact directory once it has been
added to the archive.

## 4. Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `GZCTF_FLAG` | — (required) | Injected by GZ::CTF. Consumed by the generator only. |
| `PORT` | `3000` | Download service port. Must match the challenge *Service Port*. |
| `ARTIFACT_DIR` | `/app/runtime` | Where the ZIP is written. Must be writable by UID 1000. |
| `BINARY_PATH` | `/app/bin/northstar-license` | Packaged executable (override only for testing). |
| `PACKAGE_README` | `/app/package/README.txt` | Participant README added to the ZIP. |

## 5. Local run

```bash
cd source
docker build -t rev-01-broken-license:dev .

docker run --rm -d --name rev-01 \
  -e 'GZCTF_FLAG=GZCTF{local_test_flag}' \
  -p 127.0.0.1:3000:3000 \
  rev-01-broken-license:dev

curl http://127.0.0.1:3000/health
docker logs rev-01      # [northstar-artifact] packaged ... ; [northstar-download] listening ...
```

## 6. Download service

| Route | Behaviour |
|---|---|
| `GET /` | Landing page (product identity, platform requirement, run instructions) |
| `GET /download` | Serves the fixed archive path as `application/zip` with the expected filename |
| `GET /health` | `200` with `archive: ready`, or `503` with `archive: missing` |
| `GET /assets/*` | Static CSS/favicon only |

The service never reads `GZCTF_FLAG`, never lists directories and only serves the
fixed archive path.

## 7. Configure the challenge in the admin UI

1. **Admin → Games → New Game** (or reuse the event game). The game must be
   running, or Practice Mode must be enabled, for containers to launch.
2. Inside the game, **Add Challenge**:
   * Title: `The Broken License`
   * Category: `Reverse`
   * Type: **DynamicContainer** (fixed at creation time)
3. Fill in the editor:

| UI field (en-US) | Value |
|---|---|
| Challenge Content | the description from `challenge.yml` → `public.description` |
| Score | `100` |
| Minimum Score Ratio | `1.0` |
| Difficulty Factor | `1.0` (score coefficient, not the display difficulty) |
| Flag Template | `AXUM{broken_license_[TEAM_HASH]}` |
| Container Image | `registry.axumsec.example/ctf/rev-01-broken-license:1.0.0` |
| Service Port | `3000` |
| Memory Limit (MB) | `128` |
| CPU Limit (0.1 CPUs) | `1` |
| Storage Limit (MB) | `64` |
| Network Mode | `Open` |
| Traffic Capture | off |
| Hints | the three markdown hints from `challenge.yml` → `public.hints` |

4. Enable the challenge. GZ::CTF creates one instance per participating team and
   injects a distinct `GZCTF_FLAG` into each container.

### Equivalent API calls

```bash
# create the game
curl -sb cookies.txt -H 'Content-Type: application/json' \
  -X POST http://<platform>/api/Edit/Games -d '{
    "title": "AxumSec Reverse Engineering",
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

# create the challenge (type is fixed here; "Reverse" is ChallengeCategory.Reverse)
curl -sb cookies.txt -H 'Content-Type: application/json' \
  -X POST http://<platform>/api/Edit/Games/<gameId>/Challenges \
  -d '{"title":"The Broken License","category":"Reverse","type":"DynamicContainer"}'

# configure and enable it
curl -sb cookies.txt -H 'Content-Type: application/json' \
  -X PUT http://<platform>/api/Edit/Games/<gameId>/Challenges/<challengeId> -d '{
    "title": "The Broken License",
    "content": "Northstar License Manager recovery.",
    "category": "Reverse",
    "flagTemplate": "AXUM{broken_license_[TEAM_HASH]}",
    "hints": [
      "**Hint 1 — Identify the file**\n\nBefore running the program, inspect what kind of executable you have and examine the information it exposes.",
      "**Hint 2 — Follow the validation**\n\nLook for the function that checks the entered license. Pay attention to how each input byte is transformed before comparison.",
      "**Hint 3 — XOR is reversible**\n\nThe executable contains the transformation key, while the accompanying data file contains the encoded license. Remember that XOR can be reversed by applying the same key again."
    ],
    "isEnabled": true,
    "containerImage": "registry.axumsec.example/ctf/rev-01-broken-license:1.0.0",
    "exposePort": 3000,
    "memoryLimit": 128,
    "cpuCount": 1,
    "storageLimit": 64,
    "networkMode": "Open",
    "enableTrafficCapture": false,
    "originalScore": 100,
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

## 8. Port conventions and public entry

The image declares **no `EXPOSE`**: GZ::CTF maps `Service Port` (`3000`) to a
random host port per instance, and extra declarations would reserve ports for
every dynamic container.

`ContainerProvider.PublicEntry` (in `appsettings.json`) controls the address shown
to players:

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
host port, which is unusable from outside.

## 9. Per-team isolation

* One container per team; `GZCTF_FLAG` is generated from `[TEAM_HASH]` and
  differs per team.
* The archive is generated per container, so each team downloads a different
  `license.dat`.
* The download service holds no flag and no per-team state at all — it serves the
  archive produced in its own container.
* Cross-team flag submission is rejected by the platform (verified).

## 10. Verify the deployment

```bash
python3 tests/gzctf_e2e.py \
  --base-url https://ctf.axumsec.example \
  --admin-user <admin> --admin-pass '<password>' \
  --image registry.axumsec.example/ctf/rev-01-broken-license:1.0.0
```

The script creates a throw-away game, registers two players, starts one container
per team, downloads each archive, recovers the key from the ELF and data file
only, asserts the two flags differ and match `AXUM{broken_license_<12 hex>}`,
submits each team's own flag (must be `Accepted`) and the opposite team's flag
(must be rejected), then deletes the game.

## 11. Reset and redeploy

* **One team:** player UI → *Destroy* then *Launch*, or
  `DELETE /api/Game/<gameId>/Container/<challengeId>` followed by
  `POST /api/Game/<gameId>/Container/<challengeId>`. The archive is regenerated
  from the newly injected flag.
* **Everything:** disable and re-enable the challenge, then relaunch.
* **New image version:** push a new tag, update *Container Image*, destroy and
  relaunch instances. No persistent state exists.

## 12. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Container exits immediately, log shows `GZCTF_FLAG is missing` | Challenge is not a `DynamicContainer`, or the platform did not inject the flag. |
| Log shows `flag length is outside the supported range` | The generated flag exceeded 128 bytes — shorten the flag template. |
| `/health` returns 503 | Archive generation did not run; check the `[northstar-artifact]` log line. |
| Archive generation fails with a missing input | `BINARY_PATH` or `PACKAGE_README` points outside the image. |
| Entry URL reports a `172.x` address | `ContainerProvider.PublicEntry` is not configured. |
| Participant reports "License rejected" with a correct key | A trailing newline or trailing space was included in the pasted key. |
| Container stays `Pending` | The platform cannot pull the image; check the tag and platform logs. |

## 13. Unverified platform details

* Kubernetes provider deployment of this image — **NOT TESTED** (the topology is
  a single container, so it is expected to work unchanged).
* Traffic capture (`enableTrafficCapture: true`) — **NOT TESTED**; capture is
  disabled for this challenge.
* `linux/arm64` builds — **NOT TESTED**; the challenge targets x86_64 only, and the
  packaged ELF must match the participant's `Linux x86_64` platform statement.
