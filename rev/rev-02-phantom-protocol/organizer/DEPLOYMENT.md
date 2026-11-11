# REV-02 — Deployment

Verified against GZ::CTF **1.9.1** (`23ccbbaa`) with the Docker container
provider and `PortMappingType: Default`.

## 1. Prerequisites

* GZ::CTF with the Docker container provider.
* A registry the platform can pull from (or a local image on the platform host).
* No extra privileges: the container runs as UID 1000 with no mounts, no
  capabilities and no Docker socket access.
* `ContainerProvider.PublicEntry` set to the address players use (section 6).

## 2. Build and publish

```bash
docker build -t registry.axumsec.example/ctf/rev-02-phantom-protocol:1.0.0 .
docker push registry.axumsec.example/ctf/rev-02-phantom-protocol:1.0.0
```

The image contains no flag and is built once for the whole event. Do not pass
`GZCTF_FLAG` as a build argument.

| Stage | Base | Purpose |
|---|---|---|
| `build` | `alpine:3.20` + `build-base` | compiles and strips `phantom-client` |
| `deps` | `node:22-alpine` | production dependencies via `npm ci` |
| runtime | `node:22-alpine` + `python3` | download service + runtime generator |

The C toolchain never reaches the runtime stage.

The participant binary is statically linked against musl, so it runs on any
Linux x86_64 host regardless of the participant's glibc version.

## 3. Runtime artifact generation

`entrypoint.sh` runs before the download service:

| Step | Action |
|---|---|
| 1 | Reject a missing, empty or blank `GZCTF_FLAG` |
| 2 | `python3 generator/generate_package.py` (inherits the flag) |
| 3 | Validates length `1..128` bytes and bytes `0x20..0x7e` |
| 4 | Applies add → XOR → rotate, serialises `protocol.dat` |
| 5 | Builds `phantom-protocol-package.zip` in `${RUNTIME_DIR}` |
| 6 | Generator pops `GZCTF_FLAG` from `os.environ` and zeroes its buffer, then exits |
| 7 | `unset GZCTF_FLAG` |
| 8 | `exec node /app/server/server.js` |

`protocol.dat` exists only inside the ZIP; no plaintext artifact is written to
the runtime filesystem.

## 4. Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `GZCTF_FLAG` | — (required) | Injected by GZ::CTF. Consumed by the generator only. |
| `PORT` | `3000` | Download service port. Must match the challenge *Service Port*. |
| `RUNTIME_DIR` | `/app/runtime` | Output directory for the ZIP. Must be writable by UID 1000. |

## 5. Local run

```bash
docker build -t rev-02-phantom-protocol:dev .

docker run --rm -d --name rev-02 \
  -e 'GZCTF_FLAG=AXUM{local_test_token}' \
  -p 127.0.0.1:3000:3000 \
  rev-02-phantom-protocol:dev

curl http://127.0.0.1:3000/health
docker logs rev-02     # [phantom-generator] packaged … ; [phantom-download] listening …
```

## 6. Port conventions and public entry

The image declares **no `EXPOSE`**: GZ::CTF maps `Service Port` (`3000`) to a
random host port per instance.

`ContainerProvider.PublicEntry` in `appsettings.json`:

```json
{
  "ContainerProvider": {
    "PublicEntry": "ctf.axumsec.example"
  }
}
```

Verified behaviour in 1.9.1: `Container.Entry` is
`${PublicEntry ?? containerIP}:${PublicPort ?? port}`. Without it the platform
reports the container network address combined with the published host port,
which is unusable from outside.

## 7. Configure the challenge in the admin UI

1. **Admin → Games → New Game** (or reuse the event game). The game must be
   running, or Practice Mode enabled, for containers to launch.
2. Inside the game, **Add Challenge**:
   * Title: `Phantom Protocol`
   * Category: `Reverse`
   * Type: **DynamicContainer** (fixed at creation time)
3. Fill in:

| UI field (en-US) | Value |
|---|---|
| Challenge Content | the description from `challenge.yml` → `public.description` |
| Score | `300` |
| Minimum Score Ratio | `1.0` |
| Difficulty Factor | `1.0` (score coefficient, not the display difficulty) |
| Flag Template | `AXUM{phantom_protocol_[TEAM_HASH]}` |
| Container Image | `registry.axumsec.example/ctf/rev-02-phantom-protocol:1.0.0` |
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
curl -sb cookies.txt -H 'Content-Type: application/json' \
  -X POST http://<platform>/api/Edit/Games -d '{
    "title": "AxumSec Reverse Engineering",
    "hidden": false, "summary": "", "content": "",
    "acceptWithoutReview": true, "practiceMode": true,
    "start": "2026-11-10T00:00:00Z", "end": "2026-11-17T00:00:00Z",
    "teamMemberCountLimit": 0, "containerCountLimit": 3, "bloodBonus": 0
  }'

curl -sb cookies.txt -H 'Content-Type: application/json' \
  -X POST http://<platform>/api/Edit/Games/<gameId>/Challenges \
  -d '{"title":"Phantom Protocol","category":"Reverse","type":"DynamicContainer"}'

curl -sb cookies.txt -H 'Content-Type: application/json' \
  -X PUT http://<platform>/api/Edit/Games/<gameId>/Challenges/<challengeId> -d '{
    "title": "Phantom Protocol",
    "content": "Aegis Communications intercept analysis.",
    "category": "Reverse",
    "flagTemplate": "AXUM{phantom_protocol_[TEAM_HASH]}",
    "hints": [
      "**Hint 1 — Inspect the artifact**\n\nInspect the executable'\''s file format, metadata, and strings.",
      "**Hint 2 — Follow the validation**\n\nLocate the token-validation routine and follow how it processes candidate bytes.",
      "**Hint 3 — The stages are reversible**\n\nLook for repeated byte operations, position-dependent arithmetic, and bit rotations. The transformations are reversible."
    ],
    "isEnabled": true,
    "containerImage": "registry.axumsec.example/ctf/rev-02-phantom-protocol:1.0.0",
    "exposePort": 3000, "memoryLimit": 128, "cpuCount": 1, "storageLimit": 64,
    "networkMode": "Open", "enableTrafficCapture": false,
    "originalScore": 300, "minScoreRate": 1.0, "difficulty": 1.0, "submissionLimit": 0
  }'
```

Smoke-test before the game opens:

```bash
curl -sb cookies.txt -X POST \
  http://<platform>/api/Edit/Games/<gameId>/Challenges/<challengeId>/Container
```

## 8. Per-team isolation

* One container per team; `GZCTF_FLAG` differs per team.
* The ZIP is generated inside each container, so each team gets a different
  `protocol.dat` and a different token.
* The download service holds no flag and no per-team state; it serves the
  archive generated in its own container.
* Cross-team submissions are rejected by the platform (verified).

## 9. Verify the deployment

```bash
python3 tests/gzctf_e2e.py \
  --base-url https://ctf.axumsec.example \
  --admin-user <admin> --admin-pass '<password>' \
  --image registry.axumsec.example/ctf/rev-02-phantom-protocol:1.0.0
```

Creates a throw-away game, registers two players, starts one container per team,
downloads each archive, recovers the token with `scripts/verify_solution.py`,
asserts both tokens differ and match `AXUM{phantom_protocol_<12 hex>}`, submits
each team's own token (`Accepted`) and the opposite team's token (rejected), then
deletes the game.

## 10. Reset and redeploy

* **One team:** player UI → *Destroy* then *Launch*. The archive is regenerated
  from the newly injected flag.
* **Everything:** disable and re-enable the challenge, then relaunch.
* **New image version:** push a new tag, update *Container Image*, destroy and
  relaunch instances. No persistent state exists.

## 11. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Container exits with `GZCTF_FLAG is missing or empty` | Challenge is not a `DynamicContainer`, or the platform did not inject the flag. |
| Log shows `flag length is outside the supported range` | The generated flag exceeded 128 bytes — shorten the template. |
| `/health` returns 503 with `archive: missing` | Generator did not run; check the `[phantom-generator]` log line. |
| Generator reports `packaging failed` | `RUNTIME_DIR` not writable by UID 1000. |
| Entry URL reports a `172.x` address | `ContainerProvider.PublicEntry` is not configured. |
| Participant gets `ACCESS DENIED` for a recovered token | Trailing newline or space captured with the token. |
| Container stays `Pending` | Platform cannot pull the image; check the tag and platform logs. |

## 12. Unverified platform details

* Kubernetes provider deployment — **NOT TESTED** (single-container topology, so
  it is expected to work unchanged).
* Traffic capture (`enableTrafficCapture: true`) — **NOT TESTED**; disabled by
  design.
* `linux/arm64` builds — **NOT TESTED**; the challenge targets Linux x86_64 and
  the participant README states that requirement.
