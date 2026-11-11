# NET-02 — Lost in DNS: deployment

Verified against GZ::CTF **1.9.1** (`23ccbbaa`) with the Docker container
provider and `PortMappingType: Default`.

## 1. Requirements

* GZ::CTF with the Docker container provider.
* A registry the platform can pull from (or the image present on the platform
  host).
* No special privileges: the container runs as UID 10001, drops nothing but
  needs nothing, and mounts nothing.

## 2. Build and publish

```bash
docker build -t registry.axumsec.example/ctf/net-02-lost-in-dns:1.0.0 .
docker push registry.axumsec.example/ctf/net-02-lost-in-dns:1.0.0
```

The image contains no flag. Do not pass `GZCTF_FLAG` as a build argument.

Base image: `python:3.12-alpine3.21` (pinned), with `scapy==2.8.0` from
`requirements.txt`. No Node runtime is required — the download service uses the
Python standard library.

## 3. Runtime behaviour

| Step | Action |
|---|---|
| 1 | Reject a missing, empty or blank `GZCTF_FLAG` |
| 2 | `python3 src/generate_capture.py` encodes the flag and builds the capture |
| 3 | The capture is validated (structure, fragments, reconstruction, no plaintext leak) |
| 4 | The artifact is published atomically as `$PCAP_PATH` |
| 5 | `unset GZCTF_FLAG` |
| 6 | `exec python3 src/app.py` — the server starts only after a valid artifact exists |

If generation or validation fails the container exits non-zero and `/health`
never becomes ready.

## 4. Environment

| Variable | Default | Notes |
|---|---|---|
| `GZCTF_FLAG` | — (required) | Injected by GZ::CTF; used only by the generator |
| `PORT` | `8080` | Must match the challenge *Service Port* |
| `PCAP_PATH` | `/app/runtime/capture.pcap` | Must be writable by UID 10001 |
| `LOG_LEVEL` | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR`/`CRITICAL` |

## 5. Ports and public entry

The image declares `EXPOSE 8080` (matching the application default) and GZ::CTF
maps `Service Port` `8080` to a random host port per instance.

Set `ContainerProvider.PublicEntry` in `appsettings.json` so players receive a
reachable address:

```json
{
  "ContainerProvider": {
    "PublicEntry": "ctf.axumsec.example"
  }
}
```

Verified behaviour in 1.9.1: `Container.Entry` is
`${PublicEntry ?? containerIP}:${PublicPort ?? port}`.

## 6. GZ::CTF configuration

1. **Admin → Games → New Game** (or reuse the event game). The game must be
   running, or Practice Mode enabled, for containers to launch.
2. Inside the game, **Add Challenge**: title `Lost in DNS`, category
   **Forensics**, type **DynamicContainer**.
3. Fill in:

| UI field | Value |
|---|---|
| Challenge Content | description from `challenge.yml` → `public.description` |
| Score | `50` |
| Minimum Score Ratio | `1.0` |
| Difficulty Factor | `1.0` |
| Flag Template | `AXUM{lost_in_dns_[TEAM_HASH]}` |
| Container Image | `registry.axumsec.example/ctf/net-02-lost-in-dns:1.0.0` |
| Service Port | `8080` |
| Memory Limit (MB) | `128` |
| CPU Limit (0.1 CPUs) | `1` |
| Storage Limit (MB) | `64` |
| Network Mode | `Open` |
| Traffic Capture | off |
| Hints | the four markdown hints from `challenge.yml` |

4. Enable the challenge.

### API equivalent

```bash
curl -sb cookies.txt -H 'Content-Type: application/json' \
  -X POST http://<platform>/api/Edit/Games -d '{
    "title": "AxumSec Network Forensics",
    "hidden": false, "summary": "", "content": "",
    "acceptWithoutReview": true, "practiceMode": true,
    "start": "2026-11-10T00:00:00Z", "end": "2026-11-17T00:00:00Z",
    "teamMemberCountLimit": 0, "containerCountLimit": 3, "bloodBonus": 0
  }'

curl -sb cookies.txt -H 'Content-Type: application/json' \
  -X POST http://<platform>/api/Edit/Games/<gameId>/Challenges \
  -d '{"title":"Lost in DNS","category":"Forensics","type":"DynamicContainer"}'

curl -sb cookies.txt -H 'Content-Type: application/json' \
  -X PUT http://<platform>/api/Edit/Games/<gameId>/Challenges/<challengeId> -d '{
    "title": "Lost in DNS",
    "content": "Suspicious DNS activity captured from an internal workstation.",
    "category": "Forensics",
    "flagTemplate": "AXUM{lost_in_dns_[TEAM_HASH]}",
    "isEnabled": true,
    "containerImage": "registry.axumsec.example/ctf/net-02-lost-in-dns:1.0.0",
    "exposePort": 8080,
    "memoryLimit": 128, "cpuCount": 1, "storageLimit": 64,
    "networkMode": "Open", "enableTrafficCapture": false,
    "originalScore": 50, "minScoreRate": 1.0, "difficulty": 1.0, "submissionLimit": 0
  }'
```

## 7. Resource limits and health

| Item | Value |
|---|---|
| Recommended limits | 128 MB memory, 0.1 CPU, 64 MB storage |
| Health probe | `GET /health` → `200 {"status":"ok","capture":"ready"}`, `503` before the artifact exists |
| Start period | 20 s (Scapy import + generation) |
| PID 1 | `python3 src/app.py` (the entrypoint `exec`s into it) |

`docker-compose.yml` in this directory applies the stricter local development
profile: `read_only` root filesystem with `tmpfs` for `/app/runtime` and `/tmp`,
`no-new-privileges`, `cap_drop: ALL`, `pids_limit`, memory and CPU limits. It is
not used by GZ::CTF and does not conflict with the platform.

GZ::CTF itself does not apply `security_opt`, `cap_drop` or `read_only`; those
were verified only through the Compose profile and `docker inspect`.

## 8. Verify the deployment

```bash
python3 tests/gzctf_e2e.py \
  --base-url https://ctf.axumsec.example \
  --admin-user <admin> --admin-pass '<password>' \
  --image registry.axumsec.example/ctf/net-02-lost-in-dns:1.0.0
```

The script creates a throw-away game, registers two players, starts one
container per team, downloads both captures, decodes the DNS fragments,
asserts the flags differ and match `AXUM{lost_in_dns_<12 hex>}`, submits each
team's own flag (must be `Accepted`) and the opposite team's flag (must be
rejected), then deletes the game.

## 9. Reset and redeploy

* **One team:** player UI → *Destroy* then *Launch*. The capture is regenerated
  from the newly injected flag.
* **Everything:** disable and re-enable the challenge, then relaunch.
* **New image version:** push a new tag, update *Container Image*, destroy and
  relaunch instances.

## 10. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Container exits with `GZCTF_FLAG is missing or empty` | Not a `DynamicContainer`, or no flag injected |
| Log shows `capture validation failed: …` | The generator refused an invalid capture; the message names the failing property |
| Log shows `capture generation failed: PermissionError` | `PCAP_PATH` is not writable by UID 10001 |
| `/health` returns 503 `capture: missing` | Generation never ran or wrote elsewhere |
| `/download` returns 503 | Artifact absent; check `/health` and container logs |
| Entry URL shows a `172.x` address | `ContainerProvider.PublicEntry` not configured |
| Participant sees no TXT queries | They are filtering on `dns.qry.name == "…"` with the wrong suffix; use `dns.qry.type == 16` |
| Container stays `Pending` | Image not pullable by the platform |

## 11. Unverified platform details

* Kubernetes provider deployment — **NOT TESTED** (single container, so it is
  expected to work unchanged).
* Traffic capture (`enableTrafficCapture: true`) — **NOT TESTED**; disabled by
  design and unnecessary here.
* `linux/arm64` build — **NOT TESTED**; the challenge targets x86_64 nodes.
