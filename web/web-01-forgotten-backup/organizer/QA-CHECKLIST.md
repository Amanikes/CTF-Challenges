# WEB-01 — QA Checklist (executed)

Test date: 2026-11-10
Host: Linux, Docker 29.8.2 (overlayfs), Node 24.18.0 for the scripts.
Platform: GZ::CTF 1.9.1 (`23ccbbaa`), Docker provider, `PortMappingType: Default`,
API encryption disabled, registration active on registration.

Everything below marked **PASS** was executed, not inferred. The raw commands
are reproducible with `tests/run-local-docker-tests.sh` and
`tests/gzctf_e2e.py`.

## 1. Image build

| Check | Result | Evidence |
|---|---|---|
| `docker build` succeeds | PASS | staged build, final image `sha256:7bfaedaf…` |
| Production dependencies only (`npm ci --omit=dev`) | PASS | express 5.3.0, yazl 3.3.1, buffer-crc32 |
| Runtime user is non-root | PASS | `uid=1000(node) gid=1000(node)` |
| No `EXPOSE` directive | PASS | `docker inspect` shows only the mapped port from the test run |
| No flag or archive baked into the image | PASS | `grep -rIl "AXUM{" /app` → no match; `/app/runtime/backups` empty |
| No Docker socket / host mount / privileged mode required | PASS | containers ran with `-e`, `-p` only |

## 2. Application behaviour (local Docker, two simulated teams)

Team A flag: `AXUM{team_a_test_flag}`
Team B flag: `AXUM{team_b_test_flag}`

| Check | Result |
|---|---|
| Homepage loads (`GET /`) | PASS (200) |
| `robots.txt` accessible and contains `Disallow: /backups/` | PASS |
| `GET /backups/` returns a listing containing `northstar-site-backup.zip` | PASS |
| `GET /healthz` returns 200 JSON | PASS |
| Archive downloads (`GET /backups/northstar-site-backup.zip`) | PASS (200, ~11 KiB) |
| Archive extracts cleanly (`unzip -t`) | PASS |
| `config/production.env` contains `CTF_FLAG` | PASS |
| Team A archive contains team A flag | PASS |
| Team B archive contains team B flag | PASS |
| Team A archive does not contain team B flag | PASS |
| Team B archive does not contain team A flag | PASS |
| No flag in `/`, CSS, JS, favicon, `robots.txt`, `/healthz`, listing, 404 | PASS (0 occurrences) |
| `/runtime/...` and `/src/server.js` not web accessible | PASS (404) |
| Path traversal attempts (`..%2f`, `%2e%2e%2f`, dotfiles) | PASS (404) |
| `x-powered-by` absent | PASS |
| Container healthcheck reports `healthy` | PASS |
| Container refuses to start without `GZCTF_FLAG` | PASS (exit 1, explicit error) |
| Flag absent from PID 1 environment after startup | PASS (`/proc/1/environ` has no `GZCTF_FLAG`) |
| Recreate with a rotated flag rebuilds the archive | PASS (old flag gone, new flag present) |
| `docker restart` rebuilds the archive with the same flag | PASS |

## 3. GZ::CTF dynamic flag validation (executed)

`tests/gzctf_e2e.py` was run against the local platform. It created a game and
a `DynamicContainer` challenge with the production image, registered two
players with separate teams, joined both teams to the game and launched one
container per team.

| Check | Result | Evidence |
|---|---|---|
| Game/challenge created through admin API | PASS | game 9, challenge 8 |
| Challenge accepted as `DynamicContainer` | PASS | configuration PUT accepted, instances created and launched |
| Flag template accepted (`AXUM{forgotten_backup_[TEAM_HASH]}`) | PASS | challenge saved with `isEnabled: true` |
| Platform creates one instance per team | PASS | team A and team B containers both `Running` |
| Each container receives a distinct flag | PASS | A: `AXUM{forgotten_backup_69bebdd3f044}`, B: `AXUM{forgotten_backup_c3c950f1bd91}` |
| Backup archive in each instance contains that team's flag | PASS | flags recovered from `config/production.env` |
| Team A's own flag accepted | PASS | submission status `Accepted` |
| Team B's own flag accepted | PASS | submission status `Accepted` |
| Team A submitting team B's flag | PASS (rejected) | status `WrongAnswer` |
| Team B submitting team A's flag | PASS (rejected) | status `WrongAnswer` |
| Instance lifecycle (destroy via game delete) | PASS with note | database records removed; running containers had to be removed manually (see limitation) |

The script exited with `"result": "passed"` and deleted the throw-away game.

## 4. Not executed / limitations

| Item | Status | Reason |
|---|---|---|
| Registry push and pull from the platform host | NOT RUN | No registry available in the test environment; the platform used a locally built image. The image is registry-agnostic. |
| Kubernetes provider | NOT RUN | Only the Docker provider was available. |
| External `PublicEntry` reachability | NOT RUN | Local dev platform has no `PublicEntry`; the test script falls back to the published port on loopback. Configure `PublicEntry` for the event. |
| Concurrent load / many teams | NOT RUN | Two-team functional validation only. |
| Automatic container reaping after game deletion | PARTIAL | Containers were still running after `DELETE /api/Edit/Games/{id}` in 1.9.1 and were removed manually. Documented in `docs/DEPLOYMENT.md` §7. |

## 5. Reproduce

```bash
# Local image + application checks (builds web-01-forgotten-backup:test)
./tests/run-local-docker-tests.sh

# Platform validation (needs an admin account on the instance)
python3 tests/gzctf_e2e.py \
  --base-url http://127.0.0.1:8080 \
  --admin-user <admin> --admin-pass '<password>' \
  --image web-01-forgotten-backup:dev
```
