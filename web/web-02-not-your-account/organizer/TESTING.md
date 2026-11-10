# WEB-02 — Testing Report

Executed on 2026-11-10.

Environment:

* Docker 29.8.2 (overlayfs), image built from `source/Dockerfile` (`node:22-alpine`)
* GZ::CTF 1.9.1 (`23ccbbaa`), Docker provider, `PortMappingType: Default`,
  API encryption disabled, registration active on registration
* Test scripts: `tests/run-local-docker-tests.sh` and `tests/gzctf_e2e.py`

Result of the local suite: **35 PASS, 0 FAIL**.

## 1. Functional tests

Commands used (abridged; the suite performs exactly these calls):

```bash
docker build -t web-02-not-your-account:test source
docker run -d --name a -e 'GZCTF_FLAG=AXUM{team_a_test_flag}' -p 127.0.0.1::3000 web-02-not-your-account:test
PORT=$(docker port a 3000/tcp | sed 's/.*://')
curl -c jar -d 'username=alex&password=Northstar@2026' "http://127.0.0.1:$PORT/login"
curl -b jar "http://127.0.0.1:$PORT/api/accounts/1002"
```

| # | Test | Expected | Actual |
|---|---|---|---|
| 1 | Starts with a valid `GZCTF_FLAG` | healthy container | PASS (`healthy`, `/healthz` 200) |
| 2 | Login page loads | HTTP 200, branded | PASS (200, "Northstar Bank" present) |
| 3 | Valid credentials authenticate | 303 → `/dashboard`, session set | PASS |
| 4 | Invalid credentials rejected | 303 → `/?error=invalid` | PASS |
| 5 | Unauthenticated protected API | HTTP 401 JSON | PASS (`{"error":"Authentication required"}`) |
| 5b | Unauthenticated protected page | redirect to login | PASS (302 → `/`) |
| 6 | Authenticated read of account 1001 | 200, Alex Morgan | PASS |
| 7 | Authenticated read of 1001 transactions | 200, non-empty | PASS (5 transactions) |
| 8 | Authenticated read of account 1002 (IDOR) | 200, Jordan Lee | PASS |
| 9 | Account 1002 contains the runtime flag | flag equals instance value | PASS |
| 10 | Logout invalidates the session | subsequent API call 401 | PASS |
| 11 | Session id rotated on login | two logins → different ids | PASS |
| 12 | Session cookie attributes | `HttpOnly`, `SameSite=Lax` | PASS |
| 13 | Unknown account | 404 | PASS |

## 2. Dynamic flag isolation

Two containers with distinct flags:

| Instance | `GZCTF_FLAG` | Result |
|---|---|---|
| A | `AXUM{team_a_test_flag}` | `/api/accounts/1002` returns exactly this value |
| B | `AXUM{team_b_test_flag}` | `/api/accounts/1002` returns exactly this value |

Additional checks, all PASS:

* instance A's response never contains `team_b_test_flag`;
* instance B's response never contains `team_a_test_flag`;
* neither test flag appears in the image (`grep -r "AXUM{" /app`);
* neither test flag appears in pages, CSS, JS, favicon or `/healthz`;
* neither test flag appears in `docker logs` for either container.

## 3. Security checks

| Check | Command | Result |
|---|---|---|
| Not privileged | `docker inspect` → `HostConfig.Privileged` | PASS (`false`) |
| No mounts | `docker inspect` → `Mounts` | PASS (`[]`) |
| No Docker socket | inspect mount sources | PASS |
| Non-root runtime | `docker run --rm --entrypoint id` | PASS (`uid=1000(node)`) |
| No flag in frontend assets | HTTP scan of every page/asset | PASS (0 occurrences) |
| No flag in logs | `docker logs` scan | PASS |
| Fail closed without flag | `docker run` without `GZCTF_FLAG` | PASS (exit 1, `GZCTF_FLAG is missing or empty`) |
| Clean shutdown | `docker stop` | PASS (exit code 0 on SIGTERM) |
| Healthcheck | `docker inspect .State.Health.Status` | PASS (`healthy`) |

## 4. Participant simulation

Performed using only the participant-facing description and the running
application:

1. Opened `/`, signed in with `alex` / `Northstar@2026` — no error.
2. Dashboard loaded and displayed Alex Morgan, account 1001, balance and recent
   transactions.
3. Opened browser devtools → Network: the page requested
   `/api/session`, `/api/accounts/1001` and
   `/api/accounts/1001/transactions`.
4. Replaced `1001` with `1002` in the account request.
5. The response contained Jordan Lee's record and the `flag` field.
6. Logged in again in a fresh client, confirmed the same path, and submitted the
   flag.

Findings: the three hints are sufficient; the API path is visible without
guessing, the account number is shown on the dashboard, and no source code
access is needed. The suite automates this path and asserts the flag is returned
(`Participant simulation` check).

## 5. GZ::CTF integration (executed)

`tests/gzctf_e2e.py` created a throw-away game and `DynamicContainer` challenge,
registered two players with separate teams, launched one container per team and
followed the intended IDOR path on each instance.

| Check | Result |
|---|---|
| Game and challenge created through the admin API | PASS (game 10, challenge 9) |
| Challenge saved with `flagTemplate` `AXUM{not_your_account_[TEAM_HASH]}` | PASS |
| One instance per team | PASS |
| Distinct flags per team | PASS — A: `AXUM{not_your_account_ea36d36d1a4d}`, B: `AXUM{not_your_account_3e130c42fa4a}` |
| Flags match the template (`AXUM{..._<12 hex>}`) | PASS |
| Each instance serves only its own flag | PASS |
| Team A's own flag accepted by GZ::CTF | PASS (`Accepted`) |
| Team B's own flag accepted by GZ::CTF | PASS (`Accepted`) |
| Team A submitting team B's flag | PASS (rejected: `WrongAnswer`) |
| Team B submitting team A's flag | PASS (rejected: `WrongAnswer`) |
| Unauthenticated account API on the platform instance | PASS (401) |
| Cleanup | game deleted; running containers removed manually (platform behaviour, see below) |

## 6. Not executed

| Item | Reason |
|---|---|
| Registry push/pull from the platform host | No registry in the test environment; a locally built image was used. The image is registry-agnostic. |
| Kubernetes provider | Only the Docker provider was available. |
| External `PublicEntry` reachability | The local platform has no `PublicEntry` configured; the script falls back to the published port on loopback. |
| Load / many concurrent teams | Functional two-team validation only. |

## 7. Platform notes

* Deleting a game in GZ::CTF 1.9.1 removes its database records but can leave
  its containers running until the manager reaps them (default lifetime
  120 min). Remove them explicitly when cleaning a host.
* Without `ContainerProvider.PublicEntry`, `Container.Entry` reports the
  container network address with the published host port. The published port is
  still reachable on the platform host; configure `PublicEntry` for players.
