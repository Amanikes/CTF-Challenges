# WEB-04 — QA Checklist (executed)

Test date: 2026-11-12
Host: Linux, Docker 29.8.2 (overlayfs), Node 24.18.0 for the scripts, Python 3.14.8.
Platform: GZ::CTF 1.9.1 (`23ccbbaa`) in Development mode, Docker provider,
`PortMappingType: Default`, `ContainerProvider.PublicEntry = 127.0.0.1`.

Everything below marked **PASS** was executed, not inferred. The raw commands
are reproducible with `tests/run-local-docker-tests.sh` and
`tests/gzctf_e2e.py`.

## 1. Image build

| Check | Result | Evidence |
|---|---|---|
| `docker build` succeeds | PASS | staged build; `node:22-alpine` deps stage, `node:22-alpine` runtime stage |
| Native module compiles in the build stage | PASS | `better-sqlite3` 13.0.3 built with `python3`/`make`/`g++` installed in `deps` |
| Runtime stage ships no compilers | PASS | build tools installed with `--virtual .build-deps` in the `deps` stage only |
| Production dependencies only (`npm ci --omit=dev`) | PASS | express 5.3.0, better-sqlite3 13.0.3 |
| Runtime user is non-root | PASS | `uid=1000(node) gid=1000(node) groups=1000(node)` |
| No `EXPOSE` directive | PASS | `docker image inspect` → `ExposedPorts` null |
| No flag baked into the image | PASS | `grep -rIl "AXUM{" /app/src /app/public /app/entrypoint.sh /app/package.json` → no match |
| No database baked into the image | PASS | `ls -A /app/data` → empty |
| No Docker socket / host mount / privileged mode required | PASS | containers ran with `-e` and `-p` only |

## 2. Application behaviour (local Docker, two simulated teams)

Team A flag: `AXUM{team_a_test_flag}`
Team B flag: `AXUM{team_b_test_flag}`

| Check | Result |
|---|---|
| Catalogue page loads (`GET /`) | PASS (200, Blackstone branding) |
| Stylesheet and client bundle served | PASS (200 / 200) |
| `GET /health` | PASS (`{"status":"ok","service":"blackstone-inventory"}`) |
| `GET /healthz` | PASS (200) |
| `GET /api/products` | PASS (12 rows) |
| `GET /api/categories` | PASS (4 categories) |
| `GET /api/products/search?q=printer` | PASS (1 row) |
| `GET /api/products/search?category=Industrial Hardware` | PASS (3 rows) |

## 3. Intended vulnerability

| Check | Result | Detail |
|---|---|---|
| Unterminated quote rejected | PASS | `category='` → 400 |
| Error response leaks no SQL or schema | PASS | body is `{"error":"Invalid search query parameter."}`; no `sqlite`, `select`, `syntax error`, or table names |
| Tautology returns the whole table | PASS | `category=' OR 1=1-- -` → 12 rows |
| Schema enumerable | PASS | `UNION SELECT 1,sql,3,4 FROM sqlite_master` exposes both `CREATE TABLE` statements |
| UNION returns the flag | PASS | 4-column match returns `internal_records` row with the flag in `description` |
| Column-count mismatch fails safely | PASS | generic 400, no crash, container stays healthy |

## 4. Dynamic flag isolation

| Check | Result |
|---|---|
| Instance A returns its own flag | PASS |
| Instance B returns its own flag | PASS |
| Instance A never returns instance B's flag | PASS |
| Instance B never returns instance A's flag | PASS |
| Flags differ between instances | PASS |

## 5. Flag leakage

| Check | Result |
|---|---|
| No flag in `/`, `/css/style.css`, `/js/app.js` | PASS |
| No flag in `/health`, `/healthz` | PASS |
| No flag in `/api/products`, `/api/categories`, `/api/products/search?q=` | PASS |
| Container logs contain no flag | PASS |
| Image contains no flag | PASS |

## 6. Security posture and lifecycle

| Check | Result |
|---|---|
| Not privileged, no mounts, runs as `node` | PASS |
| Runtime uid 1000 | PASS |
| Docker socket not mounted | PASS |
| Refuses to start without `GZCTF_FLAG` | PASS (exit 1) |
| Explicit missing-flag error | PASS (`[FATAL] GZCTF_FLAG is missing or empty; refusing to start.`) |
| Refuses to start with a whitespace-only `GZCTF_FLAG` | PASS (exit 1) |
| Healthcheck reports healthy | PASS |

## 7. Platform validation (two teams, GZ::CTF)

`python3 tests/gzctf_e2e.py --admin-user Admin --admin-pass ***`

| Check | Result |
|---|---|
| Game + DynamicContainer challenge created via admin API | PASS |
| Two independent players/teams joined and started a container each | PASS |
| Container reached `Running` and served `/health` | PASS |
| Flag recovered from each instance through the UNION payload | PASS |
| Recovered flags match `AXUM{database_after_dark_[TEAM_HASH]}` | PASS |
| Flags differ between teams | PASS |
| Own flag accepted by GZ::CTF | PASS (`Accepted`, both teams) |
| Team B's flag rejected for team A | PASS (`WrongAnswer`) |
| Team A's flag rejected for team B | PASS (`WrongAnswer`) |
| Temporary validation game deleted | PASS |

Example run: game 23, challenge 31, entries `127.0.0.1:32835` / `127.0.0.1:32836`,
flags `AXUM{database_after_dark_d89a6d51a865}` / `AXUM{database_after_dark_c64c08aa1946}`.

## 8. Observed behaviour, not a defect

* Unmatched `GET` routes (including unknown `/api/*` paths) return the catalogue
  HTML shell with status 200. This is the deliberate SPA fallback in
  `src/server.js` and is not exploitable; the tests do not depend on it.
* The SQLite file is deleted and recreated at every container start, so
  containers always begin from identical seed data.

## 9. Known gap in the environment (not WEB-04 specific)

The first platform run failed with
`created container: network gzctf-open not found`. GZ::CTF creates
`gzctf-open` and `gzctf-isolated` only at startup, and they had been removed from
the host while the platform kept running. Recreating them restored service:

```bash
docker network create --driver bridge --attachable gzctf-open
docker network create --driver bridge --attachable \
  --opt com.docker.network.bridge.enable_ip_masquerade=false gzctf-isolated
```

Add this to the event-day checklist: after any host-side Docker network cleanup,
restart GZ::CTF or recreate these two networks, otherwise every container start
returns HTTP 500.
