# WEB-03 — Testing Report

Executed on 2026-11-10.

Environment:

* Docker 29.8.2 (overlayfs); image built from `source/Dockerfile` (`node:22-alpine`)
* GZ::CTF 1.9.1 (`23ccbbaa`), Docker provider, `PortMappingType: Default`,
  API encryption disabled, registration active on registration
* Browsers used for the UI checks: Chromium via the integrated browser tool
  (1440 px and 400 px viewports)

Results: local Docker suite **38 PASS, 0 FAIL**; platform end-to-end
**passed**.

## 1. Functional tests

| # | Test | Expected | Actual |
|---|---|---|---|
| 1 | Starts with a valid `GZCTF_FLAG` | healthy container | PASS (`healthy`, `/health` 200) |
| 2 | Refuses to start without `GZCTF_FLAG` | exit 1, explicit message | PASS (`GZCTF_FLAG is missing or empty; refusing to start`) |
| 3 | Dashboard loads | HTTP 200, Meridian branding | PASS |
| 4 | JavaScript bundle loads | HTTP 200 | PASS (`/assets/app.js`) |
| 5 | CSS loads | HTTP 200 | PASS (`/assets/style.css`) |
| 6 | Public projects API returns valid JSON | 200, 6 projects | PASS |
| 7 | Internal preview returns valid JSON | 200, `project.name = Orion Internal Platform` | PASS |
| 8 | Internal preview contains the runtime flag | equals instance value | PASS |
| 9 | Health endpoint exposes no flag | no `AXUM{` | PASS |
| 10 | Internal endpoint requires no authentication | 200 without credentials | PASS |
| 11 | Bundle uses a normal script reference | `<script src="/assets/app.js"` | PASS |

## 2. Frontend leakage checks

| Check | Result |
|---|---|
| Bundle contains the internal route | PASS (`/api/internal/project-preview`) |
| Route is part of a named configuration entry | PASS (`internalPreview`) |
| Bundle contains the flag | PASS — absent |
| Bundle contains the internal project record | PASS — absent |
| HTML contains the flag | PASS — absent |
| CSS contains the flag | PASS — absent |
| Source maps served or present in `public/` | PASS — none (`*.map` → 404) |
| Initial load does not request the internal endpoint | PASS (behavioural check) |
| Feature switch is off in the public bundle | PASS (`internalPreview: false`) |
| Container logs contain the flag | PASS — absent |
| Image contains no flag | PASS (`grep -r "AXUM{" /app`) |

### Auto-request check

`tests/check-no-autoload.js` evaluates the served bundle with a stub DOM and a
recording `fetch`, then asserts no internal URL was requested:

```json
{ "fetched": ["/api/projects"], "internalRequests": [] }
```

The check was validated against a deliberately modified bundle
(`internalPreview: true`), which produced
`{"fetched": ["/api/projects", "/api/internal/project-preview"]}` and exit
code 1 — so the assertion is meaningful, not vacuous.

### Browser observation

Loading the dashboard in Chromium recorded the resource list:

```
/assets/style.css, /assets/app.js, /api/projects
```

No `/api/internal/...` request, confirming the page never fetches the exposed
endpoint on its own.

## 3. Dynamic flag isolation

| Instance | `GZCTF_FLAG` | Internal preview returns |
|---|---|---|
| A | `AXUM{team_a_test_flag}` | exactly this value |
| B | `AXUM{team_b_test_flag}` | exactly this value |

Also verified: instance A's response never contains `team_b_test_flag`, instance
B's response never contains `team_a_test_flag`, and neither value appears in the
built image or in any public asset.

## 4. Container security

| Check | Result |
|---|---|
| Non-root runtime | PASS (`uid=1000(node)`) |
| Not privileged | PASS (`HostConfig.Privileged = false`) |
| No Docker socket | PASS |
| No host mounts | PASS (`Mounts = []`) |
| Production dependencies only | PASS (`express` + transitive; `npm ci --omit=dev`) |
| No real secrets in the image | PASS |
| Clean SIGTERM shutdown | PASS (exit code 0) |
| Healthcheck | PASS (`healthy`) |
| Resource limits documented | 1 CPU (0.1 core), 128 MB RAM, 64 MB storage |

## 5. GZ::CTF integration (executed)

`tests/gzctf_e2e.py` created a throw-away game and `DynamicContainer` challenge,
registered two players with separate teams, launched one container per team,
**discovered the route from the served bundle**, and recovered both flags.

| Check | Result |
|---|---|
| Game and challenge created through the admin API | PASS (game 11, challenge 10) |
| Challenge saved with `AXUM{hidden_in_plain_sight_[TEAM_HASH]}` | PASS |
| One instance per team | PASS |
| Route discoverable from the bundle on each instance | PASS (`/api/internal/project-preview`) |
| Distinct flags per team | PASS — A: `AXUM{hidden_in_plain_sight_28b3eae7ffea}`, B: `AXUM{hidden_in_plain_sight_1fdd9ee75bed}` |
| Flags match the template | PASS |
| Cross-instance flag leakage | PASS — none observed |
| Team A's own flag accepted | PASS (`Accepted`) |
| Team B's own flag accepted | PASS (`Accepted`) |
| Team A submitting team B's flag | PASS (rejected: `WrongAnswer`) |
| Team B submitting team A's flag | PASS (rejected: `WrongAnswer`) |
| Cleanup | game deleted; running containers removed manually (platform behaviour) |

## 6. Participant simulation

Performed from the participant description and the hint only:

1. Opened the portal: a normal-looking project dashboard, no mention of internal
   data.
2. Opened DevTools → Network and reloaded. The page loaded `app.js`,
   `style.css` and `/api/projects` only.
3. Opened `app.js` in the Sources panel and searched for `internal`. The
   configuration entry and `loadInternalProjectPreview` were visible within a few
   seconds of scrolling; no minification or obfuscation to work through.
4. Copied the route into a new request: `/api/internal/project-preview`.
5. Read the JSON, found `project.name` and `flag`, and submitted it.

Findings: the hint ("resources loaded by the application") is enough to send a
solver to the bundle; the route string is plain and searchable; the response is
small and self-describing. Estimated solve time 5–15 minutes, in line with the
10–15 minute target.

## 7. Not executed

| Item | Reason |
|---|---|
| Registry push/pull from the platform host | No registry in the test environment; a locally built image was used. The image is registry-agnostic. |
| Kubernetes provider | Only the Docker provider was available. |
| External `PublicEntry` reachability | The local platform has no `PublicEntry`; the script falls back to the published port on loopback. |
| Load / many concurrent teams | Functional two-team validation only. |

## 8. Platform notes

* Deleting a game in GZ::CTF 1.9.1 removes its database records but can leave
  containers running until the manager reaps them (default lifetime 120 min).
* Without `ContainerProvider.PublicEntry`, `Container.Entry` reports the
  container network address with the published host port; the port remains
  reachable on the platform host, and `PublicEntry` should be configured for an
  event.
