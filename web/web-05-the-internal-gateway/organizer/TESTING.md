# WEB-05 — Testing Report

All results below were produced by executing the commands shown, on the
organizer workstation, with GZ::CTF 1.9.1 (`23ccbbaa`) running locally.

## Environment

| Item | Value |
|---|---|
| Node.js (host) | v24.18.0 (image uses `node:22-alpine`) |
| Image | `web-05-internal-gateway:test` |
| GZ::CTF | 1.9.1, Docker provider, `PortMappingType: Default`, `PublicEntry: 127.0.0.1` |
| Host OS | Fedora, SELinux enforcing |

## 1. Local Docker suite

```bash
./tests/run-local-docker-tests.sh
```

Result: **66 checks, 0 failed**.

| Section | Checks | Result |
|---|---|---|
| Image build | 1 | PASS |
| Startup failure handling (missing / empty / blank flag) | 3 | PASS |
| Two-instance startup and health | 4 | PASS |
| Gateway surface (7 routes + branding + catalogue) | 9 | PASS |
| Flag separation in assets, APIs and logs | 7 | PASS |
| Process environment separation | 2 | PASS |
| Internal service isolation | 3 | PASS |
| URL validation (malformed, `file:`, `gopher:`, missing) | 5 | PASS |
| Functional preview (status, body, content type, HTML as text) | 5 | PASS |
| Redirect, size cap and timeout | 5 | PASS |
| Header filtering | 3 | PASS |
| SSRF solve path (health → catalogue → record → flag) | 5 | PASS |
| Two-instance flag isolation | 5 | PASS |
| Image and runtime hardening | 9 | PASS |
| Clean SIGTERM shutdown | 1 | PASS |

Key evidence from the run:

```text
PASS gateway process environment has no GZCTF_FLAG
PASS internal process environment carries GZCTF_FLAG
PASS internal port 9000 is not published
PASS internal service is unreachable from other containers on the network
PASS redirect is not followed (302 relayed)
PASS oversized response is flagged as truncated
PASS response body capped at 64 KiB (got 65536 bytes)
PASS slow upstream times out with 504
PASS closed port returns 502 without a stack trace
PASS set-cookie header is not relayed
PASS diagnostics record returns team A's flag through the gateway
PASS instance B never returns team A's flag
PASS instance A never returns team B's flag
PASS no flag is baked into the image
PASS container stops cleanly on SIGTERM (exit 143)
```

After the first run, one check failed because the test harness measured the
JSON-decoded body with a trailing newline (`65537` bytes instead of `65536`).
The measurement was corrected in the suite; the application limit itself was
never wrong.

The fixture upstream is delivered to its container as base64 rather than a bind
mount, because the test host runs SELinux in enforcing mode and denied the mount
(`ls: can't open '/fixtures': Permission denied`). This affects the harness only.

## 2. GZ::CTF platform validation

```bash
python3 tests/gzctf_e2e.py \
  --base-url http://127.0.0.1:3000 \
  --admin-user Admin --admin-pass '<redacted>' \
  --image web-05-internal-gateway:test
```

Result: **passed**.

```text
[gzctf-e2e] game 15 / challenge 14 configured as DynamicContainer
[gzctf-e2e] team-a: container running at 127.0.0.1:32788
[gzctf-e2e] team-a: catalogue exposed internal probe: http://127.0.0.1:9000/internal/health
[gzctf-e2e] team-a: preview of http://127.0.0.1:9000/internal/health -> HTTP 200
[gzctf-e2e] team-a: internal catalogue retrieved through the gateway
[gzctf-e2e] team-a: diagnostics record MD-OPS-204 retrieved through the gateway
[gzctf-e2e] team-a: recovered AXUM{internal_gateway_a4aebab9c118}
[gzctf-e2e] team-b: container running at 127.0.0.1:32789
[gzctf-e2e] team-b: diagnostics record MD-OPS-204 retrieved through the gateway
[gzctf-e2e] team-b: recovered AXUM{internal_gateway_2e5d3a1034b9}
[gzctf-e2e] team-a: own flag accepted by GZ::CTF
[gzctf-e2e] team-b: own flag accepted by GZ::CTF
[gzctf-e2e] team-a: team B's flag rejected (status WrongAnswer)
[gzctf-e2e] team-b: team A's flag rejected (status WrongAnswer)
[gzctf-e2e] validation game deleted
```

This confirms on the real platform:

* `DynamicContainer` deployment with `exposePort: 3000` works;
* `GZCTF_FLAG` reaches the internal process and only the internal process;
* `[TEAM_HASH]` expands to 12 hex characters (`a4aebab9c118`, `2e5d3a1034b9`);
* the SSRF path is solvable end to end through the platform entry URL;
* per-team flags are isolated and cross-team submissions are rejected.

Test artefacts (game, containers, players, teams) were removed afterwards.

## 3. Browser verification

Chromium through the VS Code browser tools, against a container started with
`GZCTF_FLAG=AXUM{ui_review_flag}`.

| Viewport | Result |
|---|---|
| 1440 × 1000 | Four metric cards in a row, integrations table with all five columns visible, preview panel renders status `HTTP 200`, target, duration, body size, relayed headers and the escaped JSON body |
| 390 × 844 | Sidebar collapses to a horizontal nav without a stray scrollbar, metrics render two-up, form stacks with a correctly sized input, response panel and history render correctly |

The internal record was rendered with `verification_token: "AXUM{ui_review_flag}"`
inside a `<pre>` block as text — no HTML/JS in previewed bodies is executed
(preview responses are served as `application/json`).

## 4. Status summary

| Area | Status | Evidence |
|---|---|---|
| Application implementation (frontend) | PASS | Browser checks at 1440 px and 390 px; `/`, `/assets/app.js`, `/assets/styles.css`, `/assets/favicon.svg` all return 200 |
| Internal API | PASS | `/internal/health`, `/internal/services`, `/internal/diagnostics/record` exercised through the gateway |
| SSRF behavior | PASS | Local suite plus platform run both retrieve the record and flag through `POST /api/integrations/preview` |
| Dynamic flag | PASS | Platform-injected flags differ per team and are accepted by GZ::CTF |
| Gateway environment separation | PASS | `/proc/<pid>/environ` checks inside the container |
| Docker build | PASS | `docker build` succeeds; image is production-only, non-root, no `EXPOSE` |
| Non-root runtime | PASS | `Config.User=node`, `id -u` = 1000 |
| Multi-instance isolation | PASS | Two containers with different flags never expose each other's value |
| GZ::CTF schema validation | PASS | `ContainerConfig`, `ChallengeType`, `Challenge.Hints` inspected in the 1.9.1 sources; configuration accepted by the platform |
| GZ::CTF deployment | PASS | Two-team end-to-end run on GZ::CTF 1.9.1 |
| Organizer documentation | PASS | `WRITEUP.md`, `SOLUTION.md`, `DEPLOYMENT.md`, `TESTING.md` |

Not executed (documented as unverified in `DEPLOYMENT.md`):

* Kubernetes provider deployment — NOT TESTED.
* Traffic capture proxy (`enableTrafficCapture: true`) — NOT TESTED, disabled by design.
