# REV-01 — Testing Report

All results below were produced by executing the commands shown, on the
organizer workstation, with GZ::CTF 1.9.1 (`23ccbbaa`) running locally.

## Environment

| Item | Value |
|---|---|
| Image | `rev-01-broken-license:dev` (build stage `alpine:3.20`, runtime `node:22-alpine`) |
| GZ::CTF | 1.9.1, Docker provider, `PortMappingType: Default`, `PublicEntry: 127.0.0.1` |
| Host OS | Fedora, SELinux enforcing |

## 1. Local Docker suite

```bash
./tests/run-local-docker-tests.sh rev-01-broken-license:dev
```

Result: **66 checks, 0 failed**.

| Section | Checks | Result |
|---|---|---|
| Image build | 1 | PASS |
| C source / ELF diagnostics | 9 | PASS |
| Startup rejection of bad `GZCTF_FLAG` values | 6 | PASS |
| Three-instance startup | 4 | PASS |
| Download service surface | 12 | PASS |
| Artifact generation | 7 | PASS |
| Independent static recovery | 1 | PASS |
| C validator behaviour | 7 | PASS |
| Per-team isolation | 5 | PASS |
| Flag handling in logs / env / image | 5 | PASS |
| Container hardening | 8 | PASS |
| Clean SIGTERM shutdown | 1 | PASS |

### ELF diagnostics

```text
ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked,
BuildID[sha1]=89c9359bcaff3523828934d174efa0bcc81b5081, not stripped
PASS binary is ELF64 x86_64
PASS binary is statically linked and runs on any Linux x86_64 host
PASS symbols are retained for the intended analysis
PASS binary contains no debug information
PASS validate_license symbol is present in the symbol table
PASS transformation key is discoverable in .rodata
PASS no plaintext team flag appears in the binary
```

### Startup rejection

```text
PASS missing flag aborts startup (exit 1)
PASS empty flag aborts startup (exit 1)
PASS blank flag aborts startup (exit 1)
PASS over-long flag is rejected instead of truncated (exit 1)
PASS rejection message does not disclose the flag
PASS non-ASCII flag is rejected (exit 1)
```

### Static recovery (mandatory test)

Recovery uses only the packaged ELF and `license.dat`; the generator's plaintext
value is never consulted.

```text
PASS recovery from the artifact equals the injected flag
     binary            : …/northstar-license-package/northstar-license
     data file         : …/northstar-license-package/license.dat (22 bytes)
     .rodata literals  : 243
     candidate keys    : 1 matched
     xor key recovered : NorthstarK3y (12 bytes)
     accepted license  : GZCTF{REV01_TEST_FLAG}
```

### C validator behaviour

```text
PASS recovered key is accepted by the packaged binary
PASS incorrect key is rejected
PASS key with the wrong length is rejected
PASS missing license.dat is reported clearly
PASS empty license.dat is rejected as malformed
PASS oversized license.dat is rejected as malformed
PASS empty input is handled without a crash
```

### Per-team isolation

Three instances were started: A with `GZCTF{REV01_TEST_FLAG}`, B with
`GZCTF{TEAM_A_TEST}`, C with `GZCTF{TEAM_B_TEST}`.

```text
PASS instance B's archive recovers instance B's flag
PASS instance C's archive recovers instance C's flag
PASS the two instances produced different license data
PASS instance A's archive contains no other team's flag
PASS per-team archives differ (37b103fd29bd vs b33e8043c8b2)
```

### Flag handling and hardening

```text
PASS container logs contain no plaintext flag
PASS download service environment has no GZCTF_FLAG
PASS no team flag is baked into the image
PASS the image configuration declares no GZCTF_FLAG
PASS the image configuration contains no team flag value
PASS image runs as the non-root node user
PASS runtime uid is 1000
PASS container is not privileged
PASS no host directory is bind-mounted
PASS container declares no mounts
PASS the Docker socket is not mounted
PASS container uses bridge networking, not host networking
PASS exactly one port is published
PASS container stops cleanly on SIGTERM (exit 0)
```

## 2. Platform validation (GZ::CTF 1.9.1)

```bash
python3 tests/gzctf_e2e.py --base-url http://127.0.0.1:3000 \
  --admin-user Admin --admin-pass '<redacted>' \
  --image rev-01-broken-license:dev
```

Result: **passed**.

```text
[gzctf-e2e] game 16 / challenge 15 configured as DynamicContainer
[gzctf-e2e] team-a: container running at 127.0.0.1:32790
[gzctf-e2e] team-a: downloaded 24079 byte package from http://127.0.0.1:32790
[gzctf-e2e] team-a: recovered AXUM{broken_license_8dc2e9e64911}
[gzctf-e2e] team-b: container running at 127.0.0.1:32791
[gzctf-e2e] team-b: downloaded 24079 byte package from http://127.0.0.1:32791
[gzctf-e2e] team-b: recovered AXUM{broken_license_4c7cff778196}
[gzctf-e2e] team-a: own flag accepted by GZ::CTF
[gzctf-e2e] team-b: own flag accepted by GZ::CTF
[gzctf-e2e] team-a: team B's flag rejected (status WrongAnswer)
[gzctf-e2e] team-b: team A's flag rejected (status WrongAnswer)
[gzctf-e2e] validation game deleted
```

This confirms on the real platform:

* `DynamicContainer` with `category: Reverse` and `exposePort: 3000` is accepted;
* `GZCTF_FLAG` reaches the generator and is absent from the long-lived service;
* `[TEAM_HASH]` expands to 12 hex characters (`8dc2e9e64911`, `4c7cff778196`);
* the download page and `/download` work through the platform entry URL;
* static recovery from the downloaded artifact yields each team's own flag;
* per-team flags are isolated and cross-team submissions are rejected.

Test artefacts (game, containers, players, teams) were removed afterwards.

## 3. Browser verification

Chromium through the VS Code browser tools.

| Viewport | Result |
|---|---|
| 1440 × 1000 | Brand bar, hero, two-column package/instructions cards, notice block and footer render correctly; download link targets `/download`; no horizontal overflow (`scrollWidth` 1425 of 1440) |
| 390 × 844 | Single-column layout, full-width download button, stacked definition list, footer stacked; no horizontal overflow (`scrollWidth` 375 of 390) |

The page contains no transformation key and no flag (asserted in the local
suite: `landing page does not disclose the transformation key`).

## 4. Defects found and fixed during verification

| Defect | Cause | Fix |
|---|---|---|
| Binary shipped with `.debug_*` sections | Statically linked musl libc objects carry DWARF into the output; `-g0` alone does not remove it | Added `objcopy --strip-debug`, which keeps `.symtab` (`not stripped`) and drops all nine `.debug_*` sections; binary shrank 260 400 → 50 680 bytes |
| Test expected a quoted `Content-Disposition` filename | Express 5 omits quotes for token-safe filenames | Assertion accepts both `filename=x` and `filename="x"` |
| Test asserted no `GZCTF_FLAG` in the runtime container config | The platform necessarily passes the flag with `docker run -e`, so `Config.Env` records the key | Replaced with image-config assertions plus the existing `/proc/<pid>/environ` check on the server process |
| Stray container from an interrupted `apk` probe held the package mirror | Leftover `docker run` from a diagnostic command | Removed; it was also the cause of an unusually slow first build |

## 5. Status summary

| Area | Status | Evidence |
|---|---|---|
| C source implementation | PASS | Compiled by the `build` stage; `validate_license` and `NORTHSTAR_XOR_KEY` present |
| ELF build | PASS | `file`: ELF 64-bit LSB executable, x86-64, statically linked, not stripped, no DWARF |
| XOR validation | PASS | Correct key accepted, wrong key and wrong length rejected |
| Runtime artifact generation | PASS | Generator rejects missing/empty/blank/over-long/non-ASCII flags; `license.dat` produced per instance |
| ZIP package | PASS | Exactly `northstar-license-package/{README.txt,license.dat,northstar-license}`; binary mode 0755; no plaintext flag inside |
| Download service | PASS | `/`, `/assets/*`, `/download`, `/health` verified; 404 for unknown paths; correct content type and filename |
| Static flag recovery | PASS | `tests/recover-flag.py` recovers `GZCTF{REV01_TEST_FLAG}` and each team's platform flag from ELF + data only |
| Dynamic flag integration | PASS | Platform-injected flags differ per team and are accepted by GZ::CTF |
| Two-instance isolation | PASS | Different `license.dat`, different archives, no cross-team flag in any artifact |
| Non-root container | PASS | `Config.User=node`, `id -u` = 1000 |
| Docker build | PASS | Multi-stage build succeeds; C toolchain absent from the runtime stage |
| GZ::CTF schema validation | PASS | `ChallengeCategory.Reverse`, `ChallengeType.DynamicContainer`, `ContainerConfig.Image/ExposedPort`, `Challenge.Hints` inspected in 1.9.1 and accepted by the platform |
| GZ::CTF deployment | PASS | Two-team end-to-end run on GZ::CTF 1.9.1 |
| Organizer documentation | PASS | `WRITEUP.md`, `SOLUTION.md`, `DEPLOYMENT.md`, `TESTING.md` |

Not executed:

* Kubernetes provider deployment — **NOT TESTED**.
* Traffic capture (`enableTrafficCapture: true`) — **NOT TESTED** (disabled by design).
* `linux/arm64` image build — **NOT TESTED** (challenge targets x86_64).
