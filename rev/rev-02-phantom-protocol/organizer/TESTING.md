# REV-02 — Testing Report

Everything below was executed on the organizer workstation. Commands are quoted
exactly as run; results are the observed output.

## Environment

| Item | Value |
|---|---|
| Image | `rev-02-phantom-protocol:test` (build `alpine:3.20`, runtime `node:22-alpine` + `python3`) |
| GZ::CTF | 1.9.1 (`23ccbbaa`), Docker provider, `PortMappingType: Default`, `PublicEntry: 127.0.0.1` |
| Host OS | Fedora, SELinux enforcing |

## 1. Full suite

```console
$ ./tests/run-tests.sh rev-02-phantom-protocol:test
== building rev-02-phantom-protocol:test ==
image built

== test_generation ==   Ran 11 tests in 0.449s   OK
== test_validation ==   Ran 19 tests in 8.854s   OK
== test_isolation ==    Ran  6 tests in 12.318s  OK
== test_security ==     Ran  8 tests in 7.636s   OK

ALL SUITES PASSED
```

**44 tests, 0 failures.**

### test_generation (11)

```text
ok  test_reference_vector_matches_generator
ok  test_serialized_header_matches_specification
ok  test_missing_flag_fails_clearly
ok  test_empty_flag_fails_clearly
ok  test_over_long_flag_is_rejected
ok  test_valid_flag_produces_valid_protocol_data
ok  test_archive_contains_only_participant_files
ok  test_archive_contains_no_plaintext_flag
ok  test_different_flags_produce_different_payloads
ok  test_generator_log_does_not_leak_the_flag
ok  test_protocol_payload_is_not_the_plaintext
```

### test_validation (19) — binary executed inside the challenge container

```text
ok  test_usage_without_arguments
ok  test_usage_on_invalid_argument_count
ok  test_usage_on_unknown_option
ok  test_correct_token_is_accepted
ok  test_incorrect_token_is_denied
ok  test_empty_candidate_is_denied
ok  test_shorter_candidate_is_denied
ok  test_missing_data_file_is_reported
ok  test_bad_magic_is_rejected
ok  test_unsupported_version_is_rejected
ok  test_zero_length_is_rejected
ok  test_excessive_length_is_rejected
ok  test_truncated_file_is_rejected
ok  test_extra_data_is_rejected
ok  test_reserved_bytes_must_be_zero
ok  test_single_byte_payload
ok  test_maximum_length_payload
ok  test_binary_never_prints_the_token
ok  test_cross_check_independent_forward_implementation
```

### test_isolation (6) — two containers, different flags

```text
ok  test_each_instance_recovers_its_own_flag
ok  test_payloads_differ_between_instances
ok  test_archives_contain_no_foreign_flag
ok  test_archives_are_distinct
ok  test_client_rejects_foreign_token_against_local_data
ok  test_download_endpoint_serves_only_its_own_archive
```

### test_security (8)

```text
ok  test_runs_as_non_root_user              (Config.User=node, id -u = 1000)
ok  test_container_is_not_privileged        (no privileged, no binds, no mounts, not host net)
ok  test_only_the_http_port_is_published    (single 3000/tcp mapping)
ok  test_no_docker_socket_inside_the_container
ok  test_no_plaintext_flag_in_the_image     (grep -ralF inside a fresh container over /app)
ok  test_image_configuration_has_no_flag
ok  test_download_service_process_has_no_flag   (/proc/<pid>/environ of node server.js)
ok  test_logs_do_not_contain_the_flag
```

## 2. Cross-implementation check

The generator (Python), the C client and the organizer recovery script are three
independent implementations of the same specification. Evidence:

* `tests/test_generation.py::test_reference_vector_matches_generator` asserts the
  generator reproduces a hard-coded payload for
  `AXUM{phantom_vector_01}` →
  `69ef3d93d8eeab37fdaaf122ca9917b572748f994afb54`.
* `tests/test_validation.py::test_cross_check_independent_forward_implementation`
  asserts a third implementation, written inside the test file, produces the same
  payload the container's generator wrote.
* `tests/test_validation.py::test_correct_token_is_accepted` asserts the compiled
  C client accepts the flag the generator encoded.
* `scripts/verify_solution.py` recovers the exact original flag from that data
  (see below).

Observed recovery from a live container:

```console
$ docker run -d --name ph -e 'GZCTF_FLAG=GZCTF{PHANTOM_TEST_TOKEN}' \
    -p 127.0.0.1:3320:3000 rev-02-phantom-protocol:dev
$ curl -s -o /tmp/ph.zip http://127.0.0.1:3320/download
$ python3 scripts/verify_solution.py --archive /tmp/ph.zip
protocol data    : /tmp/ph.zip::phantom-protocol/protocol.dat (33 bytes)
payload length   : 25 bytes
recovered token  : GZCTF{PHANTOM_TEST_TOKEN}
```

```console
$ unzip -p /tmp/ph.zip phantom-protocol/protocol.dat | xxd | head -3
00000000: 5048 544d 0119 0000 99e9 63f7 7f99 9b71  PHTM......c....q
00000010: 56cc 55aa c308 313e 7d93 edb5 ba95 c4de  V.U...1>}.......
00000020: f1                                       .
```

The header is `PHTM`, version `1`, length `0x19` (25), reserved `0x0000`, and
the 25 payload bytes contain no plaintext flag.

## 3. Platform validation (GZ::CTF 1.9.1)

```bash
python3 tests/gzctf_e2e.py --base-url http://127.0.0.1:3000 \
  --admin-user Admin --admin-pass '<redacted>' \
  --image rev-02-phantom-protocol:test
```

Result: **passed**.

```text
[gzctf-e2e] game 17 / challenge 16 configured as DynamicContainer
[gzctf-e2e] team-a: container running at 127.0.0.1:32792
[gzctf-e2e] team-a: downloaded 21214 byte package from http://127.0.0.1:32792
[gzctf-e2e] team-a: recovered AXUM{phantom_protocol_c8b4384e4168}
[gzctf-e2e] team-b: container running at 127.0.0.1:32793
[gzctf-e2e] team-b: recovered AXUM{phantom_protocol_1e11a2fa508d}
[gzctf-e2e] team-a: own flag accepted by GZ::CTF
[gzctf-e2e] team-b: own flag accepted by GZ::CTF
[gzctf-e2e] team-a: team B's flag rejected (status WrongAnswer)
[gzctf-e2e] team-b: team A's flag rejected (status WrongAnswer)
[gzctf-e2e] validation game deleted
```

Confirms on the real platform: `DynamicContainer` with `category: Reverse` and
`exposePort: 3000` is accepted; `GZCTF_FLAG` reaches the generator only;
`[TEAM_HASH]` expands to 12 hex characters; the package downloads through the
platform entry URL; static recovery yields each team's own token; cross-team
submissions are rejected.

Test artefacts (game, containers, players, teams) were removed afterwards.

## 4. Browser verification

Chromium through the VS Code browser tools.

| Viewport | Result |
|---|---|
| 1440 × 1000 | Brand bar, hero, two-column cards, analyst notes and footer render correctly; download link targets `/download`; no horizontal overflow (1425 / 1440) |
| 390 × 844 | Single-column layout, full-width download button, stacked definition list; no horizontal overflow (375 / 390) |

The page contains no key material and no token.

## 5. Binary properties (observed)

```text
$ file phantom-client
ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked,
BuildID[sha1]=530dcabd322df1ef209a9ca47774e6b85aef2891, stripped
```

* statically linked → runs on any Linux x86_64 host;
* stripped → no symbol names, matching the Hard difficulty;
* the three stage helpers survive as separate functions and all constants are
  visible in code (`add $0x2b,%eax`, `lea 0x3(%rdi,%rdi,4)`, `rol %cl,%al`) and
  in `.rodata` (`AegisPhantomKey!` at `0x408290`).

## 6. Status summary

| Area | Status | Evidence |
|---|---|---|
| C source implementation | PASS | compiled by the `build` stage; validation exercised by 19 binary tests |
| Transformation stages | PASS | add/XOR/rotate visible in disassembly; verified by round-trip recovery |
| Runtime artifact generation | PASS | missing/empty/over-long/non-ASCII flags rejected; valid flag produces a valid file |
| Protocol format | PASS | header fields asserted; magic, version, length, reserved, truncation and trailing bytes all rejected |
| ZIP package | PASS | exactly three files, correct directory, binary mode 0755, no plaintext flag |
| Download service | PASS | `/`, `/assets/*`, `/download`, `/health` verified; 404 for unknown paths |
| Static recovery | PASS | `scripts/verify_solution.py` recovers the exact injected token on every instance |
| Dynamic flag integration | PASS | platform-injected per-team flags accepted by GZ::CTF |
| Two-instance isolation | PASS | distinct payloads, distinct archives, no cross-team flag, foreign token rejected |
| Non-root runtime | PASS | `Config.User=node`, `id -u` = 1000 |
| Docker build | PASS | multi-stage build succeeds; C toolchain absent from runtime |
| GZ::CTF schema validation | PASS | `Reverse`, `DynamicContainer`, `ContainerConfig`, `Hints` inspected in 1.9.1 and accepted |
| GZ::CTF deployment | PASS | two-team end-to-end run |
| Organizer documentation | PASS | `WRITEUP.md`, `DEPLOYMENT.md`, `TESTING.md` |

Not executed:

* Kubernetes provider deployment — **NOT TESTED**.
* Traffic capture (`enableTrafficCapture: true`) — **NOT TESTED** (disabled by design).
* `linux/arm64` image build — **NOT TESTED** (challenge targets x86_64).

## 7. Defects found during verification

| Defect | Cause | Fix |
|---|---|---|
| `docker port CONTAINER:3000/tcp` failed in the test helper | This Docker version requires the port as a separate argument | Use `docker port CONTAINER 3000/tcp` |
| Security test compared `str` to `bytes` | `support.run()` uses `text=True`, `ChallengeInstance.exec()` does not | Compare against the correct type per helper |
| `HostConfig.Binds` assertion | Docker reports `null`, not `[]`, when no bind mounts are configured | Accept `None` or `[]` |
