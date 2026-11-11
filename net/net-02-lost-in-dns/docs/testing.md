# NET-02 — Lost in DNS: testing report

Every result below was produced by executing the command shown.

## Environment

| Item | Value |
|---|---|
| Image | `net-02-lost-in-dns:test` (`python:3.12-alpine3.21` + `scapy==2.8.0`) |
| GZ::CTF | 1.9.1 (`23ccbbaa`), Docker provider, `PortMappingType: Default`, `PublicEntry: 127.0.0.1` |
| Analysis tools | Scapy 2.8.0 (host + image), `tcpdump` as an independent parser |
| Host OS | Fedora, SELinux enforcing |

## 1. Full suite

```console
$ ./tests/run-tests.sh net-02-lost-in-dns:test
== building net-02-lost-in-dns:test ==
image built

== test_encoding ==  Ran 28 tests in 0.001s   OK
== test_capture ==   Ran 20 tests in 0.080s   OK
== test_flag ==      Ran 13 tests in 2.352s   OK
== test_app ==       Ran 18 tests in 14.921s  OK

ALL SUITES PASSED
```

**79 tests, 0 failures.**

### test_encoding (28)

Covers the requirement list directly:

```text
ok  test_normal_flag_encoding                 ok  test_missing_fragment_is_detected
ok  test_single_byte_flag                     ok  test_duplicate_fragment_is_detected
ok  test_empty_flag_is_rejected               ok  test_unrelated_names_are_ignored
ok  test_non_string_is_rejected               ok  test_reassembly_without_fragments_is_an_error
ok  test_over_long_flag_is_rejected           ok  test_invalid_utf8_payload_is_rejected
ok  test_utf8_flag_encoding                   ok  test_suspicious_suffix_is_consistent
ok  test_multiple_fragments                   ok  test_query_name_layout
ok  test_short_payload_single_fragment        ok  test_sequence_labels
ok  test_odd_final_fragment_is_rejected       ok  test_label_length_limits
ok  test_empty_payload_is_rejected            ok  test_sequence_overflow_is_rejected
ok  test_non_hex_payload_is_rejected          ok  test_reconstruction_roundtrip
ok  test_uppercase_hex_is_rejected            ok  test_reconstruction_handles_unordered_input
ok  test_odd_fragment_size_is_rejected        ok  test_short_flag_roundtrip
ok  test_validate_fragment_limits             ok  test_long_flag_roundtrip
```

### test_capture (20)

```text
ok  test_capture_is_written_and_readable      ok  test_no_plaintext_flag_in_capture
ok  test_layer_structure                      ok  test_interleaving
ok  test_dns_destination_port                 ok  test_responses_are_present_for_most_queries
ok  test_client_and_resolver_addresses        ok  test_transaction_ids_are_valid
ok  test_normal_traffic_volume                ok  test_timestamps_are_monotonic
ok  test_mixed_query_types                    ok  test_ephemeral_source_ports
ok  test_suspicious_fragment_count_and_order  ok  test_size_is_reasonable
ok  test_suspicious_queries_are_txt_type      ok  test_normal_query_catalogue_is_plausible
ok  test_reconstruction_matches_the_flag      ok  test_validation_rejects_a_wrong_flag
ok  test_atomic_publish_leaves_no_temporary_files   ok  test_missing_flag_cannot_generate
```

### test_flag (13)

```text
ConfigTests
ok  test_missing_flag_is_rejected          ok  test_capture_path_override
ok  test_empty_flag_is_rejected            ok  test_repr_never_contains_the_flag
ok  test_default_port                      ok  test_flag_is_not_required_for_the_web_process
ok  test_custom_port                       ok  test_invalid_log_level_is_rejected
ok  test_invalid_port_is_rejected
GeneratorProcessTests
ok  test_generator_fails_without_flag      ok  test_generator_does_not_log_the_flag
ok  test_generator_fails_with_blank_flag   ok  test_generator_rejects_over_long_flag
```

### test_app (18)

```text
AppTests (real server, generated artifact)
ok  test_landing_page                 ok  test_unknown_path_is_404
ok  test_landing_page_reports_size    ok  test_path_traversal_is_prevented
ok  test_download                     ok  test_landing_page_has_no_flag
ok  test_download_payload_decodes_to_the_flag   ok  test_no_directory_listing
ok  test_health                       ok  test_missing_artifact_is_handled
ok  test_stylesheet
IntegrationTests (containers, two teams)
ok  test_container_generates_the_capture_at_runtime
ok  test_download_reconstructs_the_exact_injected_flag
ok  test_second_team_gets_a_separate_artifact
ok  test_no_cross_contamination
ok  test_no_plaintext_flag_in_logs_or_pages
ok  test_runs_as_non_root_without_capabilities
ok  test_service_process_has_no_flag
```

## 2. Participant workflow (executed)

```console
$ docker run -d --name n2 -e 'GZCTF_FLAG=GZCTF{LOST_IN_DNS_TEST_FLAG}' \
    -p 127.0.0.1:3340:8080 net-02-lost-in-dns:dev
$ docker logs n2
[..] INFO net02.capture: wrote capture.pcap (7594 bytes, 67 packets, 35 queries, 32 responses, 3 fragments)
[..] INFO net02.app: listening on 0.0.0.0:8080

$ curl -s http://127.0.0.1:3340/health
{"status": "ok", "service": "lost-in-dns", "capture": "ready"}

$ curl -s -o n2.pcap -D - http://127.0.0.1:3340/download | grep -iE 'HTTP/|content-type|content-disposition'
HTTP/1.0 200 OK
Content-Type: application/vnd.tcpdump.pcap
Content-Disposition: attachment; filename="capture.pcap"
```

Suspicious queries seen with tcpdump (independent parser):

```console
$ tcpdump -nn -r n2.pcap | grep telemetry.example.test
10.20.4.77.49799 > 10.20.0.53.53: 61969+ TXT? 001.475a4354467b4c4f53545f49.telemetry.example.test. (69)
10.20.4.77.49967 > 10.20.0.53.53: 44144+ TXT? 002.4e5f444e535f4558414d504c.telemetry.example.test. (69)
10.20.4.77.50108 > 10.20.0.53.53: 49418+ TXT? 003.455f464c41477d.telemetry.example.test. (59)
```

Decoded with the shared encoding module:

```console
fragments: 3
recovered: GZCTF{LOST_IN_DNS_TEST_FLAG}
```

The recovered value equals the injected flag. Plaintext occurrences in the
capture: `0` (verified by `grep -c 'GZCTF{'` over the tcpdump text output and by
`test_no_plaintext_flag_in_capture`).

## 3. Platform validation (GZ::CTF 1.9.1)

```bash
python3 tests/gzctf_e2e.py --base-url http://127.0.0.1:3000 \
  --admin-user Admin --admin-pass '<redacted>' \
  --image net-02-lost-in-dns:test
```

Result: **passed**.

```text
[gzctf-e2e] game 19 / challenge 18 configured as DynamicContainer
[gzctf-e2e] team-a: container running at 127.0.0.1:32796
[gzctf-e2e] team-a: recovered AXUM{lost_in_dns_a1942c0bb83f}
[gzctf-e2e] team-b: container running at 127.0.0.1:32797
[gzctf-e2e] team-b: recovered AXUM{lost_in_dns_8bd2494c06c5}
[gzctf-e2e] team-a: own flag accepted by GZ::CTF
[gzctf-e2e] team-b: own flag accepted by GZ::CTF
[gzctf-e2e] team-a: team B's flag rejected (status WrongAnswer)
[gzctf-e2e] team-b: team A's flag rejected (status WrongAnswer)
[gzctf-e2e] validation game deleted
```

Confirms on the real platform: `DynamicContainer` with category `Forensics` and
`exposePort: 8080` is accepted; `GZCTF_FLAG` reaches only the generator;
`[TEAM_HASH]` expands to 12 hex characters; the PCAP downloads through the
platform entry URL; fragment decoding yields each team's own flag; cross-team
submissions are rejected.

## 4. Browser verification

| Viewport | Result |
|---|---|
| 1440 × 1000 | Brand bar, hero, artifact/mission cards, tools block and footer render correctly; download targets `/download`; file size shown as `7.4 KB`; no horizontal overflow (1425 / 1440) |
| 390 × 844 | Single column, full-width download button, stacked definition list; no horizontal overflow (375 / 390) |

The page never contains the flag, the hex payload, the fragment count or the
suspicious domain (asserted by `test_landing_page_has_no_flag` and manual
inspection of the rendered snapshot).

## 5. Status summary

| Area | Status | Evidence |
|---|---|---|
| Encoding engine | PASS | 28 tests incl. UTF-8, odd fragments, label limits, ordering |
| PCAP generator | PASS | valid libpcap, 67 packets, atomic publish |
| PCAP structure | PASS | Ethernet/IPv4/UDP/DNS on every packet, dport 53 |
| Normal traffic volume | PASS | 32 ordinary queries (A and AAAA) |
| Fragment placement | PASS | exactly the expected `NNN.<hex>.telemetry.example.test` queries, TXT type |
| Interleaving | PASS | fragments separated by normal lookups (asserted) |
| Flag confidentiality | PASS | no plaintext in capture, logs, pages, image |
| Download service | PASS | `/`, `/download`, `/health`, `/static/*`; 404 elsewhere |
| Path traversal | PASS | no user-controlled paths; traversal probes return 404 |
| Application tests | PASS | 11 in-process HTTP tests |
| Integration tests | PASS | 7 container tests incl. two-team separation |
| Non-root container | PASS | UID 10001 |
| Docker build | PASS | pinned base, non-root, no flag baked in |
| GZ::CTF schema | PASS | `Forensics`, `DynamicContainer`, `Hints` inspected in 1.9.1 |
| GZ::CTF deployment | PASS | two-team end-to-end run |
| Documentation | PASS | `README.md`, `docs/challenge.md`, `docs/writeup.md`, `docs/deployment.md` |

Not executed:

* Kubernetes provider deployment — **NOT TESTED**.
* Traffic capture (`enableTrafficCapture: true`) — **NOT TESTED**.
* `linux/arm64` build — **NOT TESTED**.
* `read_only` / `cap_drop: ALL` compose profile under GZ::CTF — the profile was
  written but the platform does not apply those options; only `docker inspect`
  of the default run was checked.

## 6. Defects found and fixed during verification

| Defect | Cause | Fix |
|---|---|---|
| `validate_capture()` raised `ValueError` when validating a wrong flag | `list.index()` on an expected query that is absent | Detect missing names first and record a validation problem |
| `test_capture` crashed with `'str' object has no attribute 'read_bytes'` | Mixed `os.path` strings with `pathlib` in the test | Use `pathlib.Path` consistently and pass `str()` to Scapy |
| `rdpcap()` rejected a `PosixPath` | Scapy expects a filename string or file object | Pass `str(path)` |
| Local generator run failed with `PermissionError` | Default `PCAP_PATH` is `/app/runtime/...`, which is not writable on the host | Document the requirement and set `PCAP_PATH` for local runs |

## 7. Notes

* Scapy 2.8.0 emits `DeprecationWarning` for `DNS.qd` access; the warnings are
  cosmetic and the assertions remain valid for this version.
* `tshark` is not installed on the verification host, so the writeup's `tshark`
  commands were not executed; header/name extraction was demonstrated with
  Scapy and `tcpdump -A`. The `awk | sort | xxd` pipeline is documented as an
  alternative and is not part of the automated suite.
