# NET-03 — The Last Transmission: testing report

Every result below was produced by executing the command shown.

## Environment

| Item | Value |
|---|---|
| Image | `net-03-the-last-transmission:test` (`python:3.12-alpine3.21` + `scapy==2.8.0`) |
| GZ::CTF | 1.9.1 (`23ccbbaa`), Docker provider, `PortMappingType: Default`, `PublicEntry: 127.0.0.1` |
| Analysis tools | Scapy 2.8.0 (host + image), `tcpdump` as an independent parser |
| Host OS | Fedora, SELinux enforcing |

## 1. Full suite

```console
$ ./tests/run-tests.sh net-03-the-last-transmission:test
== building net-03-the-last-transmission:test ==
image built

== test_artifact ==        Ran 17 tests in 0.002s   OK
== test_dns ==             Ran 12 tests in 0.022s   OK
== test_http ==            Ran 12 tests in 0.020s   OK
== test_ftp ==             Ran 16 tests in 0.022s   OK
== test_tcp_reassembly ==  Ran 11 tests in 0.029s   OK
== test_capture ==         Ran 17 tests in 0.412s   OK
== test_flag ==            Ran 15 tests in 3.455s   OK
== test_app ==             Ran 20 tests in 15.322s  OK

ALL SUITES PASSED
```

**118 tests, 0 failures.**

### test_artifact (17)

```text
ok  test_archive_name                        ok  test_validate_bundle_reports_metadata
ok  test_bundle_is_a_valid_zip               ok  test_validate_rejects_wrong_flag
ok  test_expected_internal_path              ok  test_validate_rejects_empty_archive
ok  test_no_unintended_members               ok  test_validate_rejects_corrupt_archive
ok  test_runtime_flag_present_in_evidence    ok  test_empty_flag_is_rejected
ok  test_required_report_content             ok  test_non_string_flag_is_rejected
ok  test_utf8_flag_roundtrip                 ok  test_same_flag_is_deterministic
ok  test_different_flags_produce_different_archives
ok  test_payload_spans_multiple_tcp_segments
ok  test_archive_size_is_reasonable
```

### test_dns (12)

```text
ok  test_dns_layers                     ok  test_background_traffic_present
ok  test_queries_use_port_53            ok  test_a_and_aaaa_lookups_both_present
ok  test_responses_come_from_port_53    ok  test_transaction_ids_are_valid
ok  test_suspicious_query_exists        ok  test_no_flag_in_dns_names
ok  test_suspicious_response_resolves_the_server
ok  test_authoritative_flags_on_response
ok  test_recursion_desired_on_query
ok  test_suspicious_lookup_precedes_http
```

### test_http (12)

```text
ok  test_expected_requests_are_present      ok  test_incident_reference_recoverable
ok  test_request_lines_are_well_formed      ok  test_archive_name_recoverable
ok  test_every_response_is_complete         ok  test_transfer_status_document_is_valid_json
ok  test_content_length_matches_body        ok  test_stream_is_reconstructable
ok  test_no_flag_in_http_traffic            ok  test_background_http_conversation_exists
ok  test_http_precedes_ftp                  ok  test_http_targets_the_resolved_address
```

### test_ftp (16)

```text
ok  test_control_uses_port_21                   ok  test_data_connection_is_separate_from_control
ok  test_greeting_and_login_sequence            ok  test_data_connection_initiated_by_client
ok  test_login_order_is_correct                 ok  test_data_payload_direction
ok  test_pasv_reply_encodes_port_50000          ok  test_payload_equals_the_archive
ok  test_pasv_precedes_retr                     ok  test_payload_is_binary_zip
ok  test_retr_names_the_archive                 ok  test_payload_is_segmented
ok  test_opening_and_completion_replies         ok  test_archive_extracts_to_the_flag
ok  test_no_flag_in_control_messages            ok  test_data_connection_timing
```

### test_tcp_reassembly (11)

```text
ok  test_three_way_handshake                    ok  test_fin_termination
ok  test_sequence_numbers_advance_by_payload_length   ok  test_no_overlapping_payloads
ok  test_segmentation_at_mss                    ok  test_independent_conversations_do_not_interfere
ok  test_acknowledgements_follow_each_segment   ok  test_timestamps_are_monotonic_after_sorting
ok  test_reassembly_preserves_binary_payload    ok  test_real_capture_has_no_retransmissions
ok  test_binary_payload_is_not_text_converted
```

### test_capture (17) — includes the acceptance test

```text
CaptureTests
ok  test_capture_written_and_readable           ok  test_size_is_reasonable
ok  test_packet_layers                          ok  test_no_temporary_file_left_behind
ok  test_dns_precedes_http                      ok  test_validation_rejects_wrong_archive
ok  test_http_precedes_ftp                      ok  test_generation_is_deterministic_for_the_same_flag
ok  test_ftp_control_precedes_data              ok  test_second_flag_produces_a_different_capture
ok  test_background_traffic_is_interleaved      ok  test_no_flag_in_dns_http_or_control
ok  test_all_tcp_conversations_have_a_handshake

EndToEndAcceptanceTests
ok  test_recover_archive_and_flag_from_the_capture
ok  test_payload_matches_the_generated_archive
ok  test_correlation_evidence_is_reachable
ok  test_data_connection_targets_the_resolved_address
```

### test_flag (15)

```text
ConfigTests                        FlagConfidentialityTests
ok  test_missing_flag_is_rejected            ok  test_generator_fails_without_flag
ok  test_empty_flag_is_rejected              ok  test_generator_fails_with_blank_flag
ok  test_default_port                        ok  test_generator_does_not_log_the_flag
ok  test_custom_port                         ok  test_utf8_flag_is_supported
ok  test_invalid_ports_are_rejected          ok  test_flag_only_reachable_through_the_archive
ok  test_default_capture_path
ok  test_capture_path_override
ok  test_log_level_validation
ok  test_repr_never_contains_the_flag
ok  test_web_process_does_not_require_the_flag
```

### test_app (20)

```text
AppTests
ok  test_landing_page                       ok  test_unknown_path_is_404
ok  test_landing_page_reports_size          ok  test_path_traversal_is_prevented
ok  test_download                           ok  test_no_directory_listing
ok  test_download_payload_yields_the_flag   ok  test_landing_page_hides_solution_details
ok  test_health                             ok  test_missing_artifact_is_handled
ok  test_stylesheet_and_favicon

IntegrationTests (containers, two teams)
ok  test_capture_generated_at_runtime           ok  test_runs_as_non_root_without_capabilities
ok  test_download_reconstructs_the_injected_flag  ok  test_service_process_has_no_flag
ok  test_teams_get_independent_artifacts        ok  test_no_docker_socket
ok  test_no_cross_contamination                 ok  test_image_contains_no_flag
ok  test_no_flag_in_logs_or_pages
```

## 2. Mandatory end-to-end acceptance test

`EndToEndAcceptanceTests.test_recover_archive_and_flag_from_the_capture`
satisfies the requirement that the archive be recovered **from the capture**, not
from the generator:

```text
1. generate_capture.generate(flag, capture.pcap)   ← writes and validates
2. rdpcap(capture.pcap)                            ← re-read from disk
3. select packets with TCP.sport == 50000 (server → client)
4. sort by TCP.seq, concatenate TCP.payload        ← sequence-number reassembly
5. payload starts with PK\x03\x04                  ← it is the ZIP
6. zipfile.ZipFile(payload) → testzip() is None
7. archive.read("evidence/incident_summary.txt")
8. recovered token == injected flag                ← exact match
```

Observed during the run:

```text
data segments on port 50000: (36.05s, 1200) (36.06s, 1200) (36.06s, 576)
recovered payload          : 2976 bytes, PK\x03\x04
members                    : ['evidence/incident_summary.txt']
recovered token            : GZCTF{NET03_ACCEPTANCE_FLAG}
```

## 3. Participant workflow (executed)

```console
$ docker run -d --name n3 -e 'GZCTF_FLAG=GZCTF{NET03_E2E_TEST_FLAG}' \
    -p 127.0.0.1:3350:8080 net-03-the-last-transmission:dev
$ docker logs n3
[..] INFO net03.capture: wrote capture.pcap (17026 bytes, 130 packets, 38 DNS,
     1836 HTTP bytes, 370 FTP control bytes, 2976 FTP data bytes)
[..] INFO net03.app: listening on 0.0.0.0:8080

$ curl -s http://127.0.0.1:3350/health
{"status": "ok", "service": "the-last-transmission", "capture": "ready"}

$ curl -s -o n3.pcap -D - http://127.0.0.1:3350/download | grep -iE 'HTTP/|content-type|content-disposition'
HTTP/1.0 200 OK
Content-Type: application/vnd.tcpdump.pcap
Content-Disposition: attachment; filename="capture.pcap"
```

Reconstruction from the downloaded file:

```text
--- FTP control commands ---            --- FTP control replies ---
USER evidence                           220 Asterion Transfer Service ready
PASS archive-access                     331 Password required for evidence
TYPE I                                  230 Login successful.
PASV                                    200 Type set to I.
RETR confidential_bundle.zip            227 Entering Passive Mode (192,0,2,80,195,80)
QUIT                                    150 Opening BINARY mode data connection for
                                            confidential_bundle.zip (2972 bytes).
                                        226 Transfer complete.
                                        221 Goodbye.

--- HTTP requests ---
GET / HTTP/1.1
GET /api/status HTTP/1.1
GET /api/transfer/status HTTP/1.1
GET /favicon.ico HTTP/1.1
incident reference in response body: True

--- FTP data ---
bytes: 2976   magic: b'PK'
Verification token: GZCTF{NET03_E2E_TEST_FLAG}
```

## 4. Platform validation (GZ::CTF 1.9.1)

```bash
python3 tests/gzctf_e2e.py --base-url http://127.0.0.1:3000 \
  --admin-user Admin --admin-pass '<redacted>' \
  --image net-03-the-last-transmission:test
```

Result: **passed**.

```text
[gzctf-e2e] game 20 / challenge 19 configured as DynamicContainer
[gzctf-e2e] team-a: container running at 127.0.0.1:32798
[gzctf-e2e] team-a: recovered AXUM{last_transmission_c78242485532}
[gzctf-e2e] team-b: container running at 127.0.0.1:32799
[gzctf-e2e] team-b: recovered AXUM{last_transmission_86b613011ff9}
[gzctf-e2e] team-a: own flag accepted by GZ::CTF
[gzctf-e2e] team-b: own flag accepted by GZ::CTF
[gzctf-e2e] team-a: team B's flag rejected (status WrongAnswer)
[gzctf-e2e] team-b: team A's flag rejected (status WrongAnswer)
[gzctf-e2e] validation game deleted
```

The script performs the full participant path against the platform entry URL:
download → identify port 50000 → reassemble → open ZIP → read evidence → submit.

## 5. Browser verification

| Viewport | Result |
|---|---|
| 1440 × 1000 | Brand bar, hero, artifact/mission cards, tools block and footer render correctly; download targets `/download`; no horizontal overflow (1425 / 1440) |
| 390 × 844 | Single column, full-width download button, stacked definition list; no horizontal overflow (375 / 390) |

The page was checked to contain none of: the flag, `GZCTF{`, `AX-7842`, the
archive name, the evidence path, the FTP credentials or the data port.

## 6. Status summary

| Area | Status | Evidence |
|---|---|---|
| ZIP generation | PASS | 17 artifact tests; deterministic, valid, single member |
| DNS traffic | PASS | 12 tests; A+AAAA background, correct resolution, no flag |
| HTTP traffic | PASS | 12 tests; 4 requests, 4 responses, correct Content-Length, stream reassembly |
| FTP passive mode | PASS | 16 tests; full transcript, `195*256+80 = 50000`, separate data connection |
| TCP reconstruction | PASS | 11 tests; handshake, ISN tracking, MSS segmentation, no overlaps |
| PCAP generation | PASS | 17 tests; atomic publish, ordering, interleaving, layers |
| End-to-end recovery | PASS | archive recovered from the capture and flag matches exactly |
| Download service | PASS | `/`, `/download`, `/health`, static assets; 404 elsewhere |
| Path traversal | PASS | no request-controlled paths; probes return 404 |
| Flag confidentiality | PASS | no plaintext in DNS, HTTP, FTP control, logs, pages or image |
| Non-root container | PASS | UID 10001, no added capabilities |
| Docker build | PASS | pinned base, single stage, no flag baked in |
| GZ::CTF schema | PASS | `Forensics`, `DynamicContainer`, `Hints` inspected in 1.9.1 and accepted |
| GZ::CTF deployment | PASS | two-team end-to-end run |
| Documentation | PASS | README, `docs/challenge.md`, `docs/writeup.md`, `docs/deployment.md` |

Not executed:

* `tshark` / Wireshark dissection — **NOT TESTED**: neither `tshark` nor
  `wireshark` is installed on the verification host. The capture is a plain
  libpcap file with correct Ethernet/IPv4/TCP/UDP layers, valid sequence/ack
  numbers and no retransmissions (asserted), which is what those tools require,
  but this was not observed directly. Reconstruction was demonstrated with Scapy
  and `tcpdump`.
* Kubernetes provider deployment — **NOT TESTED**.
* Traffic capture (`enableTrafficCapture: true`) — **NOT TESTED**.
* `linux/arm64` build — **NOT TESTED**.
* `read_only` / `cap_drop: ALL` compose profile under GZ::CTF — the profile was
  written and validated with `docker compose config`; the platform does not
  apply those options.

## 7. Defects found and fixed during verification

| Defect | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'config'` | `generate_capture.py` imported `config` before it existed | Created `src/config.py` |
| `TypeError: unsupported operand type(s) for +: 'Ether' and 'bytes'` | Scapy `/` binds tighter than `+`, so the NTP payload was concatenated onto a packet | Wrapped the payload in `Raw(load=...)` |
| `capture validation failed: packet without an IPv4 layer` | ARP background frames legitimately have no IPv4 layer | Validation now skips ARP frames |
| `FTP data connection does not follow the control negotiation` | Compared the data start against the *last* control packet (the QUIT at 42 s) | Compare against the `150` reply, and require the data connection to end before `226` |
| `Flag` enum comparison failure in the handshake test | `set` of `Flag` objects does not match the string `"S"` | Store `str(packet[TCP].flags)` |
| Landing page exposed `AX-7842` | The case id was in the top navigation bar | Replaced with a neutral label; the reference must be discovered via HTTP |
| Off-by-one in two TCP tests | The FIN consumes one sequence number | Asserted sequence state before `close()` and used `len(payload)` instead of a hardcoded count |
