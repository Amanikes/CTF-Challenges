# NET-01 — Testing Report

Every result below was produced by executing the commands shown. Commands are
quoted as run; results are the observed output.

## Environment

| Item | Value |
|---|---|
| Image | `net-01-unencrypted-secrets:test` (`node:22-alpine` + `python3` + `scapy==2.8.0`) |
| GZ::CTF | 1.9.1 (`23ccbbaa`), Docker provider, `PortMappingType: Default`, `PublicEntry: 127.0.0.1` |
| Analysis tools | Scapy 2.8.0 (host + container), `tcpdump` as an independent parser |
| Host OS | Fedora, SELinux enforcing |

## 1. Full suite

```console
$ ./tests/run-tests.sh net-01-unencrypted-secrets:test
== building net-01-unencrypted-secrets:test ==
image built

== test_generation ==     Ran 10 tests in 7.940s   OK
== test_pcap_validity ==  Ran 11 tests in 1.076s   OK
== test_flag_exposure ==  Ran  9 tests in 1.066s   OK
== test_isolation ==      Ran 17 tests in 19.594s  OK

ALL SUITES PASSED
```

**47 tests, 0 failures.**

### test_generation (10)

```text
ok  test_missing_flag_is_rejected
ok  test_empty_flag_is_rejected
ok  test_over_long_flag_is_rejected
ok  test_non_ascii_flag_is_rejected
ok  test_valid_flag_produces_a_capture
ok  test_capture_size_is_reasonable
ok  test_permissions_allow_the_service_to_read_it
ok  test_generator_output_does_not_leak_the_flag
ok  test_different_flags_produce_different_captures
ok  test_capture_is_readable_by_tcpdump
```

### test_pcap_validity (11)

```text
ok  test_dns_query_and_response_exist
ok  test_dns_traffic_uses_the_internal_resolver
ok  test_tcp_three_way_handshake_exists
ok  test_addresses_match_the_documented_topology
ok  test_http_request_and_response_are_reconstructed
ok  test_segmented_response_is_captured_as_multiple_segments
ok  test_target_request_is_reconstructable
ok  test_target_header_is_present_and_carries_the_flag
ok  test_follow_tcp_stream_reassembles_the_full_request
ok  test_tcpdump_can_extract_the_header
ok  test_no_retransmissions_or_out_of_order_segments
```

### test_flag_exposure (9)

```text
ok  test_flag_appears_in_exactly_one_packet
ok  test_flag_only_in_the_target_request_packet
ok  test_flag_is_only_in_the_session_header_line
ok  test_flag_absent_from_dns
ok  test_flag_absent_from_urls
ok  test_flag_absent_from_http_responses
ok  test_flag_absent_from_other_request_headers
ok  test_raw_file_contains_the_flag_once
ok  test_capture_header_is_not_used_to_store_the_flag
```

### test_isolation (17)

```text
IsolationTests
ok  test_each_capture_carries_its_own_flag
ok  test_captures_never_cross_contaminate
ok  test_captures_differ
ok  test_downloaded_captures_are_valid_pcaps
ok  test_each_download_serves_only_its_own_artifact
ok  test_logs_do_not_contain_the_flag
ok  test_landing_page_does_not_contain_the_flag_or_header
ok  test_health_endpoint_reports_ready
ok  test_download_headers
ok  test_unknown_paths_are_404

ContainerSecurityTests
ok  test_runs_as_non_root
ok  test_container_is_isolated
ok  test_only_the_http_port_is_published
ok  test_no_docker_socket
ok  test_service_process_has_no_flag
ok  test_image_contains_no_flag
ok  test_image_config_declares_no_flag
```

## 2. Participant workflow (executed)

```console
$ docker run -d --name net-test -e 'GZCTF_FLAG=GZCTF{NET01_TEST_FLAG}' \
    -p 127.0.0.1:3330:3000 net-01-unencrypted-secrets:dev
$ curl -s http://127.0.0.1:3330/health
{"status":"ok","service":"meridian-capture-download","capture":"ready"}

$ docker logs net-test
[meridian-capture] wrote meridian-traffic.pcap (10475 bytes, 74 packets, 8 DNS, 64 TCP, 15 HTTP payloads)
[meridian-download] listening on http://0.0.0.0:3000

$ curl -s -o net.pcap -D - http://127.0.0.1:3330/download | head -1
HTTP/1.1 200 OK
# Content-Disposition: attachment; filename=meridian-traffic.pcap
# Content-Type: application/vnd.tcpdump.pcap

$ tcpdump -nn -A -r net.pcap | grep X-Meridian-Session
X-Meridian-Session: GZCTF{NET01_TEST_FLAG}
```

The recovered value equals the injected flag.

HTTP requests present in the capture (Scapy extraction):

```text
 192.168.10.25 -> 192.168.10.10  GET / HTTP/1.1
 192.168.10.25 -> 192.168.10.10  GET /api/shipments?window=7d HTTP/1.1
 192.168.10.25 -> 192.168.10.10  GET /internal/api/session HTTP/1.1
 192.168.10.30 -> 192.168.10.10  GET /api/shipments?status=delivered HTTP/1.1
 192.168.10.30 -> 192.168.10.10  GET /api/status HTTP/1.1
 192.168.10.25 -> 192.168.10.20  GET /report/daily HTTP/1.1
 192.168.10.30 -> 192.168.10.20  POST /telemetry HTTP/1.1
```

Target stream (`Follow TCP Stream` equivalent):

```http
GET /internal/api/session HTTP/1.1
Host: portal.meridian.internal
User-Agent: MeridianDesktop/2.4 (Windows 11; x64)
Accept: application/json
X-Meridian-Session: GZCTF{NET01_TEST_FLAG}
Connection: keep-alive
```

## 3. Platform validation (GZ::CTF 1.9.1)

```bash
python3 tests/gzctf_e2e.py --base-url http://127.0.0.1:3000 \
  --admin-user Admin --admin-pass '<redacted>' \
  --image net-01-unencrypted-secrets:test
```

Result: **passed**.

```text
[gzctf-e2e] game 18 / challenge 17 configured as DynamicContainer
[gzctf-e2e] team-a: container running at 127.0.0.1:32794
[gzctf-e2e] team-a: recovered AXUM{unencrypted_secrets_2d2cb9301d07}
[gzctf-e2e] team-b: container running at 127.0.0.1:32795
[gzctf-e2e] team-b: recovered AXUM{unencrypted_secrets_3d49ba3310ca}
[gzctf-e2e] team-a: own flag accepted by GZ::CTF
[gzctf-e2e] team-b: own flag accepted by GZ::CTF
[gzctf-e2e] team-a: team B's flag rejected (status WrongAnswer)
[gzctf-e2e] team-b: team A's flag rejected (status WrongAnswer)
[gzctf-e2e] validation game deleted
```

Confirms on the real platform: `DynamicContainer` with `category: Forensics` and
`exposePort: 3000` is accepted; `GZCTF_FLAG` reaches only the generator;
`[TEAM_HASH]` expands to 12 hex characters; the PCAP downloads through the
platform entry URL; stream reassembly yields each team's own token; cross-team
submissions are rejected.

Artefacts (game, containers, players, teams) were removed afterwards.

## 4. Browser verification

| Viewport | Result |
|---|---|
| 1440 × 1000 | Brand bar, hero, capture/instructions cards, review scope and footer render correctly; download targets `/download`; no horizontal overflow (1425 / 1440) |
| 390 × 844 | Single column, full-width download button, stacked definition list; no horizontal overflow (375 / 390) |

The page never contains the flag or the header name (asserted in
`test_landing_page_does_not_contain_the_flag_or_header`).

## 5. Status summary

| Area | Status | Evidence |
|---|---|---|
| PCAP generator | PASS | produces a valid capture; rejects bad flags |
| PCAP validity | PASS | 74 packets, libpcap magic, 8 KiB–4 MiB, readable by Scapy and tcpdump |
| DNS traffic | PASS | ≥2 queries and ≥2 responses, resolver `192.168.10.53`, correct answer for the portal |
| TCP reconstruction | PASS | SYN/SYN-ACK/ACK verified, ACK = SYN+1, no retransmissions or out-of-order segments |
| HTTP reconstruction | PASS | 7 requests and 7 responses, segmented 1.7 KB response |
| Target header | PASS | `X-Meridian-Session` present in `/internal/api/session` only |
| Dynamic flag insertion | PASS | flag equals the injected value and appears in exactly one packet |
| Download service | PASS | `/`, `/download` (correct type + filename), `/health`, 404 elsewhere |
| Participant workflow | PASS | download → tcpdump/Scapy → extract header → equals test flag |
| Two-team isolation | PASS | own flags only, captures differ, no cross-contamination, no flag in logs |
| Non-root container | PASS | `Config.User=node`, `id -u` = 1000 |
| Docker build | PASS | multi-stage; runtime has only Node, Python and Scapy |
| GZ::CTF schema | PASS | `Forensics`, `DynamicContainer`, `ContainerConfig`, `Hints` inspected in 1.9.1 and accepted |
| GZ::CTF deployment | PASS | two-team end-to-end run |
| Organizer documentation | PASS | `WRITEUP.md`, `DEPLOYMENT.md`, `TESTING.md` |

Not executed:

* Kubernetes provider deployment — **NOT TESTED**.
* Traffic capture (`enableTrafficCapture: true`) — **NOT TESTED** (disabled by design).
* `linux/arm64` build — **NOT TESTED**.

## 6. Defects found and fixed during verification

| Defect | Cause | Fix |
|---|---|---|
| Generator raised `KeyError: '192.168.10.10'` | The RST frame passed an IP string into the TCP `sport` argument | Pass the numeric port `3389` |
| Capture written with mode 0600 | `mkstemp` creates private files | `chmod 0644` after write so the service user can read it |
| `test_each_download_serves_only_its_own_artifact` failed | Compared `bytes(first[0])` (first packet only) instead of scanning the capture | Reassemble the target request and count flag occurrences in the whole file |
| 404 test emitted a `ResourceWarning` | The `HTTPError` object was never closed | Close it in the assertion |

## 7. Notes and limitations

* The capture uses private, synthetic addresses only; no packet is ever sent on
  an interface, and the container needs no `NET_RAW`/`NET_ADMIN`.
* Scapy emits `DeprecationWarning` for `DNS.qd`/`DNS.an` access on 2.8.0. The
  warnings are cosmetic and the assertions are valid for this version.
* `tshark` is not installed on the verification host, so header extraction was
  demonstrated with Scapy and tcpdump. `tshark` field names are documented in
  the writeup with a `tcpdump`/`-V` fallback that needs no HTTP dissector.
