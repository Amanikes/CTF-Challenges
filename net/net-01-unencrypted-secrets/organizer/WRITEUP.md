# NET-01 — Organizer Writeup: Unencrypted Secrets

> Organizer-only. This directory is excluded from the Docker build context and
> never served at runtime.

## 1. Challenge overview

| | |
|---|---|
| Name | Unencrypted Secrets |
| Category | Network traffic analysis (configured as `Forensics` — GZ::CTF 1.9.1 has no Network category) |
| Difficulty / points | Easy / 100 |
| Artifact | `meridian-traffic.pcap`, generated per team |
| Sensitivity | Session token in a plaintext HTTP request header |
| Flag source | GZ::CTF dynamic flag (`GZCTF_FLAG`) |
| Guidance | Guided — three staged hints |

The team's flag is written into exactly one place: the value of the
`X-Meridian-Session` header on the authenticated session request. Everything
else in the capture is ordinary business traffic.

## 2. Network topology

| Device | Address | MAC (synthetic) |
|---|---|---|
| Meridian portal | `192.168.10.10` | `02:00:5e:10:0a:0a` |
| Reporting service | `192.168.10.20` | `02:00:5e:10:0a:14` |
| Workstation A | `192.168.10.25` | `02:00:5e:10:0a:19` |
| Workstation B | `192.168.10.30` | `02:00:5e:10:0a:1e` |
| Internal DNS | `192.168.10.53` | `02:00:5e:10:0a:35` |

Hostnames in the capture: `portal.meridian.internal`,
`updates.meridian.internal`, `reporting.meridian.internal`,
`cdn.meridian.internal`. All addresses are private and synthetic; no packet is
ever transmitted.

## 3. PCAP generation architecture

`scripts/generate_capture.py` imports Scapy and builds layers in memory:

```text
Ether / IP / TCP / Raw        ← HTTP conversations
Ether / IP / UDP / DNS        ← name resolution
Ether / ARP                   ← local resolution noise
```

A small `Capture` accumulator assigns every frame a controlled timestamp
(`BASE_TIME + offset`), and `Conversation` tracks both sequence numbers so each
segment's `seq`/`ack` matches the peer's expectation:

| Step | Sent by | Flags | seq | ack |
|---|---|---|---|---|
| SYN | client | `S` | ISN_c | 0 |
| SYN/ACK | server | `SA` | ISN_s | ISN_c + 1 |
| ACK | client | `A` | ISN_c + 1 | ISN_s + 1 |
| data | client | `PA` | c_next | s_next |
| ACK | server | `A` | s_next | c_next + len |
| data | server | `PA` | s_next | c_next |
| ACK | client | `A` | c_next | s_next + len |
| FIN/ACK, FIN/ACK, ACK | both | `FA`,`FA`,`A` | … | … |

Because sequence numbers are tracked exactly, Wireshark shows no retransmissions,
no "previous segment not captured" and no out-of-order warnings — verified by
parsing tcpdump output for those markers (`test_pcap_validity.py`).

Segmentation: every payload larger than 1460 bytes is emitted as multiple
full-MSS segments with an ACK between them. The shipment-list response
(~1.7 KB) is the deliberate example, so Follow TCP Stream exercises reassembly.

### Validation gate

`validate_capture()` re-reads the written file with `rdpcap` and asserts:

1. the file exists and its size is within 8 KiB–4 MiB;
2. at least 40 packets are present;
3. at least one DNS query and one DNS response exist;
4. a TCP SYN and SYN/ACK exist;
5. an HTTP request and an HTTP response exist;
6. the target request `/internal/api/session` is reconstructable;
7. `X-Meridian-Session` is present in that request;
8. the header value equals the injected flag;
9. the flag occurs in exactly **one** packet, sent by a workstation;
10. the flag appears in no DNS name and no HTTP response;
11. nothing else in the capture carries the flag.

If any check fails the generator exits non-zero and the download service is
never started, so a partial capture is never served.

## 4. Packet flow

Timestamps are offsets from `2026-10-28 09:14:02 UTC`.

| Time | Conversation | Content |
|---|---|---|
| 0.000 | A → DNS | `A? portal.meridian.internal` |
| 0.008 | DNS → A | `A 192.168.10.10` |
| 0.012 | A:51513 → portal:80 | TCP handshake, `GET /`, `200 OK` (HTML) |
| 0.175 | same | `GET /api/shipments?window=7d`, `200 OK` (1.7 KB, 2 segments) |
| 0.274 | same | FIN/ACK teardown |
| 0.517 | A:51514 → portal:80 | handshake, **`GET /internal/api/session`** with the session header, `200 OK` |
| 1.18 | B → DNS | `A? updates.meridian.internal` |
| 1.20 | B:53989 → portal:80 | `GET /api/shipments?status=delivered`, `GET /api/status` |
| 2.30 | A → DNS, A:51516 → reporting:8080 | `GET /report/daily` |
| 3.20 | B:53990 → reporting:8080 | `POST /telemetry`, `204 No Content` |
| 4.15 | B → DNS | `A? cdn.meridian.internal` |
| 4.20 | broadcast | ARP request/reply |
| 4.35 | A:51517 → portal:3389 | SYN/SYN-ACK then RST (closed port) |

Total: 74 packets, 15 HTTP payloads, 8 DNS packets.

## 5. Relevant HTTP request

```http
GET /internal/api/session HTTP/1.1
Host: portal.meridian.internal
User-Agent: MeridianDesktop/2.4 (Windows 11; x64)
Accept: application/json
X-Meridian-Session: AXUM{unencrypted_secrets_<12 hex>}
Connection: keep-alive
```

The response is body-only JSON and carries no secret:

```json
{"session":"valid","employee":"j.reinhardt","role":"dispatcher",
 "expires_in":3600,"permissions":["shipments:read","shipments:update"]}
```

## 6. Target header

`X-Meridian-Session` — a custom header the desktop client uses to prove an
already-authenticated session. Because the request is plain HTTP on port 80,
the value is readable by anyone with capture access.

## 7. Wireshark solve steps

1. Open `meridian-traffic.pcap`.
2. **Statistics → Protocol Hierarchy**: Ethernet, IPv4, TCP, HTTP, DNS, ARP.
3. Filter `http.request` — seven requests across four conversations.
4. Open `GET /internal/api/session` → *Packet details* → **Hypertext Transfer
   Protocol** → the `X-Meridian-Session` header.
5. **Right-click → Follow → TCP Stream** to read the request in one block.

## 8. Display filters

```text
http                                  # all HTTP traffic
http.request                          # requests only
http.request.method == "GET"           # GET requests
http.host == "portal.meridian.internal"
tcp.port == 80 && http
http contains "internal/api/session"
dns                                   # name resolution
arp                                   # local resolution noise
tcp.flags.reset == 1                  # the refused connection
```

Header-level filters (two equivalent forms, depending on build):

```text
http.x_meridian_session
http contains "X-Meridian-Session"
```

## 9. Follow TCP Stream

Select any packet of the conversation `192.168.10.25:51514 ↔
192.168.10.10:80`, then **Follow → TCP Stream**. The dialog shows the full
request terminated by a blank line, followed by the JSON response. The header
is on a single line, which is why hint 3 points at the stream rather than at
individual packets.

## 10. tshark extraction procedure

```console
$ tshark -r meridian-traffic.pcap -Y 'http.request' \
    -T fields -e http.host -e http.request.uri
portal.meridian.internal	/
portal.meridian.internal	/api/shipments?window=7d
portal.meridian.internal	/internal/api/session
portal.meridian.internal	/api/shipments?status=delivered
portal.meridian.internal	/api/status
reporting.meridian.internal:8080	/report/daily
reporting.meridian.internal:8080	/telemetry
```

```console
$ tshark -r meridian-traffic.pcap -Y 'http.request.uri contains "session"' \
    -T fields -e http.x_meridian_session
AXUM{unencrypted_secrets_<12 hex>}
```

Field name not resolved by the local Wireshark build? Fall back to the generic
text filter, which always works:

```console
$ tshark -r meridian-traffic.pcap -Y 'http.request' -V | grep -i 'x-meridian-session'
    X-Meridian-Session: AXUM{unencrypted_secrets_<12 hex>}
```

Or with tcpdump, no HTTP dissector required:

```console
$ tcpdump -nn -A -r meridian-traffic.pcap | grep X-Meridian-Session
X-Meridian-Session: AXUM{unencrypted_secrets_<12 hex>}
```

## 11. Dynamic flag integration

* `entrypoint.sh` rejects a missing/empty/blank `GZCTF_FLAG`.
* `generate_capture.py` reads it, pops it from `os.environ`, validates the byte
  range `0x20..0x7E` and the 200-byte maximum, and injects it into the target
  request header only.
* The generator prints one line containing the packet/size summary — never the
  flag.
* The shell then `unset`s the variable and `exec`s the download service, so the
  long-running process never inherits it.
* **Memory-cleanup limit:** popping an environment variable and dropping a
  Python string reference does not scrub copies made by the allocator, the
  kernel, swap or a core dump. The objective is to keep the secret out of the
  long-running service and out of any file other than the intended PCAP.

## 12. Per-team isolation

Each container generates its own capture, so `protocol`-level artefacts differ
per team. Verified locally and on GZ::CTF:

* instance A's PCAP contains A's flag exactly once, and never B's;
* instance B's PCAP contains B's flag exactly once, and never A's;
* the two files differ byte-for-byte;
* the download service holds no flag and serves one fixed path;
* `GZCTF_FLAG` is absent from the service process environment, the image
  configuration, the image filesystem and the container logs.

## 13. Lessons about plaintext HTTP

* **Anything readable by the client is readable by the network.** A token sent
  in a header over port 80 is visible to any device on the path with capture
  access — including other tenants of a shared switch segment.
* **Custom headers are not protection.** Moving a credential out of a cookie or
  query string changes nothing if the transport is plaintext.
* **TLS would have prevented this entire class of disclosure**, and would have
  reduced the challenge to endpoint compromise rather than traffic analysis.
* **What is captured is retained.** A capture file turns a transient request
  into a permanent, shareable credential leak, which is why capture files must
  be treated as sensitive material and why secrets should be short-lived.
* **Defence in depth:** short token lifetimes, binding tokens to client
  certificates, and avoiding long-lived bearer values all reduce the impact.
