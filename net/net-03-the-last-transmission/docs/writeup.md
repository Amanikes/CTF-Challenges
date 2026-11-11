# NET-03 — The Last Transmission: writeup

Works for any runtime flag. Examples use `AXUM{last_transmission_<12 hex>}`.

## 1. Challenge overview

`capture.pcap` holds 130 packets on one segment:

| Stage | Time | Content |
|---|---|---|
| DNS | 00:00–00:07 | 18 ordinary A/AAAA lookups |
| DNS | 00:08 | `files-update.example.test` → `192.0.2.80` |
| HTTP | 00:15–00:18 | `GET /`, `/api/status`, `/api/transfer/status`, `/favicon.ico` |
| FTP control | 00:25–00:42 | login, `PASV`, `RETR`, completion |
| FTP data | 00:36 | 2976-byte ZIP in three segments |

Background noise — a reset HTTPS attempt, ARP, NTP and an intranet HTTP session
— is interleaved throughout so no single filter reveals the whole story.

## 2. Intended learning outcomes

* Correlating DNS answers with later TCP destinations.
* Reading HTTP **response bodies**, not just request lines.
* Understanding FTP's two-connection model and passive-mode port arithmetic.
* Reconstructing and extracting a binary TCP stream.

## 3. DNS filtering

```text
dns
```

Sort by name and look for a host that appears once, right before the interesting
activity. The suspicious lookup:

```text
dns.qry.name == "files-update.example.test"
```

Expected answer:

```text
files-update.example.test: type A, class IN, addr 192.0.2.80
```

`files-update.example.test` is the only documentation-range external host that
resolves immediately before the HTTP phase; everything else is internal
`*.asterion.internal`, Microsoft telemetry, or public CDNs.

## 4. HTTP stream analysis

```text
http && ip.addr == 192.0.2.80
```

Four requests on one keep-alive connection. The first two are unremarkable:

```text
GET /               → 200 text/html
GET /api/status     → 200 application/json  {"service":"transfer-service","version":"2.3",...}
```

The third carries the correlation evidence:

```text
GET /api/transfer/status → 200 application/json
{
  "status": "completed",
  "session": "AX-7842",
  "archive": "confidential_bundle.zip",
  "destination": "transfer-service",
  "size_bytes": 2976,
  "completed_at": "2026-07-02T09:20:18Z"
}
```

`GET /favicon.ico` returns 404 and is noise.

Record two values from this response: the session `AX-7842` and the archive name
`confidential_bundle.zip`.

## 5. FTP control stream

```text
ftp && ip.addr == 192.0.2.80
```

Right-click any control packet → **Follow → TCP Stream**:

```text
220 Asterion Transfer Service ready
USER evidence
331 Password required for evidence
PASS archive-access
230 Login successful.
TYPE I
200 Type set to I.
PASV
227 Entering Passive Mode (192,0,2,80,195,80)
RETR confidential_bundle.zip
150 Opening BINARY mode data connection for confidential_bundle.zip (2976 bytes).
226 Transfer complete.
QUIT
221 Goodbye.
```

## 6. Passive-mode negotiation

`227 Entering Passive Mode` carries the data endpoint as six comma-separated
numbers: four address octets, then two port octets.

```text
(192,0,2,80,195,80)
 └──────┬──────┘└──┬──┘
   192.0.2.80    195, 80  →  195 * 256 + 80 = 50000
```

The client then opens a **new** connection from an ephemeral port to
`192.0.2.80:50000`. Filter it with:

```text
tcp.port == 50000
```

## 7. Control connection versus data connection

| | Control | Data |
|---|---|---|
| Server port | 21 | 50000 |
| Direction of commands | client → server | none |
| Direction of payload | replies only | server → client (the archive) |
| Lifetime | whole session (25 s → 42 s) | only during the transfer (36 s) |

The data connection contains **no FTP syntax at all** — it is raw binary. That
is why searching for FTP keywords never finds the archive.

## 8. ZIP extraction

Easiest path — Wireshark:

1. Click a packet on port 50000.
2. **Follow → TCP Stream**.
3. Set **Show data as: Raw**, then **Save as…** → `confidential_bundle.zip`
   (choose "All bytes" / the server→client direction only).

Command line with tshark:

```console
$ tshark -r capture.pcap -q -z follow,tcp,raw,1
```

Pick the stream number whose endpoints include `:50000`, then decode the hex
half of the output:

```console
$ tshark -r capture.pcap -q -z follow,tcp,raw,1 \
  | sed -n '/^=/,$p' | tail -n +2 | tr -d '\n\t ' | xxd -r -p > confidential_bundle.zip
$ unzip -l confidential_bundle.zip
Archive:  confidential_bundle.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     2816  2026-07-02 09:20   evidence/incident_summary.txt
```

Or with tcpdump, if you prefer to keep it simple:

```console
$ tcpdump -r capture.pcap -w ftpdata.pcap 'tcp port 50000 and src host 192.0.2.80'
```

then open `ftpdata.pcap` in Wireshark and Follow TCP Stream as above.

## 9. Evidence file inspection

```console
$ unzip -o confidential_bundle.zip
$ sed -n '1,14p' evidence/incident_summary.txt
ASTERION TECHNOLOGIES
CONFIDENTIAL INCIDENT REPORT

Incident Reference: AX-7842
Classification: INTERNAL

The following transmission was recovered from the affected workstation.

Recovered evidence identifier:
AXUM-INCIDENT-03

Verification token:
AXUM{last_transmission_<12 hex>}
```

## 10. Runtime flag recovery

The token is the team's dynamic flag. Submit it to GZ::CTF. Verification that
you recovered the right value:

```console
$ grep -o 'AXUM{[^}]*}' evidence/incident_summary.txt
AXUM{last_transmission_<12 hex>}
```

The value matches `GZCTF_FLAG` for that container, which is exactly what the
platform validates.

## 11. Alternative tshark workflow

```console
# 1. suspicious resolution
$ tshark -r capture.pcap -Y 'dns.qry.name contains "files-update"' \
    -T fields -e dns.qry.name -e dns.a
files-update.example.test	192.0.2.80

# 2. HTTP evidence
$ tshark -r capture.pcap -Y 'http.response && ip.addr == 192.0.2.80' \
    -T fields -e http.request.uri -e http.response.code
/api/transfer/status	200

$ tshark -r capture.pcap -Y 'http.response && ip.addr == 192.0.2.80' -T fields -e text \
  | grep -E 'session|archive'

# 3. FTP negotiation
$ tshark -r capture.pcap -Y 'ftp.response.code == 227' -T fields -e ftp.response.arg
Entering Passive Mode (192,0,2,80,195,80)

# 4. data stream
$ tshark -r capture.pcap -Y 'tcp.port == 50000' -T fields -e tcp.len | paste -sd+ | bc
2976
```

## 12. Common participant mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Searching only for FTP keywords | No archive found | The archive is raw binary on port 50000 |
| Following the control stream and expecting the file | 370 bytes of text | Control carries commands; data carries the file |
| Ignoring the `227` reply | Cannot explain port 50000 | Decode `195,80` as `195 * 256 + 80` |
| Reading only request URLs | Misses `AX-7842` and the archive name | Read response bodies |
| Filtering `http` only | Never sees the transfer | Check FTP too |
| Saving the whole stream in ASCII mode | Corrupt ZIP | Save **Raw**, and only the server→client direction |
| Assuming three segments mean three files | Misreads Follow TCP Stream | One file, segmented at 1200 bytes |
| Using the incident reference as the flag | Wrong answer | `AX-7842` is a session id, not the token |

## 13. Notes for staff

* The archive is transmitted **uncompressed** inside the ZIP, so the flag is
  visible once extracted — this is the intended artifact, not a leak.
* The flag never appears in DNS, HTTP or FTP control messages; the automated
  suite asserts this.
* Each team's capture differs because the archive differs.
* Reset an instance by destroying and relaunching the container; the capture is
  regenerated from the newly injected flag.
