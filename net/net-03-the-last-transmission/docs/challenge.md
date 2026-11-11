# NET-03 — The Last Transmission: challenge sheet (organizer)

| | |
|---|---|
| ID | NET-03 |
| Name | The Last Transmission |
| Category | Network traffic analysis — configured as `Forensics` (GZ::CTF 1.9.1 has no Network category) |
| Difficulty | Medium |
| Points | 150 |
| Protocols | DNS (UDP/53), HTTP (TCP/80), FTP passive (TCP/21 control, TCP/50000 data) |
| Artifact | `capture.pcap` — 130 packets, ~16.6 KB |
| Transferred object | `confidential_bundle.zip` (2976 bytes, 3 TCP segments) |
| Flag placement | `evidence/incident_summary.txt` inside the archive |
| Guidance | Guided (4 hints) |
| Deployment | GZ::CTF `DynamicContainer`, one isolated instance per team |
| Flag template | `AXUM{last_transmission_[TEAM_HASH]}` |
| Expected solve time | 25–45 minutes |

## Scenario

> Asterion Technologies has reported a suspected data breach. One of its internal
> workstations communicated with an unfamiliar external server shortly before
> confidential information disappeared from the organisation's systems.
>
> The security team recovered a packet capture from the affected network
> segment. It contains DNS lookups, HTTP requests and an unusual file transfer.
> Individually these events appear relatively ordinary — together they may
> reveal what happened.
>
> Your mission is to reconstruct the communication, identify the suspicious
> transfer, recover the transmitted archive, and investigate its contents to
> uncover the hidden flag.

## Participant mission

1. Investigate DNS.
2. Identify suspicious destinations.
3. Correlate HTTP communication.
4. Identify the FTP session.
5. Reconstruct TCP streams.
6. Extract the ZIP archive.
7. Recover the flag.

## Guided hints

1. **DNS** — Begin by identifying unusual DNS queries. Determine which domain
   resolves shortly before the suspicious communications begin.
2. **HTTP** — Look at HTTP requests and responses involving the IP address
   discovered through DNS. Inspect the response bodies, not just the request
   URLs.
3. **FTP control** — FTP uses a control connection and a separate data
   connection. Follow the control stream and inspect passive-mode negotiation.
4. **FTP data** — Look for the RETR command and reconstruct the corresponding
   TCP data stream. The transferred file is a ZIP archive containing the final
   evidence.

## Hints deliberately withheld

* The suspicious domain `files-update.example.test` and the address `192.0.2.80`.
* The incident reference `AX-7842`.
* The passive data port and how `227` encodes it.
* The FTP credentials.
* The archive's internal path.

## Learning objectives

* Correlate name resolution with subsequent connections.
* Read HTTP response bodies rather than only request lines.
* Understand FTP's split control/data architecture and passive-mode negotiation
  (`227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)` → `p1 * 256 + p2`).
* Reconstruct a binary TCP stream and extract a transferred file.
* Recognise that a single evidence source is rarely sufficient.

## Configuration

| Setting | Value |
|---|---|
| Type | `DynamicContainer` |
| Category | `Forensics` |
| Container image | `registry.axumsec.example/ctf/net-03-the-last-transmission:1.0.0` |
| Service port | `8080` |
| Score / minimum ratio / difficulty | `150` / `1.0` / `1.0` |
| Memory / CPU / storage | 192 MB / 1 (× 0.1 cores) / 64 MB |
| Network mode | `Open` |
| Traffic capture | off |

## Operational notes

* The archive and capture are generated per team; nothing is shared or static.
* All addresses are documentation-only (RFC 5737 / RFC 1918); no packet is
  transmitted.
* The download service holds no flag and serves one fixed path.
* GZ::CTF performs all flag validation; the container exposes no validation API.
