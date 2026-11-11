# NET-02 — Lost in DNS: challenge sheet (organizer)

| | |
|---|---|
| ID | NET-02 |
| Name | Lost in DNS |
| Category | Network traffic analysis — configured as `Forensics` (GZ::CTF 1.9.1 has no Network category) |
| Difficulty | Easy |
| Points | 50 |
| Protocol | DNS over UDP/53 |
| Encoding | Hexadecimal, 24 characters per fragment |
| Payload placement | Second label of `NNN.<hex>.telemetry.example.test` queries |
| Artifact | `capture.pcap` (~7.5 KB, ~67 packets) |
| Guidance | Guided |
| Deployment | GZ::CTF `DynamicContainer`, one isolated instance per team |
| Flag template | `AXUM{lost_in_dns_[TEAM_HASH]}` |
| Expected solve time | 5–15 minutes |

## Participant description

> A network monitoring system has detected unusual DNS activity originating
> from an internal workstation.
>
> An investigation team captured the network traffic, but the DNS queries
> appear mostly ordinary at first glance. Something unusual is hidden within
> the DNS records.
>
> Investigate the provided packet capture, identify the suspicious DNS queries,
> reconstruct the hidden message, and recover the flag.

## Guided hints

Give these out in order — each one keeps the investigation moving without giving
the answer away.

1. **DNS traffic can reveal more than just the domains a machine visits.**
   Inspect the query names carefully.
2. **Wireshark provides a display filter that isolates DNS packets.**
3. **Look for repeated destination domains and subdomains containing sequential
   numeric identifiers.**
4. **The data fragments are hexadecimal.** Concatenate them in the correct order
   before decoding.

## Hints deliberately withheld

* The suspicious domain `telemetry.example.test`.
* The number of fragments.
* The fragment size (24 hex characters = 12 bytes).
* The fact that the flag is UTF-8 encoded before hex encoding.

## Configuration

| Setting | Value |
|---|---|
| Type | `DynamicContainer` |
| Category | `Forensics` |
| Container image | `registry.axumsec.example/ctf/net-02-lost-in-dns:1.0.0` |
| Service port | `8080` |
| Score / minimum ratio / difficulty | `50` / `1.0` / `1.0` |
| Memory / CPU / storage | 128 MB / 1 (× 0.1 cores) / 64 MB |
| Network mode | `Open` |
| Traffic capture | off |

## Operational notes

* The artifact is generated per team; there is no shared static PCAP.
* No packet is transmitted; the capture is assembled in memory by Scapy.
* The download service holds no flag and serves one fixed path.
* GZ::CTF performs all flag validation — there is no validation endpoint in the
  container.
