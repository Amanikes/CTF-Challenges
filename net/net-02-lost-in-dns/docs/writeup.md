# NET-02 — Lost in DNS: writeup

The solution below works for any runtime flag. Example values use the
placeholder `AXUM{lost_in_dns_<12 hex>}`.

## 1. Overview

The capture holds about 70 DNS packets. Most are ordinary A/AAAA lookups for
internal hosts and public services. A small number are TXT queries whose
subdomains carry hex-encoded chunks of a message in sequence order.

## 2. Intended discovery

1. Open the capture and look at **Statistics → Protocol Hierarchy**: Ethernet,
   IPv4, UDP, DNS only.
2. Filter to DNS and sort by query name. The query names form two groups:
   familiar hostnames and a repeating suffix with numeric subdomains.
3. The numeric subdomains are `001`, `002`, `003`… under the same parent, which
   is the classic signature of data being carried in DNS labels.
4. Each query type is `TXT` (not `A`), and the resolver answers `SERVFAIL` —
   the names are not real services.
5. Concatenate the hex fragments in sequence order and decode.

## 3. Wireshark investigation steps

```
1. File → Open → capture.pcap
2. Apply filter:            dns.qry.name contains "telemetry.example.test"
3. Note the fragments:
      001.475a4354467b4c4f53545f49.telemetry.example.test
      002.4e5f444e535f4558414d504c.telemetry.example.test
      003.455f464c41477d.telemetry.example.test
4. Copy each second label, concatenate in order:
      475a4354467b4c4f53545f49 4e5f444e535f4558414d504c 455f464c41477d
5. Decode as hex → the flag
```

Useful display filters:

```text
dns                                   # all DNS traffic
dns.qry.name                          # just the query names
dns.qry.name contains "telemetry"     # the suspicious family
dns.qry.type == 16                    # TXT queries only
dns.flags.rcode == 2                  # SERVFAIL answers
dns.qry.name contains "001."          # the first fragment
```

If you prefer not to type the parent domain, this works just as well and shows
the pattern immediately:

```text
dns.qry.type == 16
```

Every TXT query in the capture belongs to the suspicious family.

## 4. Suspicious domain identification

* Parent domain: `telemetry.example.test`
* Label layout: `<NNN>.<hex fragment>.<parent>`
* Sequence label: three digits, `001` upward
* Fragment length: 24 hex characters (12 bytes), except possibly the last

Distinguishing features: unusual `TXT` type, sequential numeric labels, uniform
label length, and no useful answers (`SERVFAIL`).

## 5. Payload extraction and ordering

Concatenate the second labels in ascending sequence order — *not* in capture
order, although here they happen to agree. Do not sort the fragments
lexicographically as strings; sort by the numeric identifier.

## 6. Hexadecimal decoding

The concatenated hex is the UTF-8 encoding of the flag:

```console
$ python3 - <<'PY'
fragments = [
    "475a4354467b4c4f53545f49",
    "4e5f444e535f4558414d504c",
    "455f464c41477d",
]
print(bytes.fromhex("".join(fragments)).decode())
PY
AXUM{lost_in_dns_<12 hex>}
```

## 7. Python alternative (straight from the capture)

```python
#!/usr/bin/env python3
"""Recover the hidden message from a Lost in DNS capture."""
import sys
from collections import defaultdict

from scapy.all import DNS, rdpcap

SUFFIX = "telemetry.example.test"


def recover(path):
    fragments = {}

    for packet in rdpcap(path):
        if not packet.haslayer(DNS) or packet[DNS].qr != 0:
            continue
        question = packet[DNS].qd
        if question is None:
            continue

        labels = question.qname.decode().rstrip(".").split(".")
        if len(labels) < 3 or ".".join(labels[2:]) != SUFFIX:
            continue

        sequence, payload = labels[0], labels[1]
        if not sequence.isdigit() or len(payload) % 2:
            continue
        fragments[int(sequence)] = payload

    assert sorted(fragments) == list(range(1, len(fragments) + 1)), "gap in sequence"
    payload = "".join(fragments[index] for index in sorted(fragments))
    return bytes.fromhex(payload).decode("utf-8")


if __name__ == "__main__":
    print(recover(sys.argv[1]))
```

## 8. tshark alternative

```console
$ tshark -r capture.pcap -Y 'dns.qry.name contains "telemetry.example.test"' \
    -T fields -e dns.qry.name
001.475a4354467b4c4f53545f49.telemetry.example.test
002.4e5f444e535f4558414d504c.telemetry.example.test
003.455f464c41477d.telemetry.example.test
```

```console
$ tshark -r capture.pcap -Y 'dns.qry.type == 16' -T fields -e dns.qry.name \
  | awk -F. '{print $1" "$2}' | sort -n | awk '{printf "%s", $2}' \
  | xxd -r -p
AXUM{lost_in_dns_<12 hex>}
```

## 9. Runtime flag verification

```console
$ docker run --rm -d --name net02 -e 'GZCTF_FLAG=GZCTF{LOST_IN_DNS_TEST_FLAG}' \
    -p 127.0.0.1:8080:8080 net-02-lost-in-dns:dev
$ curl -s http://127.0.0.1:8080/health
{"status": "ok", "service": "lost-in-dns", "capture": "ready"}
$ curl -s -OJ http://127.0.0.1:8080/download
$ tshark -r capture.pcap -Y 'dns.qry.type == 16' -T fields -e dns.qry.name \
  | awk -F. '{print $1" "$2}' | sort -n | awk '{printf "%s", $2}' | xxd -r -p
GZCTF{LOST_IN_DNS_TEST_FLAG}
```

The recovered value equals the injected flag, which is what GZ::CTF validates.

## 10. Common participant mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Sorting fragments as strings | `010` sorts before `002` | Sort numerically by the sequence label |
| Decoding each fragment separately | Each fragment decodes to partial text or fails | Concatenate first, then hex-decode |
| Using capture order | Usually correct, but not guaranteed | Trust the sequence identifier |
| Filtering only `A` queries | Fragments are `TXT` | Filter `dns.qry.type == 16` |
| Dropping the trailing short fragment | Flag truncated at `}` | Include the last, shorter fragment |
| Treating the hex as ASCII digits | Garbage output | Decode hex → bytes → UTF-8 |
| Assuming a fixed number of fragments | Missed data for longer flags | Count every query under the suffix |

## 11. Notes for staff

* The fragment count depends on flag length: 12 bytes per fragment. A 33-byte
  flag yields three fragments.
* The resolver answers `SERVFAIL` to every suspicious query on purpose; if a
  participant reports "the domain does not resolve", that is expected.
* Cross-team flags are rejected by GZ::CTF. Reset an instance by destroying and
  relaunching the container; the capture is regenerated from the new flag.
