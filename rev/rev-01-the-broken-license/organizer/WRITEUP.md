# REV-01 — Organizer Writeup: The Broken License

## 1. Challenge overview

| | |
|---|---|
| Name | The Broken License |
| Category | Reverse Engineering |
| Difficulty / points | Easy / 100 |
| Technique | Repeating-key XOR |
| Artifact | `northstar-license-package.zip` (per team) |
| Flag source | GZ::CTF dynamic flag (`GZCTF_FLAG`) |
| Guidance | Guided — three staged hints |
| Expected solve time | 10–20 minutes |

Participants download a per-team ZIP containing a Linux x86_64 ELF executable
and an encoded `license.dat`. Reversing the validation routine yields the XOR
key; applying it to the data file yields the team's flag, which is the accepted
license key.

The plaintext flag never exists in the image, the archive or the executable —
only the XOR-encoded bytes in `license.dat`.

## 2. ELF identification

```console
$ file northstar-license
northstar-license: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
  statically linked, BuildID[sha1]=89c9359b…, not stripped
```

```console
$ readelf -h northstar-license | sed -n '2,6p'
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
```

Design notes that keep the first challenge approachable:

* **static** — the binary runs on any Linux x86_64 host regardless of the
  participant's libc version;
* **not stripped** — `validate_license` and `NORTHSTAR_XOR_KEY` appear as named
  symbols, which is the intended first step;
* **no DWARF** — `.debug_*` sections are removed with `objcopy --strip-debug`, so
  there are no source paths or line tables to shortcut the analysis;
* `-O1 -fno-inline` — the validation function survives as a real function with a
  short, readable loop instead of being inlined into `main`.

## 3. Useful strings

```console
$ strings -a northstar-license | grep -nE 'license.dat|Enter license|accepted|NorthstarK3y'
233:license.dat
237:Enter license key:
249:License accepted. Northstar License Manager is now registered.
250:License rejected: the key does not match the installed license data.
251:NorthstarK3y
```

Line 251 is the transformation key. It is a plain C string literal, so it
survives in `.rodata` and is also directly visible in the symbol table as
`NORTHSTAR_XOR_KEY`.

## 4. Relevant validation function

`validate_license` is called once from `main` with four arguments:
`candidate`, `candidate_len`, `encoded`, `encoded_len`.

```console
$ objdump -d --no-show-raw-insn --disassemble=validate_license northstar-license
0000000000401284 <validate_license>:
  401284: mov    %rdi,%r8
  401287: mov    %rsi,%rdi
  40128a: mov    %rdx,%r9
  401292: cmp    %rcx,%rsi               ; candidate_len == encoded_len ?
  401295: jne    4012f2 <validate_license+0x6e>
  4012a6: lea    0x6fd3(%rip),%r11      ; r11 = &NORTHSTAR_XOR_KEY   <-- key
  4012ad: movabs $0xaaaaaaaaaaaaaaab,%r10
  4012b7: mov    %rcx,%rax
  4012ba: mul    %r10                    ; magic-number division ...
  4012bd: shr    $0x3,%rdx
  4012c1: lea    (%rdx,%rdx,2),%rax
  4012c5: shl    $0x2,%rax
  4012c9: mov    %rcx,%rdx
  4012cc: sub    %rax,%rdx               ; rdx = i % 12   (key length)
  4012cf: movzbl (%r11,%rdx,1),%eax      ; key[i % 12]
  4012d4: xor    (%r8,%rcx,1),%al        ; ^ candidate[i]
  4012d8: xor    (%r9,%rcx,1),%al        ; ^ encoded[i]
  4012dc: movzbl %al,%eax
  4012df: or     %eax,%esi               ; difference |= ...
  4012e1: add    $0x1,%rcx
  4012e5: cmp    %rcx,%rdi
  4012e8: jne    4012b7 <validate_license+0x33>
  4012ea: test   %esi,%esi
  4012ec: sete   %al                     ; return difference == 0
  4012f2: ret
```

Two `xor` instructions in a row followed by an accumulator `or` is the whole
algorithm: `candidate[i] ^ key[i % 12] ^ encoded[i]`, valid only when every byte
cancels.

### Key location

| Item | Value |
|---|---|
| Symbol | `NORTHSTAR_XOR_KEY` |
| Section | `.rodata` |
| Address (this build) | `0x408280` |
| Value | `NorthstarK3y` |
| Length | 12 bytes |
| Reference | `lea 0x6fd3(%rip),%r11` at `0x4012a6` |

The magic constant `0xaaaaaaaaaaaaaaab` with `shr $3` is gcc's division by 12 —
that is the key length, not an obfuscation trick, and it tells the solver the
key is 12 bytes long.

## 5. XOR algorithm

```
C[i] = P[i] XOR K[i % n]
P[i] = C[i] XOR K[i % n]
```

with `K = "NorthstarK3y"`, `n = 12`, `P` = the plaintext license (the team's
flag) and `C` = the bytes written to `license.dat`.

Encoded data extraction for the worked example
`AXUM{broken_license_5418ce4d815c}` (33 bytes):

```console
$ xxd license.dat
00000000: 0f37 2739 1311 060e 192e 5d26 2206 1111  .7'9......]&"...
00000010: 0600 113e 477f 0241 2d0a 4610 5042 4102  ...>G..A-.F.PBA.
00000020: 0f                                       .
```

Note that `license.dat` is exactly `len(flag)` bytes — no header, no padding — so
the flag length is also visible from the file size.

## 6. Tested recovery script

[`tests/recover-flag.py`](../tests/recover-flag.py) performs the recovery with no
knowledge of the key or of the generator: it parses the ELF section table, takes
NUL-terminated `.rodata` literals, and tries each one as a repeating XOR key
until the decode of `license.dat` looks like a license key.

```console
$ python3 tests/recover-flag.py --binary northstar-license --data license.dat
binary            : northstar-license
data file         : license.dat (22 bytes)
.rodata literals  : 243
candidate keys    : 1 matched
xor key recovered : NorthstarK3y (12 bytes)
accepted license  : GZCTF{REV01_TEST_FLAG}
```

The script refuses to return a result when several literals produce a
key-shaped decode, so an accidental ambiguity fails loudly instead of passing.

Minimal participant version of the same idea:

```python
#!/usr/bin/env python3
import sys

key = b"NorthstarK3y"
data = open("license.dat", "rb").read()
print(bytes(b ^ key[i % len(key)] for i, b in enumerate(data)).decode())
```

## 7. Verified solve steps

```console
$ curl -OJ http://<entry>/download          # or click Download package
$ unzip -o northstar-license-package.zip
$ cd northstar-license-package
$ chmod +x northstar-license
$ file northstar-license                    # ELF 64-bit LSB executable, x86-64, statically linked
$ strings -a northstar-license | grep -iE 'license|key'
$ objdump -d --disassemble=validate_license northstar-license   # xor key, xor loop
$ xxd license.dat                           # 22 encoded bytes
$ python3 -c 'k=b"NorthstarK3y"; d=open("license.dat","rb").read(); \
      print(bytes(b^k[i%len(k)] for i,b in enumerate(d)).decode())'
AXUM{broken_license_5418ce4d815c}
$ echo 'AXUM{broken_license_5418ce4d815c}' | ./northstar-license
License accepted. Northstar License Manager is now registered.
```

Executing the binary is optional; static analysis is sufficient. Running it only
confirms that the recovered value is the accepted one.

## 8. Runtime artifact generation

`entrypoint.sh`:

1. rejects a missing/empty/blank `GZCTF_FLAG`;
2. runs `node scripts/generate-artifact.js` — the only process that inherits the
   flag;
3. the generator validates length (1–128 bytes) and character range
   (`0x20`–`0x7e`), XOR-encodes the flag, writes `license.dat`, builds the ZIP
   and exits;
4. `unset GZCTF_FLAG`;
5. `exec node server.js` — the download service never sees the flag.

Inside the generator the plaintext `Buffer` is zero-filled after encoding
(`plaintext.fill(0)`), and `delete process.env.GZCTF_FLAG` runs immediately after
the value is read.

Failure is generic and never echoes the value:

```console
$ docker run --rm -e "GZCTF_FLAG=$(python3 -c 'print("A"*150)')" rev-01-broken-license:dev
[entrypoint] ...
[northstar-artifact] the injected flag length is outside the supported range (1-128 bytes)
```

## 9. Root cause (in the narrative of the challenge)

The developer treated the XOR key as a secret but shipped it inside the client
binary, and shipped the encoded license alongside it. Anyone with both files can
recover the plaintext: XOR is symmetric, so the "protection" is only as strong as
the secrecy of a constant that is embedded in a distributed artifact.

Real-world lessons reinforced by the challenge:

* Obfuscation is not cryptography; a key shipped with the data protects nothing.
* Client-side validation can always be bypassed by the person holding the client.
* `strings` and a five-line script defeat "hidden" constants in compiled code.

## 10. Common failure modes

| Symptom | Cause |
|---|---|
| `license.dat is missing` | The participant moved the executable away from the data file; the tool resolves `license.dat` relative to `/proc/self/exe`. |
| `could not be read or is corrupted` | Data file empty, or larger than the 128-byte maximum. |
| Recovered text looks like garbage | Wrong key length assumption; the key is 12 bytes, not the flag length. |
| `License rejected` with the correct-looking key | Trailing newline included in the candidate string, or the key was mis-copied. |
| Container exits at start | `GZCTF_FLAG` was not injected — confirm the challenge type is `DynamicContainer`. |
| `/health` returns 503 | Archive generation failed; check `docker logs` for the `[northstar-artifact]` line. |
