# REV-02 — Organizer Writeup: Phantom Protocol

> **Organizer-only.** This directory is excluded from the Docker build context
> and is never copied into the participant ZIP or the runtime image.

## 1. Challenge overview

| | |
|---|---|
| Name | Phantom Protocol |
| Category | Reverse Engineering |
| Difficulty / points | Hard / 300 |
| Platform | Linux ELF64 x86-64 |
| Language | C |
| Technique | Reversible three-stage obfuscation (add / XOR / rotate) |
| Artifact | `phantom-protocol-package.zip`, generated per team |
| Flag source | GZ::CTF dynamic flag (`GZCTF_FLAG`) |
| Guidance | Moderate — three staged hints |

Participants receive `phantom-client` (stripped, statically linked) and
`protocol.dat`. The accepted token — the team's dynamic flag — is only present
inside `protocol.dat`, in transformed form.

## 2. Expected participant solve path

1. Download and extract the package.
2. `file`, `readelf`, `strings` on the executable. The strings
   `ACCESS GRANTED`, `ACCESS DENIED`, `PHTM` and `AegisPhantomKey!` are the
   useful anchors; the binary is stripped, so there are no symbol names.
3. Find the validation routine by xref to `ACCESS GRANTED` / `ACCESS DENIED`,
   then follow the call into the transformation loop.
4. Recognise three stages: an additive constant that depends on the index, an
   XOR against a 16-byte key, and a variable bit rotation.
5. Read the protocol header to learn the payload length, then invert the stages
   in reverse order on the payload.
6. Submit the recovered token; optionally confirm with
   `./phantom-client --verify '<token>'`.

## 3. ELF inspection commands

```console
$ file phantom-client
phantom-client: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
  statically linked, BuildID[sha1]=530dcabd…, stripped

$ readelf -h phantom-client | sed -n '2,7p'
  Class:                             ELF64
  Data:                              2's complement, little endian
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64

$ readelf -S phantom-client | grep -E '\.text|\.rodata'
  [ 4] .text    PROGBITS  0000000000401010  00001010
  [ 6] .rodata  PROGBITS  0000000000408000  00008000

$ strings -a -t x phantom-client | grep -E 'PHTM|ACCESS|AegisPhantomKey'
   8290 AegisPhantomKey!
   …    ACCESS GRANTED
   …    ACCESS DENIED
```

`strings -t x` gives the file offset of the key: `0x8290`. Because `.rodata`
maps file offset `0x8000` to virtual address `0x408000`, the key lives at
**`0x408290`** at runtime.

## 4. Identifying the validation routine

The binary is stripped, so start from the decision strings and walk backwards.
The three stages were compiled as three small helpers at `-O1 -fno-inline`:

```text
0x40114d   rotate_left(value, bits)
           mov %edi,%eax ; mov %esi,%ecx ; rol %cl,%al ; ret

0x401154   position_addend(index)
           lea 0x0(,%rdi,8),%eax ; sub %edi,%eax ; add $0x2b,%eax ; ret
           => 8*index - index + 0x2b  ==  7*index + 0x2b

0x401161   position_rotation(index)
           lea 0x3(%rdi,%rdi,4),%eax ; and $0x7,%eax ; ret
           => (index + 4*index + 3) & 7  ==  (5*index + 3) & 7
```

The main transformation loop starts at `0x401417`:

```text
40141a  je     0x401478                 ; empty buffer -> nothing to do
40142f  lea    0x6e5a(%rip),%r14        # 0x408290   <- XOR key
401436  movzbl (%r12,%rbx,1),%ebp       ; b = buffer[i]
40143b  mov    %rbx,%rdi
40143e  call   0x401154                 ; addend = 7*i + 0x2b
401443  add    %eax,%ebp                ; b += addend          (stage 1)
401445  mov    %rbx,%rax
401448  and    $0xf,%eax                ; i & 15  -> key length 16
40144b  xor    (%r14,%rax,1),%bpl       ; b ^= key[i % 16]     (stage 2)
40144f  mov    %rbx,%rdi
401452  call   0x401161                 ; rotation = (5*i + 3) & 7
401457  mov    %eax,%esi
401459  movzbl %bpl,%edi
40145d  call   0x40114d                 ; b = rol(b, rotation) (stage 3)
401462  mov    %al,(%r12,%rbx,1)        ; buffer[i] = b
401466  add    $0x1,%rbx
40146a  cmp    %rbx,%r13
40146d  jne    0x401436
```

The comparison after the call accumulates a difference byte
(`difference |= working[i] ^ payload[i]`) and returns true only when it stays
zero, so the loop always runs to completion.

## 5. Exact transformation stages

Forward (candidate token -> stored payload):

| # | Stage | Formula |
|---|---|---|
| 1 | Position-dependent addition | `b[i] = (b[i] + ((0x2B + 7*i) mod 256)) mod 256` |
| 2 | Repeating-key XOR | `b[i] = b[i] XOR KEY[i mod 16]` |
| 3 | Position-dependent rotation | `b[i] = rotl8(b[i], (3 + 5*i) mod 8)` |

## 6. Exact key material and constants

| Item | Value |
|---|---|
| XOR key | `AegisPhantomKey!` (16 bytes) |
| Key address | `0x408290` (`.rodata`), referenced by `lea 0x6e5a(%rip),%r14` at `0x40142f` |
| Addition base | `0x2B` (43) |
| Addition step | `7` |
| Rotation base | `3` |
| Rotation step | `5` |
| Rotation direction | left (`rol %cl,%al`) |
| `rotl8` with 0 bits | identity (guarded in source, never emitted for a 0 count) |

## 7. Inverse transformation (reverse order)

| # | Stage | Formula |
|---|---|---|
| 1 | Undo rotation | `b[i] = rotr8(payload[i], (3 + 5*i) mod 8)` |
| 2 | Undo XOR | `b[i] = b[i] XOR KEY[i mod 16]` |
| 3 | Undo addition | `b[i] = (b[i] - ((0x2B + 7*i) mod 256)) mod 256` |

`rotr8(v, n) = ((v >> n) | (v << (8 - n))) & 0xFF` for `n > 0`, identity for
`n == 0`. Because the stages are applied per byte and index, they commute with
respect to *other* bytes only — the order within one byte must be reversed
exactly as above.

## 8. Protocol data format

| Offset | Size | Field | Notes |
|---|---|---|---|
| `0x00` | 4 | magic | ASCII `PHTM` |
| `0x04` | 1 | version | `1` |
| `0x05` | 1 | length | payload length, `1..128` |
| `0x06` | 2 | reserved | must be `0x0000` |
| `0x08` | *length* | payload | transformed token bytes |

Total file size is exactly `8 + length`; the client rejects anything else. All
multi-byte fields are little-endian by position, though only the reserved pair
is wider than a byte.

The client rejects: wrong magic, wrong version, zero length, length > 128,
non-zero reserved bytes, truncated files, trailing bytes, and unreadable files —
all with the same generic message:

```text
phantom-client: protocol data rejected: unsupported or corrupted format
```

## 9. Recovery script

[`scripts/verify_solution.py`](../scripts/verify_solution.py) implements the
inverse pipeline and validates the container format.

```console
$ python3 scripts/verify_solution.py --archive phantom-protocol-package.zip
protocol data    : phantom-protocol-package.zip::phantom-protocol/protocol.dat (33 bytes)
payload length   : 25 bytes
recovered token  : AXUM{phantom_protocol_<12 hex>}
```

Minimal standalone version:

```python
#!/usr/bin/env python3
import struct

KEY = b"AegisPhantomKey!"
data = open("protocol.dat", "rb").read()

assert data[:4] == b"PHTM" and data[4] == 1
length = data[5]
payload = data[8:8 + length]

out = bytearray()
for i, b in enumerate(payload):
    n = (3 + 5 * i) & 7
    b = b if n == 0 else ((b >> n) | (b << (8 - n))) & 0xFF
    b ^= KEY[i % len(KEY)]
    b = (b - ((0x2B + 7 * i) & 0xFF)) & 0xFF
    out.append(b)

print(out.decode())
```

## 10. Local verification command

```console
$ unzip -o phantom-protocol-package.zip
$ cd phantom-protocol
$ chmod +x phantom-client
$ ./phantom-client --verify 'AXUM{phantom_protocol_<12 hex>}'
ACCESS GRANTED
$ ./phantom-client --verify 'AXUM{phantom_protocol_000000000000}'
ACCESS DENIED
```

The automated equivalent is `tests/run-tests.sh`, which builds the image and
runs the generator, binary, isolation and security suites.

## 11. Common mistakes and debugging guidance

| Symptom | Cause |
|---|---|
| Recovered text is garbage from the first byte | Stages applied in forward order instead of reverse order |
| First few characters look right, later ones garbage | Rotation applied with a constant count instead of `(3 + 5*i) & 7` |
| Garbage after byte 16 | Key index advanced past the key instead of `i % 16` |
| Every byte off by a growing amount | Addition step missed; only `0x2B` applied |
| `ACCESS DENIED` with the visually identical token | Trailing newline or space captured from a terminal selection |
| `unsupported or corrupted format` | Header edited, or the file was truncated while copying |
| Nothing found at `0x408290` | Binary rebuilt with different sources; always resolve the `lea` at `0x40142f` instead of hardcoding the address |

Debug tip: transform a known short token by hand (e.g. `A`) and compare with a
single byte of the payload to isolate which stage is misordered.

## 12. Security lessons

* **A client-side check cannot protect a secret the client must be able to
  verify.** The accepted token is recoverable by anyone holding the client and
  the data file; the only question is how much work is required.
* **Chained reversible transforms are obfuscation, not cryptography.** Add,
  XOR and rotate are all trivially invertible; the composition does not add
  secrecy, only reading effort.
* **Stripping symbols raises cost, not security.** It removes names but not the
  constants, which remain as immediates in code and as literals in `.rodata`.
* **Anything embedded in a distributed artifact is public.** The correct design
  keeps the secret server-side and sends only a proof (e.g. a MAC over a
  server-issued challenge), or uses a signature the client can verify without
  learning the key.
* **Length and structure leak information.** `protocol.dat` is exactly
  `8 + len(token)` bytes, so the payload file reveals the token length before
  any analysis.

## 13. Secret handling in the runtime image

* `entrypoint.sh` validates `GZCTF_FLAG` and hands it to
  `generator/generate_package.py`, which is the only process that ever sees the
  plaintext.
* The generator pops `GZCTF_FLAG` from `os.environ` immediately after reading it,
  then overwrites its own `bytes` object with zeros once the payload is built.
* The generator writes only the transformed payload into `protocol.dat` inside
  the ZIP; `protocol.dat` is never left on the runtime filesystem.
* The shell then `unset`s the variable and `exec`s the download service, so the
  long-running process never inherits it.
* The generator never prints the flag; its only output line contains the token
  *length* and archive size.
* **Limits of this cleanup:** overwriting a Python `bytes` object does not scrub
  copies made by the allocator, the kernel, pagefile/swap, or a core dump. The
  goal here is to keep the secret out of the long-running service and out of
  persistent storage, not to claim secure memory erasure.

## 14. Build and test evidence

See [../organizer/TESTING.md](TESTING.md) for executed commands and results.
