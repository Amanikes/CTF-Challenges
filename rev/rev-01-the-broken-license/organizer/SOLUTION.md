# REV-01 — Solution (organizers)

Condensed solve guide for staff who need to verify the challenge quickly.

## 1. Get the package

```bash
PORTAL=http://127.0.0.1:<entry-port>
curl -OJ "$PORTAL/download"
unzip -o northstar-license-package.zip
cd northstar-license-package
chmod +x northstar-license
```

## 2. Identify the binary

```bash
file northstar-license
# ELF 64-bit LSB executable, x86-64, statically linked, not stripped
```

## 3. Find the transformation key

```bash
strings -a northstar-license | grep -iE 'license\.dat|accepted|K3y'
```

`NorthstarK3y` is the XOR key (12 bytes). In Ghidra it also appears as the symbol
`NORTHSTAR_XOR_KEY`, referenced from `validate_license`.

## 4. Read the validation routine

```bash
objdump -d --no-show-raw-insn --disassemble=validate_license northstar-license
```

The loop is `key[i % 12] ^ candidate[i] ^ encoded[i]`, valid when the accumulated
difference stays zero.

## 5. Decode the data file

```bash
python3 - <<'PY'
key = b"NorthstarK3y"
data = open("license.dat", "rb").read()
print(bytes(b ^ key[i % len(key)] for i, b in enumerate(data)).decode())
PY
```

Output: `AXUM{broken_license_<12 hex>}` — the team's flag.

## 6. Confirm with the binary (optional)

```bash
./northstar-license
# Enter license key: <paste the recovered key>
# License accepted. Northstar License Manager is now registered.
```

## One-liner

```bash
python3 -c 'k=b"NorthstarK3y";d=open("license.dat","rb").read();print(bytes(b^k[i%len(k)] for i,b in enumerate(d)).decode())'
```

## Automatic recovery (organizer tooling)

```bash
python3 tests/recover-flag.py --binary northstar-license --data license.dat
```

This variant assumes nothing about the key: it tries every `.rodata` string
literal as a key candidate, so it also proves the key is discoverable from the
binary alone.

## Staff notes

* Three hints are stored on the challenge (`Challenge.Hints`, a list of markdown
  strings). Hint 3 is usually enough for a stuck team.
* Running the binary is never required — static analysis is sufficient.
* Each team's flag differs, and a flag from another team is rejected by the
  platform. Reset a team's instance by destroying and relaunching the container;
  the archive is regenerated from the newly injected flag.
* `license.dat` must stay next to the executable: the utility resolves it from
  `/proc/self/exe`, so `cd`-ing elsewhere does not break it but moving the binary
  does.
