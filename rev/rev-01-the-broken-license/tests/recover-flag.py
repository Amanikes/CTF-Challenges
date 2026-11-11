#!/usr/bin/env python3
"""Independent static recovery of the accepted Northstar license key.

This is the organizer/test recovery implementation. It does not import the
generator, does not read GZCTF_FLAG and does not assume the transformation key:

  1. read the ELF section table and take the .rodata string literals;
  2. treat every printable literal as a candidate repeating XOR key;
  3. decode license.dat with each candidate;
  4. keep the decode that looks like a license key.

That mirrors the intended solve (``strings`` / Ghidra -> key -> XOR -> key)
without borrowing anything from the challenge build.

Usage:
    python3 recover-flag.py --binary northstar-license --data license.dat
"""

import argparse
import re
import sys

# e.g. AXUM{broken_license_5418ce4d815c} or GZCTF{REV01_TEST_FLAG}
LICENSE_RE = re.compile(rb"^[A-Za-z][A-Za-z0-9_]{0,15}\{[ -~]{1,200}\}$")

MIN_KEY_LEN = 4
MAX_KEY_LEN = 64


class RecoveryError(Exception):
    pass


def section_table(blob):
    """Return {section_name: (sh_type, offset, size)} for an ELF64 little-endian file."""
    if blob[:4] != b"\x7fELF" or blob[4] != 2 or blob[5] != 1:
        raise RecoveryError("not a 64-bit little-endian ELF file")

    e_shoff = int.from_bytes(blob[0x28:0x30], "little")
    e_shentsize = int.from_bytes(blob[0x3A:0x3C], "little")
    e_shnum = int.from_bytes(blob[0x3C:0x3E], "little")
    e_shstrndx = int.from_bytes(blob[0x3E:0x40], "little")

    if e_shoff == 0 or e_shnum == 0:
        raise RecoveryError("the ELF file has no section table")

    def header(index):
        base = e_shoff + index * e_shentsize
        name = int.from_bytes(blob[base:base + 4], "little")
        sh_type = int.from_bytes(blob[base + 4:base + 8], "little")
        offset = int.from_bytes(blob[base + 0x18:base + 0x20], "little")
        size = int.from_bytes(blob[base + 0x20:base + 0x28], "little")
        return name, sh_type, offset, size

    _, _, names_offset, _ = header(e_shstrndx)

    def section_name(index):
        end = blob.index(b"\x00", names_offset + index)
        return blob[names_offset + index:end].decode("latin-1")

    sections = {}
    for index in range(e_shnum):
        name_index, sh_type, offset, size = header(index)
        sections[section_name(name_index)] = (sh_type, offset, size)
    return sections


def rodata_literals(blob):
    sections = section_table(blob)
    if ".rodata" not in sections:
        raise RecoveryError("the ELF file has no .rodata section")

    _, offset, size = sections[".rodata"]
    data = blob[offset:offset + size]

    # C string literals are NUL terminated, so this yields exactly the literals
    # that `strings` shows for .rodata.
    return [chunk for chunk in data.split(b"\x00") if chunk]


def candidate_keys(literals):
    seen = set()
    for literal in literals:
        if MIN_KEY_LEN <= len(literal) <= MAX_KEY_LEN and all(0x20 <= byte <= 0x7E for byte in literal):
            if literal not in seen:
                seen.add(literal)
                yield literal


def xor_decode(data, key):
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def recover(binary_path, data_path):
    blob = open(binary_path, "rb").read()
    encoded = open(data_path, "rb").read()

    if len(encoded) == 0:
        raise RecoveryError("license.dat is empty")

    literals = rodata_literals(blob)
    hits = []

    for key in candidate_keys(literals):
        decoded = xor_decode(encoded, key)
        if LICENSE_RE.match(decoded):
            hits.append((key, decoded))

    if not hits:
        raise RecoveryError(f"no .rodata string decoded license.dat into a license key ({len(literals)} literals tried)")

    flags = {flag for _, flag in hits}
    if len(flags) > 1:
        raise RecoveryError(f"recovery is ambiguous: {len(flags)} different candidate keys produced a key-shaped result")

    key, flag = hits[0]
    return key, flag, len(literals), len(hits)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", default="northstar-license", help="path to the ELF executable")
    parser.add_argument("--data", default="license.dat", help="path to the encoded license data")
    parser.add_argument("--quiet", action="store_true", help="print only the recovered key")
    args = parser.parse_args()

    try:
        key, flag, literals, hits = recover(args.binary, args.data)
    except (OSError, RecoveryError) as error:
        print(f"recovery failed: {error}", file=sys.stderr)
        return 1

    if args.quiet:
        print(flag.decode())
        return 0

    print(f"binary            : {args.binary}")
    print(f"data file         : {args.data} ({len(open(args.data, 'rb').read())} bytes)")
    print(f".rodata literals  : {literals}")
    print(f"candidate keys    : {hits} matched")
    print(f"xor key recovered : {key.decode('latin-1')} ({len(key)} bytes)")
    print(f"accepted license  : {flag.decode()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
