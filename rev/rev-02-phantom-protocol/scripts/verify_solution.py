#!/usr/bin/env python3
"""Organizer recovery for REV-02 — Phantom Protocol.

Inverts the three transformation stages applied by phantom-client and prints the
accepted token. This script is organizer-only: it is excluded from the Docker
build context and never shipped inside the participant ZIP.

Forward pipeline implemented by the client (token -> protocol.dat payload):

    1. b[i] = (b[i] + (ADD_BASE + i * ADD_STEP)) mod 256
    2. b[i] = b[i] XOR KEY[i mod 12]
    3. b[i] = rotate_left(b[i], (ROT_BASE + i * ROT_STEP) mod 8)

Inverse pipeline (payload -> token), applied in reverse order:

    1. b[i] = rotate_right(b[i], (ROT_BASE + i * ROT_STEP) mod 8)
    2. b[i] = b[i] XOR KEY[i mod 12]
    3. b[i] = (b[i] - (ADD_BASE + i * ADD_STEP)) mod 256

Usage:
    python3 scripts/verify_solution.py --data protocol.dat
    python3 scripts/verify_solution.py --archive phantom-protocol-package.zip
"""

import argparse
import sys
import zipfile

MAGIC = b"PHTM"
VERSION = 1
HEADER_SIZE = 8
MAX_TOKEN = 128

STAGE_ADD_BASE = 0x2B
STAGE_ADD_STEP = 0x07
STAGE_ROT_BASE = 3
STAGE_ROT_STEP = 5
STAGE_XOR_KEY = b"AegisPhantomKey!"

PACKAGE_DIRECTORY = "phantom-protocol"
DATA_NAME = "protocol.dat"


class RecoveryError(Exception):
    pass


def rotate_right(value, bits):
    bits &= 7
    if bits == 0:
        return value & 0xFF
    value &= 0xFF
    return ((value >> bits) | (value << (8 - bits))) & 0xFF


def invert(payload):
    """Reverse the Phantom Protocol transformation (payload -> token bytes)."""
    output = bytearray(payload)
    key_length = len(STAGE_XOR_KEY)

    for index in range(len(output)):
        rotation = (STAGE_ROT_BASE + index * STAGE_ROT_STEP) & 7
        value = rotate_right(output[index], rotation)
        value ^= STAGE_XOR_KEY[index % key_length]
        addend = (STAGE_ADD_BASE + index * STAGE_ADD_STEP) & 0xFF
        output[index] = (value - addend) & 0xFF

    return bytes(output)


def parse_protocol(data):
    """Validate the container format and return the encoded payload."""
    if len(data) < HEADER_SIZE:
        raise RecoveryError("protocol data is shorter than the header")

    if data[0:4] != MAGIC:
        raise RecoveryError(f"unexpected magic {data[0:4]!r}")

    if data[4] != VERSION:
        raise RecoveryError(f"unsupported format version {data[4]}")

    length = data[5]
    if length == 0 or length > MAX_TOKEN:
        raise RecoveryError(f"declared length {length} is out of range")

    if data[6] != 0 or data[7] != 0:
        raise RecoveryError("reserved header bytes are not zero")

    if len(data) != HEADER_SIZE + length:
        raise RecoveryError(f"file is {len(data)} bytes but the header declares {HEADER_SIZE + length}")

    return data[HEADER_SIZE:]


def recover(protocol_bytes):
    return invert(parse_protocol(protocol_bytes))


def load_from_archive(path):
    with zipfile.ZipFile(path) as archive:
        return archive.read(f"{PACKAGE_DIRECTORY}/{DATA_NAME}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--data", help="path to protocol.dat")
    source.add_argument("--archive", help="path to phantom-protocol-package.zip")
    parser.add_argument("--quiet", action="store_true", help="print only the recovered token")
    args = parser.parse_args()

    try:
        if args.archive:
            protocol_bytes = load_from_archive(args.archive)
            label = f"{args.archive}::{PACKAGE_DIRECTORY}/{DATA_NAME}"
        else:
            with open(args.data, "rb") as handle:
                protocol_bytes = handle.read()
            label = args.data

        token = recover(protocol_bytes)
    except (OSError, RecoveryError, KeyError, zipfile.BadZipFile) as error:
        print(f"recovery failed: {error}", file=sys.stderr)
        return 1

    if args.quiet:
        print(token.decode("utf-8", "replace"))
        return 0

    print(f"protocol data    : {label} ({len(protocol_bytes)} bytes)")
    print(f"payload length   : {len(protocol_bytes) - HEADER_SIZE} bytes")
    print(f"recovered token  : {token.decode('utf-8', 'replace')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
