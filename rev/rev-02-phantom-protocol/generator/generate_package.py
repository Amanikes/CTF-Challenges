#!/usr/bin/env python3
"""Runtime package generator for REV-02 — Phantom Protocol.

Reads the per-team GZCTF_FLAG, applies the Phantom Protocol transformation and
writes the participant ZIP containing README.txt, phantom-client and
protocol.dat.

The plaintext flag is never written to disk, never logged and never passed on a
command line. It exists only in this process memory and is overwritten with the
encoded bytes as soon as the payload has been produced; see the note on memory
cleanup in organizer/WRITEUP.md for the practical limits of that.
"""

import argparse
import os
import stat
import sys
import tempfile
import zipfile
from pathlib import Path

# --- Phantom Protocol specification (must match src/phantom_client.c) --------

PROTOCOL_MAGIC = b"PHTM"
PROTOCOL_VERSION = 1
PROTOCOL_HEADER_SIZE = 8
PROTOCOL_MAX_TOKEN = 128

STAGE_ADD_BASE = 0x2B
STAGE_ADD_STEP = 0x07
STAGE_ROT_BASE = 3
STAGE_ROT_STEP = 5
STAGE_XOR_KEY = b"AegisPhantomKey!"

PACKAGE_DIRECTORY = "phantom-protocol"
ARCHIVE_NAME = "phantom-protocol-package.zip"
EXECUTABLE_NAME = "phantom-client"
DATA_NAME = "protocol.dat"
README_NAME = "README.txt"


class GenerationError(Exception):
    pass


def rotate_left(value, bits):
    bits &= 7
    if bits == 0:
        return value & 0xFF
    value &= 0xFF
    return ((value << bits) | (value >> (8 - bits))) & 0xFF


def transform(payload):
    """Forward Phantom Protocol transformation (token bytes -> encoded bytes)."""
    output = bytearray(payload)
    key_length = len(STAGE_XOR_KEY)

    for index in range(len(output)):
        addend = (STAGE_ADD_BASE + index * STAGE_ADD_STEP) & 0xFF
        value = (output[index] + addend) & 0xFF
        value ^= STAGE_XOR_KEY[index % key_length]
        rotation = (STAGE_ROT_BASE + index * STAGE_ROT_STEP) & 7
        output[index] = rotate_left(value, rotation)

    return bytes(output)


def serialize(encoded):
    """protocol.dat: magic | version | length | reserved(2) | payload."""
    if not 1 <= len(encoded) <= PROTOCOL_MAX_TOKEN:
        raise GenerationError("encoded payload length is out of range")

    header = bytearray(PROTOCOL_HEADER_SIZE)
    header[0:4] = PROTOCOL_MAGIC
    header[4] = PROTOCOL_VERSION
    header[5] = len(encoded)
    header[6] = 0
    header[7] = 0

    return bytes(header) + encoded


def read_flag():
    raw = os.environ.get("GZCTF_FLAG")

    if raw is None or raw.strip() == "":
        raise GenerationError("GZCTF_FLAG is missing or empty; refusing to start")

    # Drop it from the environment as soon as it has been read.
    os.environ.pop("GZCTF_FLAG", None)

    token = raw.encode("utf-8")

    if len(token) == 0 or len(token) > PROTOCOL_MAX_TOKEN:
        raise GenerationError(f"flag length is outside the supported range (1-{PROTOCOL_MAX_TOKEN} bytes)")

    if any(byte < 0x20 or byte > 0x7E for byte in token):
        raise GenerationError("flag contains bytes outside the supported character range")

    return token


def write_archive(archive_path, executable, readme, protocol_bytes):
    executable_mode = stat.S_IFREG | 0o755
    data_mode = stat.S_IFREG | 0o644

    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        readme_info = zipfile.ZipInfo(f"{PACKAGE_DIRECTORY}/{README_NAME}", date_time=(2026, 1, 1, 0, 0, 0))
        readme_info.external_attr = data_mode << 16
        readme_info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(readme_info, readme)

        binary_info = zipfile.ZipInfo(f"{PACKAGE_DIRECTORY}/{EXECUTABLE_NAME}", date_time=(2026, 1, 1, 0, 0, 0))
        binary_info.external_attr = executable_mode << 16
        binary_info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(binary_info, executable)

        data_info = zipfile.ZipInfo(f"{PACKAGE_DIRECTORY}/{DATA_NAME}", date_time=(2026, 1, 1, 0, 0, 0))
        data_info.external_attr = data_mode << 16
        data_info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(data_info, protocol_bytes)


def build_package(output_dir, executable_path, readme_path):
    token = read_flag()

    try:
        encoded = transform(token)
    finally:
        # Practical best effort: overwrite the plaintext buffer object we own.
        # This does not guarantee the bytes are gone from the interpreter heap.
        token = b"\x00" * len(token)

    protocol_bytes = serialize(encoded)

    executable = Path(executable_path).read_bytes()
    readme = Path(readme_path).read_bytes()

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    archive_path = output_dir / ARCHIVE_NAME
    temporary_path = output_dir / (ARCHIVE_NAME + ".tmp")

    write_archive(temporary_path, executable, readme, protocol_bytes)
    temporary_path.replace(archive_path)

    return archive_path, len(encoded)


def main():
    parser = argparse.ArgumentParser(description="Generate the Phantom Protocol participant package.")
    parser.add_argument("--output-dir", required=True, help="directory that receives the ZIP archive")
    parser.add_argument("--executable", required=True, help="path to the compiled phantom-client")
    parser.add_argument("--readme", required=True, help="path to the participant README.txt")
    args = parser.parse_args()

    try:
        archive_path, length = build_package(args.output_dir, args.executable, args.readme)
    except GenerationError as error:
        print(f"[phantom-generator] {error}", file=sys.stderr)
        return 1
    except (OSError, zipfile.BadZipFile) as error:
        print(f"[phantom-generator] packaging failed: {error.__class__.__name__}", file=sys.stderr)
        return 1

    print(f"[phantom-generator] packaged {ARCHIVE_NAME} ({length} byte token, {archive_path.stat().st_size} byte archive)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
