"""Hexadecimal encoding and DNS fragment helpers for NET-02 — Lost in DNS.

The flag is converted to UTF-8 bytes, hex-encoded, split into fixed-size
fragments and carried in DNS query name labels:

    001.<hex>.telemetry.example.test
    002.<hex>.telemetry.example.test
    ...

Every helper is pure and side-effect free so the generator and the tests can
share exactly the same implementation.
"""

FRAGMENT_HEX_CHARS = 24
SEQUENCE_DIGITS = 3
SUSPICIOUS_SUFFIX = "telemetry.example.test"
MAX_FLAG_BYTES = 400

HEX_DIGITS = frozenset("0123456789abcdef")


class EncodingError(ValueError):
    """Raised when a flag or fragment cannot be represented safely."""


def encode_flag(flag):
    """Return the lowercase hex representation of the flag's UTF-8 bytes."""
    if not isinstance(flag, str):
        raise EncodingError("flag must be a string")
    if flag == "":
        raise EncodingError("flag must not be empty")

    try:
        raw = flag.encode("utf-8")
    except UnicodeEncodeError as error:  # pragma: no cover - defensive
        raise EncodingError("flag is not valid UTF-8") from error

    if len(raw) > MAX_FLAG_BYTES:
        raise EncodingError(f"flag exceeds the supported maximum of {MAX_FLAG_BYTES} bytes")

    return raw.hex()


def fragment(hex_string, size=FRAGMENT_HEX_CHARS):
    """Split a hex string into fragments of `size` characters."""
    if size < 2 or size % 2 != 0:
        raise EncodingError("fragment size must be an even number of hex characters")

    if not isinstance(hex_string, str) or hex_string == "":
        raise EncodingError("hex payload must not be empty")

    if len(hex_string) % 2 != 0:
        raise EncodingError("hex payload must describe a whole number of bytes")

    validate_hex(hex_string)

    return [hex_string[index:index + size] for index in range(0, len(hex_string), size)]


def validate_hex(value):
    """Reject anything that is not an even-length lowercase hex string."""
    if len(value) % 2 != 0:
        raise EncodingError("hex fragment must contain a whole number of bytes")
    if not set(value) <= HEX_DIGITS:
        raise EncodingError("hex fragment contains non-hexadecimal characters")


def validate_fragment(value):
    """A single DNS payload label: hex, even length, within the label limit."""
    if not value:
        raise EncodingError("fragment must not be empty")
    if len(value) > 63:
        raise EncodingError("fragment exceeds the 63-octet DNS label limit")
    validate_hex(value)


def sequence_label(index):
    """Zero-padded three-digit sequence identifier (1-based)."""
    if index < 1:
        raise EncodingError("sequence identifiers start at 1")
    label = f"{index:0{SEQUENCE_DIGITS}d}"
    if len(label) > SEQUENCE_DIGITS:
        raise EncodingError("too many fragments for a three-digit sequence identifier")
    return label


def query_name(index, fragment_hex, suffix=SUSPICIOUS_SUFFIX):
    """Build one suspicious query name: <seq>.<hex>.<suffix>."""
    validate_fragment(fragment_hex)
    name = f"{sequence_label(index)}.{fragment_hex}.{suffix}"

    for label in name.split("."):
        if len(label.encode("ascii", "ignore")) > 63:
            raise EncodingError("DNS label exceeds the 63-octet limit")

    # 255 octets in wire format: each label plus its length byte, plus the
    # terminating zero. Characters are ASCII, so octets == characters.
    if len(name) + 2 > 255:
        raise EncodingError("DNS name exceeds the 255-octet wire-format limit")

    return name


def query_names(flag, suffix=SUSPICIOUS_SUFFIX):
    """Full pipeline: flag -> hex -> fragments -> query names."""
    fragments = fragment(encode_flag(flag))
    return [query_name(index, value, suffix) for index, value in enumerate(fragments, start=1)]


def parse_query_name(name, suffix=SUSPICIOUS_SUFFIX):
    """Return (sequence, fragment) for a suspicious name, or None if unrelated."""
    labels = name.rstrip(".").split(".")

    if len(labels) < 3:
        return None

    if ".".join(labels[2:]) != suffix:
        return None

    sequence, payload = labels[0], labels[1]

    if len(sequence) != SEQUENCE_DIGITS or not sequence.isdigit():
        return None

    try:
        validate_fragment(payload)
    except EncodingError:
        return None

    return int(sequence, 10), payload


def reassemble(names, suffix=SUSPICIOUS_SUFFIX):
    """Rebuild the hex payload from an unordered collection of query names."""
    parsed = {}

    for name in names:
        result = parse_query_name(name, suffix)
        if result is None:
            continue
        sequence, payload = result
        if sequence in parsed:
            raise EncodingError(f"duplicate fragment sequence {sequence}")
        parsed[sequence] = payload

    if not parsed:
        raise EncodingError("no suspicious fragments found")

    expected = list(range(1, len(parsed) + 1))
    if sorted(parsed) != expected:
        raise EncodingError("fragment sequence is incomplete or out of order")

    return "".join(parsed[sequence] for sequence in expected)


def decode_hex_payload(hex_string):
    """Hex string -> original UTF-8 flag."""
    validate_hex(hex_string)

    try:
        return bytes.fromhex(hex_string).decode("utf-8")
    except UnicodeDecodeError as error:
        raise EncodingError("decoded payload is not valid UTF-8") from error


def decode_names(names, suffix=SUSPICIOUS_SUFFIX):
    """Convenience: query names -> flag."""
    return decode_hex_payload(reassemble(names, suffix))


def roundtrip(flag):
    """Return True when the flag survives the full encode/reassemble cycle."""
    try:
        return decode_names(query_names(flag)) == flag
    except EncodingError:
        return False
