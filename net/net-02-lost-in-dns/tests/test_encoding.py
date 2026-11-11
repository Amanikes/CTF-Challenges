"""Encoding and fragmentation tests for NET-02 — Lost in DNS."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

import encoding  # noqa: E402
from encoding import (  # noqa: E402
    EncodingError,
    SUSPICIOUS_SUFFIX,
    decode_names,
    decode_hex_payload,
    encode_flag,
    fragment,
    query_name,
    query_names,
    reassemble,
    roundtrip,
    validate_fragment,
)


class EncodeTests(unittest.TestCase):
    def test_normal_flag_encoding(self):
        self.assertEqual(encode_flag("GZCTF{example}"), "475a4354467b6578616d706c657d")

    def test_single_byte_flag(self):
        self.assertEqual(encode_flag("A"), "41")

    def test_empty_flag_is_rejected(self):
        with self.assertRaises(EncodingError):
            encode_flag("")

    def test_non_string_is_rejected(self):
        with self.assertRaises(EncodingError):
            encode_flag(b"GZCTF{bytes}")

    def test_over_long_flag_is_rejected(self):
        with self.assertRaises(EncodingError):
            encode_flag("A" * (encoding.MAX_FLAG_BYTES + 1))

    def test_utf8_flag_encoding(self):
        # Multi-byte characters must survive the byte-oriented pipeline.
        self.assertEqual(encode_flag("é"), "c3a9")
        self.assertTrue(roundtrip("AXUM{na\u00efve_caf\u00e9}"))


class FragmentTests(unittest.TestCase):
    def test_multiple_fragments(self):
        fragments = fragment("a" * 60)
        self.assertEqual(len(fragments), 3)
        self.assertEqual([len(value) for value in fragments], [24, 24, 12])

    def test_short_payload_single_fragment(self):
        self.assertEqual(fragment("475a435446"), ["475a435446"])

    def test_odd_final_fragment_is_rejected(self):
        with self.assertRaises(EncodingError):
            fragment("abc")

    def test_empty_payload_is_rejected(self):
        with self.assertRaises(EncodingError):
            fragment("")

    def test_non_hex_payload_is_rejected(self):
        with self.assertRaises(EncodingError):
            fragment("zz12")

    def test_uppercase_hex_is_rejected(self):
        with self.assertRaises(EncodingError):
            fragment("AB12")

    def test_odd_fragment_size_is_rejected(self):
        with self.assertRaises(EncodingError):
            fragment("aabb", size=3)

    def test_validate_fragment_limits(self):
        with self.assertRaises(EncodingError):
            validate_fragment("a" * 64)
        validate_fragment("a" * 62)


class QueryNameTests(unittest.TestCase):
    def test_query_name_layout(self):
        name = query_name(1, "475a4354467b4c4f53545f49")
        self.assertEqual(name, f"001.475a4354467b4c4f53545f49.{SUSPICIOUS_SUFFIX}")

    def test_sequence_labels(self):
        self.assertEqual(encoding.sequence_label(1), "001")
        self.assertEqual(encoding.sequence_label(42), "042")

    def test_label_length_limits(self):
        fragments = fragment(encode_flag("GZCTF{" + "A" * 300 + "}"))
        for index, value in enumerate(fragments, start=1):
            name = query_name(index, value)
            for label in name.split("."):
                self.assertLessEqual(len(label), 63)
            self.assertLessEqual(len(name) + 2, 255)

    def test_sequence_overflow_is_rejected(self):
        with self.assertRaises(EncodingError):
            encoding.sequence_label(1000)


class ReconstructionTests(unittest.TestCase):
    def test_reconstruction_roundtrip(self):
        flag = "AXUM{lost_in_dns_reconstruction}"
        names = query_names(flag)
        self.assertEqual(decode_names(names), flag)

    def test_reconstruction_handles_unordered_input(self):
        flag = "AXUM{unordered_fragments}"
        names = query_names(flag)
        self.assertGreater(len(names), 1)
        self.assertEqual(decode_names(list(reversed(names))), flag)

    def test_short_flag_roundtrip(self):
        self.assertEqual(decode_names(query_names("A")), "A")

    def test_long_flag_roundtrip(self):
        flag = "AXUM{" + "abcdefghij" * 30 + "}"
        self.assertTrue(roundtrip(flag))

    def test_missing_fragment_is_detected(self):
        names = query_names("AXUM{missing_fragment_check}")
        with self.assertRaises(EncodingError):
            reassemble(names[1:])

    def test_duplicate_fragment_is_detected(self):
        names = query_names("AXUM{duplicate_fragment_check}")
        with self.assertRaises(EncodingError):
            reassemble(names + [names[0]])

    def test_unrelated_names_are_ignored(self):
        names = query_names("AXUM{ignored_noise_check}")
        names.append("portal.meridian.internal")
        self.assertEqual(decode_names(names), "AXUM{ignored_noise_check}")

    def test_reassembly_without_fragments_is_an_error(self):
        with self.assertRaises(EncodingError):
            reassemble(["portal.meridian.internal"])

    def test_invalid_utf8_payload_is_rejected(self):
        with self.assertRaises(EncodingError):
            decode_hex_payload("ff")

    def test_suspicious_suffix_is_consistent(self):
        names = query_names("AXUM{suffix}")
        self.assertTrue(all(name.endswith(SUSPICIOUS_SUFFIX) for name in names))


if __name__ == "__main__":
    unittest.main(verbosity=2)
