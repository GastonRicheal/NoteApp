"""Security checks for exact-byte HMAC exports and strict footer handling."""

import base64
import csv
import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac

import export_integrity
from export_integrity import (
    DOMAIN, FOOTER_BYTES, FOOTER_PREFIX, ExportHMAC, ExportSizeError,
    ExportVerificationError,
)


class ExportIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(32))  # Test-only key, never used by the application.
        self.signer = ExportHMAC(self.key)
        self.payload = b"student,class,grade,comment\r\nalice,Math,14.0,Good work\r\n"
        self.signed = self.signer.sign_csv(self.payload)

    def test_valid_export_matches_independent_hmac_implementation(self):
        self.assertEqual(self.signer.verify_csv(self.signed), self.payload)
        tag = self.signed[-FOOTER_BYTES:][len(FOOTER_PREFIX):-2]
        verifier = crypto_hmac.HMAC(self.key, hashes.SHA256())
        verifier.update(DOMAIN + self.payload)
        verifier.verify(bytes.fromhex(tag.decode("ascii")))

    def test_one_changed_grade_is_rejected(self):
        with self.assertRaises(ExportVerificationError):
            self.signer.verify_csv(self.signed.replace(b",14.0,", b",18.0,", 1))

    def test_header_comment_row_deletion_and_reordering_are_rejected(self):
        two = self.signer.sign_csv(self.payload + b"bob,Math,9.0,Late twice\r\n")
        lines = two.splitlines(keepends=True)
        altered = [
            two.replace(b"student,class", b"Student,class", 1),
            two.replace(b"Good work", b"Poor work", 1),
            b"".join([lines[0], lines[2], lines[3]]),
            b"".join([lines[0], lines[2], lines[1], lines[3]]),
        ]
        for value in altered:
            with self.subTest(value=value), self.assertRaises(ExportVerificationError):
                self.signer.verify_csv(value)

    def test_newlines_are_not_normalized_before_verification(self):
        altered = self.payload.replace(b"\r\n", b"\n") + self.signed[-FOOTER_BYTES:]
        with self.assertRaises(ExportVerificationError):
            self.signer.verify_csv(altered)

    def test_unicode_quotes_and_footer_like_text_inside_comment_round_trip(self):
        buf = io.StringIO(newline="")
        writer = csv.writer(buf, lineterminator="\r\n")
        comment = '中文评语, "Très bien"\r\n# HMAC: sha256:' + "0" * 64
        writer.writerow(["student", "class", "grade", "comment"])
        writer.writerow(["alice", "Math", "14", comment])
        payload = buf.getvalue().encode("utf-8")
        recovered = self.signer.verify_csv(self.signer.sign_csv(payload))
        self.assertEqual(recovered, payload)
        self.assertEqual(list(csv.reader(io.StringIO(recovered.decode("utf-8"), newline="")))[1][3], comment)

    def test_wrong_key_and_a_recomputed_plain_hash_do_not_pass(self):
        with self.assertRaises(ExportVerificationError):
            ExportHMAC(b"x" * 32).verify_csv(self.signed)
        edited = self.payload.replace(b",14.0,", b",18.0,")
        fake = edited + FOOTER_PREFIX + hashlib.sha256(edited).hexdigest().encode("ascii") + b"\r\n"
        with self.assertRaises(ExportVerificationError):
            self.signer.verify_csv(fake)

    def test_damaged_tag_and_malformed_missing_or_appended_footer_fail(self):
        body, footer = self.signed[:-FOOTER_BYTES], self.signed[-FOOTER_BYTES:]
        changed_tag = (b"0" if footer[len(FOOTER_PREFIX):len(FOOTER_PREFIX)+1] != b"0" else b"1")
        damaged = body + FOOTER_PREFIX + changed_tag + footer[len(FOOTER_PREFIX)+1:]
        cases = [b"", self.payload, self.signed[:-1], self.signed+b"\r\n", self.signed+b"extra",
                 body+footer.replace(b"sha256:", b"sha512:"),
                 body+FOOTER_PREFIX+b"z"*64+b"\r\n", self.signed+footer, damaged]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ExportVerificationError):
                self.signer.verify_csv(value)

    def test_signing_requires_an_unambiguous_record_boundary(self):
        for payload in (b"", b"header\n", b"header"):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.signer.sign_csv(payload)

    def test_supported_file_size_includes_the_footer(self):
        with patch.object(export_integrity, "MAX_EXPORT_BYTES", len(self.signed)):
            self.assertEqual(self.signer.sign_csv(self.payload), self.signed)
            self.assertEqual(self.signer.verify_csv(self.signed), self.payload)
        with patch.object(export_integrity, "MAX_EXPORT_BYTES", len(self.signed)-1):
            with self.assertRaises(ExportSizeError):
                self.signer.sign_csv(self.payload)
            with self.assertRaises(ExportSizeError):
                self.signer.verify_csv(self.signed)

    def test_key_file_reload_preserves_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test-hmac-key.b64"
            path.write_bytes(base64.b64encode(self.key) + b"\n")
            first = ExportHMAC.from_key_file(path)
            second = ExportHMAC.from_key_file(path)
            self.assertEqual(second.verify_csv(first.sign_csv(self.payload)), self.payload)

    def test_missing_invalid_or_short_key_is_rejected_without_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test-hmac-key.b64"
            with self.assertRaises(RuntimeError):
                ExportHMAC.from_key_file(path)
            self.assertFalse(path.exists())
            for invalid in (b"not-base64!", base64.b64encode(b"short")):
                path.write_bytes(invalid)
                with self.assertRaises(ValueError):
                    ExportHMAC.from_key_file(path)
                self.assertEqual(path.read_bytes(), invalid)


if __name__ == "__main__":
    unittest.main()
