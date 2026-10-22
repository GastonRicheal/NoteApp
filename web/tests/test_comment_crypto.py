import base64
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from comment_crypto import CommentCipher, CommentDecryptionError, PREFIX


class CommentCipherTests(unittest.TestCase):
    def setUp(self):
        self.key = AESGCM.generate_key(bit_length=256)
        self.cipher = CommentCipher(self.key)

    def test_unicode_and_empty_comments_round_trip(self):
        for comment in ("", "Good work", "中文评语：Très bien!\n第二行", "aesgcm:v1:ordinary user text"):
            with self.subTest(comment=comment):
                value = self.cipher.encrypt(comment, 17)
                self.assertTrue(value.startswith(PREFIX))
                self.assertNotEqual(value, comment)
                self.assertEqual(self.cipher.decrypt(value, 17), comment)

    def test_null_is_preserved(self):
        self.assertIsNone(self.cipher.encrypt(None, 17))
        self.assertIsNone(self.cipher.decrypt(None, 17))

    def test_same_comment_uses_fresh_nonce(self):
        first = self.cipher.encrypt("Same text", 17)
        second = self.cipher.encrypt("Same text", 17)
        first_payload = base64.b64decode(first[len(PREFIX):])
        second_payload = base64.b64decode(second[len(PREFIX):])
        self.assertEqual(len(first_payload), 12 + len(b"Same text") + 16)
        self.assertNotEqual(first_payload[:12], second_payload[:12])
        self.assertNotEqual(first, second)

    def test_ciphertext_is_bound_to_its_note(self):
        value = self.cipher.encrypt("Private comment", 17)
        with self.assertRaises(CommentDecryptionError):
            self.cipher.decrypt(value, 18)

    def test_nonce_ciphertext_and_tag_tampering_are_rejected(self):
        value = self.cipher.encrypt("Private comment", 17)
        payload = base64.b64decode(value[len(PREFIX):])
        for position in (0, 12, len(payload) - 1):
            changed = bytearray(payload)
            changed[position] ^= 1
            altered = PREFIX + base64.b64encode(changed).decode("ascii")
            with self.subTest(position=position), self.assertRaises(CommentDecryptionError):
                self.cipher.decrypt(altered, 17)

    def test_wrong_key_is_rejected(self):
        value = self.cipher.encrypt("Private comment", 17)
        other = CommentCipher(AESGCM.generate_key(bit_length=256))
        with self.assertRaises(CommentDecryptionError):
            other.decrypt(value, 17)

    def test_plaintext_and_malformed_values_are_rejected(self):
        for value in ("plain text", PREFIX + "!!", PREFIX, PREFIX + "YQ==", "aesgcm:v2:payload"):
            with self.subTest(value=value), self.assertRaises(CommentDecryptionError):
                self.cipher.decrypt(value, 17)

    def test_key_file_load_and_restart_preserve_decryption(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "key.b64"
            path.write_bytes(base64.b64encode(self.key) + b"\n")
            first = CommentCipher.from_key_file(path)
            value = first.encrypt("Persistent comment", 17)
            restarted = CommentCipher.from_key_file(path)
            self.assertEqual(restarted.decrypt(value, 17), "Persistent comment")

    def test_missing_or_invalid_key_never_generates_a_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "key.b64"
            with self.assertRaises(RuntimeError):
                CommentCipher.from_key_file(path)
            self.assertFalse(path.exists())
            for invalid in (b"not base64!", base64.b64encode(b"too short")):
                path.write_bytes(invalid)
                with self.assertRaises(ValueError):
                    CommentCipher.from_key_file(path)
                self.assertEqual(path.read_bytes(), invalid)


if __name__ == "__main__":
    unittest.main()
