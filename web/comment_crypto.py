"""AES-GCM protection for the notes.comment column.

Stored text: aesgcm:v1:<base64(nonce || ciphertext || authentication tag)>.
The secret key is loaded from a separate file and is never stored in PostgreSQL.
"""

import base64
import binascii
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


PREFIX = "aesgcm:v1:"
NONCE_BYTES = 12
TAG_BYTES = 16


class CommentDecryptionError(ValueError):
    """Malformed, modified, misplaced or unreadable encrypted comment."""


class CommentCipher:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("The comment encryption key must contain 32 bytes (AES-256).")
        self._aes = AESGCM(key)

    @classmethod
    def from_key_file(cls, path: Path):
        try:
            encoded_key = path.read_bytes().strip()
        except OSError as error:
            raise RuntimeError(
                "Cannot read the comment encryption key file. "
                "Generate it before starting NotesApp and configure COMMENT_ENCRYPTION_KEY_FILE."
            ) from error
        try:
            key = base64.b64decode(encoded_key, validate=True)
        except (ValueError, binascii.Error) as error:
            raise ValueError("The comment encryption key file must contain valid Base64.") from error
        return cls(key)

    @staticmethod
    def _associated_data(note_id: int) -> bytes:
        # Bind the ciphertext to this row: copying it to another note must fail.
        return f"notesapp:notes:{int(note_id)}:comment:v1".encode("ascii")

    def encrypt(self, comment: str | None, note_id: int) -> str | None:
        if comment is None:
            return None
        nonce = os.urandom(NONCE_BYTES)
        ciphertext_and_tag = self._aes.encrypt(
            nonce, comment.encode("utf-8"), self._associated_data(note_id),
        )
        payload = base64.b64encode(nonce + ciphertext_and_tag).decode("ascii")
        return PREFIX + payload

    def decrypt(self, value: str | None, note_id: int) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not value.startswith(PREFIX):
            raise CommentDecryptionError("The comment is not in the encrypted storage format.")
        try:
            payload = base64.b64decode(value[len(PREFIX):], validate=True)
            if len(payload) < NONCE_BYTES + TAG_BYTES:
                raise ValueError("Truncated encrypted comment.")
            plaintext = self._aes.decrypt(
                payload[:NONCE_BYTES], payload[NONCE_BYTES:], self._associated_data(note_id),
            )
            return plaintext.decode("utf-8")
        except (InvalidTag, ValueError, UnicodeError, binascii.Error) as error:
            # Do not return unverified data or silently treat damaged ciphertext as plaintext.
            raise CommentDecryptionError("The encrypted comment could not be authenticated.") from error


def load_comment_cipher() -> CommentCipher:
    path = Path(os.environ.get("COMMENT_ENCRYPTION_KEY_FILE",
                               "/run/secrets/comment_encryption_key"))
    return CommentCipher.from_key_file(path)
