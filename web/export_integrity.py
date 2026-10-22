"""Authenticate the exact bytes of a grades CSV with a separate HMAC key.

Wire format: UTF-8 CSV with CRLF records, followed by the final ASCII line
    # HMAC: sha256:<64 lowercase hex digits>\r\n
Only the final fixed-length footer is removed. No CSV parsing, whitespace
stripping or newline conversion occurs before verification.
"""

import base64
import binascii
import hashlib
import hmac
import os
from pathlib import Path
import re


DOMAIN = b"notesapp:grades-export:v1\x00"
FOOTER_PREFIX = b"# HMAC: sha256:"
FOOTER_BYTES = len(FOOTER_PREFIX) + 64 + 2
MAX_EXPORT_BYTES = 5 * 1024 * 1024  # Includes the footer.


class ExportVerificationError(ValueError):
    """Missing, malformed or invalid authentication for an uploaded export."""


class ExportSizeError(ValueError):
    """The signed export exceeds the supported file size."""


class ExportHMAC:
    def __init__(self, key: bytes):
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError("The export HMAC key must contain exactly 32 bytes.")
        self._key = key

    @classmethod
    def from_key_file(cls, path: Path):
        try:
            encoded = path.read_bytes().strip()
        except OSError as error:
            raise RuntimeError(
                "Cannot read the export HMAC key. Run scripts/generate_export_hmac_key.py "
                "and configure EXPORT_HMAC_KEY_FILE."
            ) from error
        try:
            key = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise ValueError("The export HMAC key file must contain valid Base64.") from error
        return cls(key)

    def _tag(self, payload: bytes) -> bytes:
        return hmac.new(self._key, DOMAIN + payload, hashlib.sha256).hexdigest().encode("ascii")

    def sign_csv(self, payload: bytes) -> bytes:
        if not payload or not payload.endswith(b"\r\n"):
            raise ValueError("CSV payload must end with a CRLF record separator.")
        if len(payload) + FOOTER_BYTES > MAX_EXPORT_BYTES:
            raise ExportSizeError("The signed export must not exceed 5 MiB.")
        return payload + FOOTER_PREFIX + self._tag(payload) + b"\r\n"

    def verify_csv(self, signed_file: bytes) -> bytes:
        """Return the unmodified CSV body only after authentication succeeds."""
        if len(signed_file) > MAX_EXPORT_BYTES:
            raise ExportSizeError("The signed export must not exceed 5 MiB.")
        if len(signed_file) <= FOOTER_BYTES:
            raise ExportVerificationError("Missing or malformed HMAC footer.")
        payload, footer = signed_file[:-FOOTER_BYTES], signed_file[-FOOTER_BYTES:]
        if (not payload.endswith(b"\r\n") or not footer.startswith(FOOTER_PREFIX)
                or not footer.endswith(b"\r\n")):
            raise ExportVerificationError("Missing or malformed HMAC footer.")
        supplied_tag = footer[len(FOOTER_PREFIX):-2]
        if re.fullmatch(rb"[0-9a-f]{64}", supplied_tag) is None:
            raise ExportVerificationError("Missing or malformed HMAC footer.")
        if not hmac.compare_digest(self._tag(payload), supplied_tag):
            raise ExportVerificationError("The file was modified or uses a different signing key.")
        return payload


def load_export_hmac() -> ExportHMAC:
    path = Path(os.environ.get("EXPORT_HMAC_KEY_FILE", "/run/secrets/export_hmac_key"))
    return ExportHMAC.from_key_file(path)
