"""Verify a downloaded export locally without Flask, Docker or CSV rewriting."""

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "web"))
from export_integrity import ExportHMAC, ExportSizeError, ExportVerificationError, MAX_EXPORT_BYTES


def main():
    parser = argparse.ArgumentParser(description="Verify a NotesApp HMAC-protected grades export")
    parser.add_argument("file", type=Path)
    parser.add_argument("--key-file", type=Path, default=ROOT / ".secrets" / "export_hmac_key.b64")
    args = parser.parse_args()
    try:
        signer = ExportHMAC.from_key_file(args.key_file)
        with args.file.open("rb") as handle:
            signed_file = handle.read(MAX_EXPORT_BYTES + 1)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(2, f"Cannot verify export: {error}\n")
    try:
        signer.verify_csv(signed_file)
    except (ExportVerificationError, ExportSizeError) as error:
        parser.exit(1, f"CHECK FAILED: {error}\n")
    print("CHECK PASSED: the file matches this server's HMAC key.")


if __name__ == "__main__":
    main()
