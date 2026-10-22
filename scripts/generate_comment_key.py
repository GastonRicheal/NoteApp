"""Create a persistent local AES-256 key without printing or overwriting it."""

import argparse
import base64
import os
from pathlib import Path
import secrets


def generate_key(path: Path) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        try:
            key = base64.b64decode(path.read_bytes().strip(), validate=True)
        except (ValueError, OSError) as error:
            raise ValueError("The existing key file is unreadable or invalid; it was not replaced.") from error
        if len(key) != 32:
            raise ValueError("The existing key is not 32 bytes; it was not replaced.")
        return False
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(base64.b64encode(secrets.token_bytes(32)) + b"\n")
    return True


def main():
    parser = argparse.ArgumentParser(description="Generate the NotesApp comment encryption key")
    parser.add_argument("--path", type=Path,
                        default=Path(__file__).resolve().parent.parent / ".secrets" / "comment_key.b64")
    args = parser.parse_args()
    try:
        created = generate_key(args.path)
    except (ValueError, OSError) as error:
        parser.exit(1, f"Key setup failed: {error}\n")
    print("Created the AES-256 key file." if created else "Existing valid key kept unchanged.")
    print(f"Key file: {args.path.resolve()}")


if __name__ == "__main__":
    main()
