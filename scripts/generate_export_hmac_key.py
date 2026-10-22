"""Create a persistent export-only HMAC key without replacing existing keys."""

import argparse
from pathlib import Path

from generate_comment_key import generate_key


def main():
    parser = argparse.ArgumentParser(description="Generate the NotesApp export HMAC key")
    parser.add_argument("--path", type=Path,
                        default=Path(__file__).resolve().parent.parent / ".secrets" / "export_hmac_key.b64")
    args = parser.parse_args()
    try:
        created = generate_key(args.path)
    except (ValueError, OSError) as error:
        parser.exit(1, f"HMAC key setup failed: {error}\n")
    print("Created a separate export HMAC key." if created else "Existing valid HMAC key kept unchanged.")
    print(f"Key file: {args.path.resolve()}")


if __name__ == "__main__":
    main()
