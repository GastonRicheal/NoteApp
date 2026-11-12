"""Provision a random JWT signing key without printing or replacing it."""

from pathlib import Path

from generate_comment_key import generate_key


if __name__ == "__main__":
    path = Path(__file__).resolve().parent.parent / ".secrets" / "jwt_key.b64"
    try:
        created = generate_key(path)
    except (ValueError, OSError) as error:
        raise SystemExit(f"JWT key setup failed: {error}") from None
    print("Created the JWT signing key." if created else "Existing JWT signing key kept unchanged.")
