"""Encrypt existing plaintext comments atomically before the app serves requests."""

import argparse
from contextlib import closing

from comment_crypto import PREFIX, CommentCipher, CommentDecryptionError


def migrate_comments(conn, cipher: CommentCipher, dry_run: bool = False) -> dict:
    previous_autocommit = conn.autocommit
    conn.autocommit = False
    migrated = verified = null_comments = 0
    try:
        with conn:
            with conn.cursor() as cur:
                # Serialize simultaneous migrations and block writes until the transaction ends.
                cur.execute("LOCK TABLE notes IN SHARE ROW EXCLUSIVE MODE")
                cur.execute("SELECT id, comment FROM notes ORDER BY id")
                for note in cur.fetchall():
                    value = note["comment"]
                    if value is None:
                        null_comments += 1
                    elif value.startswith(PREFIX):
                        try:
                            cipher.decrypt(value, note["id"])
                        except CommentDecryptionError as error:
                            raise CommentDecryptionError(
                                f"Migration stopped: encrypted comment at note {note['id']} "
                                "cannot be authenticated. No comments were changed."
                            ) from error
                        verified += 1
                    else:
                        if not dry_run:
                            cur.execute("UPDATE notes SET comment = %s WHERE id = %s",
                                        (cipher.encrypt(value, note["id"]), note["id"]))
                        migrated += 1
    finally:
        conn.autocommit = previous_autocommit
    return {"plaintext_comments": migrated, "verified_encrypted_comments": verified,
            "null_comments": null_comments, "dry_run": dry_run}


def main():
    # Import only for the command-line runner; the migration function is independently testable.
    from app import comment_cipher, get_db

    parser = argparse.ArgumentParser(description="Encrypt existing NotesApp comments")
    parser.add_argument("--dry-run", action="store_true", help="Check and count without changing data")
    args = parser.parse_args()
    try:
        with closing(get_db()) as conn:
            result = migrate_comments(conn, comment_cipher, args.dry_run)
    except CommentDecryptionError as error:
        parser.exit(1, f"{error}\n")
    action = "Would encrypt" if args.dry_run else "Encrypted"
    print(f"{action} {result['plaintext_comments']} plaintext comments; "
          f"verified {result['verified_encrypted_comments']} encrypted comments; "
          f"preserved {result['null_comments']} NULL comments.")


if __name__ == "__main__":
    main()
