"""Verify stored ciphertext and compare plaintext digests without printing comments or keys."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

import psycopg2
import psycopg2.extras

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "web"))
from comment_crypto import CommentCipher, PREFIX


def main():
    parser = argparse.ArgumentParser(description="Verify NotesApp comment storage")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--capture", type=Path, help="Capture the digest before migration")
    mode.add_argument("--expected", type=Path, help="Compare with a previously captured digest")
    args = parser.parse_args()
    key_path = Path(os.environ.get("COMMENT_ENCRYPTION_KEY_FILE",
                                   PROJECT_ROOT / ".secrets" / "comment_key.b64"))
    cipher = CommentCipher.from_key_file(key_path)
    conn = psycopg2.connect(
        host=os.environ.get("DB_HOST", "localhost"),
        dbname=os.environ.get("DB_NAME", "notesapp"),
        user=os.environ.get("DB_USER", "notesapp"),
        password=os.environ.get("POSTGRES_PASSWORD", "notesapp_pg_pw_2024"),
        cursor_factory=psycopg2.extras.RealDictCursor,
    )
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, student_id, class_id, grade, comment FROM notes ORDER BY id")
            rows = cur.fetchall()
    finally:
        conn.close()
    encrypted = plaintext = nulls = 0
    for row in rows:
        value = row["comment"]
        if value is None:
            nulls += 1
        elif value.startswith(PREFIX):
            row["comment"] = cipher.decrypt(value, row["id"])
            encrypted += 1
        else:
            plaintext += 1
    digest = hashlib.sha256(json.dumps(
        rows, ensure_ascii=False, sort_keys=True, default=str,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    result = {"notes": len(rows), "encrypted_comments": encrypted,
              "plaintext_comments": plaintext, "null_comments": nulls,
              "plaintext_data_sha256": digest}
    if args.capture:
        args.capture.parent.mkdir(parents=True, exist_ok=True)
        args.capture.write_text(json.dumps(result, indent=2), encoding="utf-8")
    else:
        if plaintext:
            parser.exit(1, f"Verification failed: {plaintext} comments are still plaintext.\n")
        if args.expected:
            before = json.loads(args.expected.read_text(encoding="utf-8"))
            if before["plaintext_data_sha256"] != digest:
                parser.exit(1, "Verification failed: recovered notes differ from the snapshot.\n")
            result["matches_before_migration"] = True
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
