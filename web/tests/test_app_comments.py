"""PostgreSQL integration checks in an isolated, disposable schema.

Enable explicitly with NOTESAPP_TEST_DB=1. No tests modify the real public tables.
"""

import base64
from contextlib import closing
import os
import unittest
from unittest.mock import patch
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from comment_crypto import CommentCipher, CommentDecryptionError, PREFIX
from migrate_comments import migrate_comments


@unittest.skipUnless(os.environ.get("NOTESAPP_TEST_DB") == "1",
                     "Set NOTESAPP_TEST_DB=1 to run isolated PostgreSQL integration checks")
class PostgresAppTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as notesapp
        from psycopg2 import sql
        cls.notesapp = notesapp
        cls.sql = sql
        cls.original_get_db = staticmethod(notesapp.get_db)

    def connect_isolated(self):
        conn = self.original_get_db()
        with conn.cursor() as cur:
            cur.execute(self.sql.SQL("SET search_path TO {}").format(self.sql.Identifier(self.schema)))
        return conn

    def tear_down_schema(self):
        if not self.schema.startswith("test_comment_crypto_"):
            raise RuntimeError("Refusing to drop a non-test schema.")
        with closing(self.original_get_db()) as conn, conn.cursor() as cur:
            cur.execute(self.sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                self.sql.Identifier(self.schema)))

    def setUp(self):
        self.schema = "test_comment_crypto_" + uuid.uuid4().hex[:12]
        self.cipher = CommentCipher(AESGCM.generate_key(bit_length=256))
        with closing(self.original_get_db()) as conn, conn.cursor() as cur:
            cur.execute(self.sql.SQL("CREATE SCHEMA {}").format(self.sql.Identifier(self.schema)))
        self.addCleanup(self.tear_down_schema)
        with closing(self.connect_isolated()) as conn, conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT,
                                    role TEXT, teacher_id INTEGER);
                CREATE TABLE classes (id INTEGER PRIMARY KEY, name TEXT, teacher_id INTEGER);
                CREATE TABLE notes (id SERIAL PRIMARY KEY, student_id INTEGER, class_id INTEGER,
                                    grade NUMERIC(4,1), comment TEXT);
                INSERT INTO users VALUES (2, 'prof.turing', 'teach123', 'teacher', NULL),
                                         (6, 'alice', 'alicepw', 'student', NULL),
                                         (7, 'bob', 'bobpw', 'student', NULL);
                INSERT INTO classes VALUES (1, 'Mathematics', 2);
            """)
            cur.execute("INSERT INTO notes VALUES (1, 6, 1, 14, %s), (2, 7, 1, 8, %s)",
                        (self.cipher.encrypt("Alice original", 1),
                         self.cipher.encrypt("Bob original", 2)))
            cur.execute("SELECT setval(pg_get_serial_sequence('notes', 'id'), 2, true)")
        for patcher in (
            patch.object(self.notesapp, "get_db", self.connect_isolated),
            patch.object(self.notesapp, "comment_cipher", self.cipher),
            patch.object(self.notesapp, "log", lambda message: None),
            patch.dict(self.notesapp.app.config, {"TESTING": True}),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = self.notesapp.app.test_client()
        self.login_as("teacher", 2, "prof.turing")

    def login_as(self, role, user_id, username):
        with self.client.session_transaction() as session:
            session.clear()
            session.update(role=role, user_id=user_id, username=username)

    def csrf(self):
        """Return this client's CSRF token, creating one as a real page would."""
        with self.client.session_transaction() as session:
            token = session.get("csrf")
            if token is None:
                token = uuid.uuid4().hex
                session["csrf"] = token
            return token

    def stored_rows(self):
        with closing(self.connect_isolated()) as conn, conn.cursor() as cur:
            cur.execute("SELECT id, grade, comment FROM notes ORDER BY id")
            return cur.fetchall()

    def set_comment(self, note_id, value):
        with closing(self.connect_isolated()) as conn, conn.cursor() as cur:
            cur.execute("UPDATE notes SET comment = %s WHERE id = %s", (value, note_id))


class AppCommentTests(PostgresAppTestCase):
    def test_create_encrypts_storage_and_all_read_paths_decrypt(self):
        comment = "课后作业评语：Très bien!"
        response = self.client.post("/grades", data={
            "student_id": "6", "class_id": "1", "grade": "15.5", "comment": comment,
            "csrf_token": self.csrf(),
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(comment.encode("utf-8"), response.data)
        stored = self.stored_rows()[-1]
        self.assertTrue(stored["comment"].startswith(PREFIX))
        self.assertNotIn(comment, stored["comment"])
        self.assertEqual(self.cipher.decrypt(stored["comment"], stored["id"]), comment)
        response = self.client.get(f"/api/notes/{stored['id']}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["comment"], comment)
        for path in ("/export.csv", "/export.csv?class_id=1"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertIn(comment.encode("utf-8"), response.data)
        self.login_as("student", 6, "alice")
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertIn(comment.encode("utf-8"), response.data)

    def test_updates_use_new_nonce_and_preserve_readable_text(self):
        values = []
        for _ in range(2):
            response = self.client.post("/grades", data={
                "note_id": "1", "grade": "16", "comment": "Updated comment",
                "csrf_token": self.csrf(),
            })
            self.assertEqual(response.status_code, 302)
            value = self.stored_rows()[0]["comment"]
            self.assertEqual(self.cipher.decrypt(value, 1), "Updated comment")
            values.append(value)
        self.assertNotEqual(values[0], values[1])

    def test_failed_encryption_rolls_back_new_note(self):
        before = self.stored_rows()
        with patch.object(self.cipher, "encrypt", side_effect=RuntimeError("Simulated encryption failure")):
            with self.assertRaises(RuntimeError):
                self.client.post("/grades", data={
                    "student_id": "6", "class_id": "1", "grade": "15", "comment": "new",
                    "csrf_token": self.csrf(),
                })
        self.assertEqual(self.stored_rows(), before)

    def test_tampered_comment_is_rejected_by_all_read_paths(self):
        value = self.stored_rows()[0]["comment"]
        payload = bytearray(base64.b64decode(value[len(PREFIX):]))
        payload[-1] ^= 1
        altered = PREFIX + base64.b64encode(payload).decode("ascii")
        self.set_comment(1, altered)
        for path in ("/api/notes/1", "/teacher", "/export.csv"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 500)
            self.assertNotIn(altered.encode("ascii"), response.data)
        self.login_as("student", 6, "alice")
        self.assertEqual(self.client.get("/dashboard").status_code, 500)

    def test_plaintext_migration_is_idempotent(self):
        self.set_comment(1, "旧评语")
        self.set_comment(2, "")
        with closing(self.connect_isolated()) as conn:
            result = migrate_comments(conn, self.cipher)
        self.assertEqual(result["plaintext_comments"], 2)
        rows = self.stored_rows()
        self.assertEqual(self.cipher.decrypt(rows[0]["comment"], 1), "旧评语")
        self.assertEqual(self.cipher.decrypt(rows[1]["comment"], 2), "")
        with closing(self.connect_isolated()) as conn:
            result = migrate_comments(conn, self.cipher)
        self.assertEqual(result["plaintext_comments"], 0)
        self.assertEqual(result["verified_encrypted_comments"], 2)
        self.assertEqual(self.stored_rows(), rows)

    def test_migration_dry_run_preserves_plaintext(self):
        self.set_comment(1, "old plaintext")
        before = self.stored_rows()
        with closing(self.connect_isolated()) as conn:
            result = migrate_comments(conn, self.cipher, dry_run=True)
        self.assertEqual(result["plaintext_comments"], 1)
        self.assertEqual(self.stored_rows(), before)

    def test_corrupt_ciphertext_rolls_back_entire_migration(self):
        self.set_comment(1, "first plaintext comment")
        self.set_comment(2, PREFIX + "invalid!")
        before = self.stored_rows()
        with closing(self.connect_isolated()) as conn, self.assertRaises(CommentDecryptionError):
            migrate_comments(conn, self.cipher)
        self.assertEqual(self.stored_rows(), before)

    def test_wrong_key_migration_cannot_modify_existing_comments(self):
        before = self.stored_rows()
        wrong_cipher = CommentCipher(AESGCM.generate_key(bit_length=256))
        with closing(self.connect_isolated()) as conn, self.assertRaises(CommentDecryptionError):
            migrate_comments(conn, wrong_cipher)
        self.assertEqual(self.stored_rows(), before)

    def test_null_comment_survives_migration_and_api_read(self):
        self.set_comment(1, None)
        with closing(self.connect_isolated()) as conn:
            result = migrate_comments(conn, self.cipher)
        self.assertEqual(result["null_comments"], 1)
        self.assertIsNone(self.client.get("/api/notes/1").get_json()["comment"])


if __name__ == "__main__":
    unittest.main()
