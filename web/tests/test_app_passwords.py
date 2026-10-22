"""Password migration checks against disposable PostgreSQL tables only."""
from contextlib import closing

from test_app_comments import PostgresAppTestCase


class PasswordMigrationTests(PostgresAppTestCase):
    def setUp(self):
        super().setUp()
        self.client.get("/logout")

    def stored_password(self):
        with closing(self.connect_isolated()) as conn, conn.cursor() as cur:
            cur.execute("SELECT password FROM users WHERE username = 'alice'")
            return cur.fetchone()["password"]

    def set_password(self, value):
        with closing(self.connect_isolated()) as conn, conn.cursor() as cur:
            cur.execute("UPDATE users SET password = %s WHERE username = 'alice'", (value,))

    def assert_not_logged_in(self):
        with self.client.session_transaction() as session:
            self.assertNotIn("user_id", session)

    def test_legacy_login_migrates_and_hash_login_still_works(self):
        response = self.client.post("/login", data={"username": "alice", "password": "alicepw"})
        self.assertEqual(response.status_code, 302)
        stored = self.stored_password()
        self.assertTrue(stored.startswith("$argon2id$"))
        self.assertTrue(self.notesapp.ph.verify(stored, "alicepw"))
        self.client.get("/logout")
        response = self.client.post("/login", data={"username": "alice", "password": "alicepw"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.stored_password(), stored)
        with self.client.session_transaction() as session:
            self.assertEqual(session["user_id"], 6)

    def test_wrong_legacy_password_does_not_migrate_or_authenticate(self):
        response = self.client.post("/login", data={"username": "alice", "password": "wrong"})
        self.assertIn(b"Invalid credentials", response.data)
        self.assertEqual(self.stored_password(), "alicepw")
        self.assert_not_logged_in()

    def test_wrong_password_for_migrated_account_is_rejected(self):
        stored = self.notesapp.ph.hash("alicepw")
        self.set_password(stored)
        response = self.client.post("/login", data={"username": "alice", "password": "wrong"})
        self.assertIn(b"Invalid credentials", response.data)
        self.assertEqual(self.stored_password(), stored)
        self.assert_not_logged_in()

    def test_invalid_hash_does_not_authenticate(self):
        self.set_password("$argon2broken")
        response = self.client.post("/login", data={"username": "alice", "password": "alicepw"})
        self.assertIn(b"Invalid credentials", response.data)
        self.assert_not_logged_in()

    def test_unknown_user_does_not_authenticate(self):
        response = self.client.post("/login", data={"username": "unknown-course-user", "password": "alicepw"})
        self.assertIn(b"Invalid credentials", response.data)
        self.assert_not_logged_in()
