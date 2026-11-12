"""Verify the repaired authentication and grade access on disposable fixtures."""

import json
import os
import secrets
from unittest.mock import patch

from test_app_comments import PostgresAppTestCase


class AuthenticationAndOwnershipTests(PostgresAppTestCase):
    def login(self, username, password):
        client = self.notesapp.app.test_client()
        response = client.post("/login", data={"username": username, "password": password})
        self.assertEqual(response.status_code, 302)
        with client.session_transaction() as session:
            return client, session["token"]

    def bearer(self, token):
        return {"Authorization": f"Bearer {token}"}

    def test_unsigned_and_unsupported_headers_rejected(self):
        client = self.notesapp.app.test_client()
        for algorithm in ("none", "HS384", "hs256"):
            with self.subTest(algorithm=algorithm):
                header = self.notesapp._b64url(json.dumps({"alg": algorithm}).encode())
                # Empty claims: check rejection without creating a usable identity.
                token = f"{header}.e30."
                self.assertIsNone(self.notesapp.verify_jwt(token))
                response = client.get("/api/notes/1", headers=self.bearer(token))
                self.assertEqual((response.status_code, response.get_json()),
                                 (401, {"error": "unauthorized"}))

    def test_pre_rotation_legitimate_token_no_longer_accepted(self):
        _, token = self.login("alice", "alicepw")
        client = self.notesapp.app.test_client()
        self.assertEqual(client.get("/api/notes/1", headers=self.bearer(token)).status_code, 200)
        with patch.object(self.notesapp, "JWT_KEY", secrets.token_bytes(32)):
            response = client.get("/api/notes/1", headers=self.bearer(token))
            self.assertEqual((response.status_code, response.get_json()),
                             (401, {"error": "unauthorized"}))

    def test_malformed_bearer_does_not_fall_back_to_cookie(self):
        client, _ = self.login("alice", "alicepw")
        self.assertEqual(client.get("/api/notes/1").status_code, 200)
        self.assertEqual(client.get("/api/notes/1", headers=self.bearer("invalid")).status_code, 401)

    def test_missing_and_short_signing_keys_fail_closed(self):
        for env in ({}, {"JWT_SECRET": "c2hvcnQ="}):
            with self.subTest(env_provided=bool(env)), patch.dict(os.environ, env, clear=True):
                with self.assertRaises(RuntimeError):
                    self.notesapp.load_jwt_key()

    def test_normal_student_login_can_read_own_note_with_bearer(self):
        _, token = self.login("alice", "alicepw")
        client = self.notesapp.app.test_client()
        response = client.get("/api/notes/1", headers=self.bearer(token))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["student"], "alice")
        self.assertEqual(response.get_json()["comment"], "Alice original")

    def test_student_denied_foreign_note_before_decryption(self):
        client, token = self.login("alice", "alicepw")
        bearer_client = self.notesapp.app.test_client()
        with patch.object(self.notesapp, "decrypt_note_comment") as decrypt:
            for response in (client.get("/api/notes/2"),
                             bearer_client.get("/api/notes/2", headers=self.bearer(token))):
                self.assertEqual(response.status_code, 404)
                self.assertEqual(response.get_json(), {"error": "not found"})
            decrypt.assert_not_called()
        missing = client.get("/api/notes/999999")
        self.assertEqual((missing.status_code, missing.get_json()), (404, {"error": "not found"}))

    def test_teacher_login_can_read_student_note(self):
        _, token = self.login("prof.turing", "teach123")
        client = self.notesapp.app.test_client()
        response = client.get("/api/notes/2", headers=self.bearer(token))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["student"], "bob")

    def test_admin_can_read_student_note(self):
        self.login_as("admin", 1, "admin")
        self.assertEqual(self.client.get("/api/notes/2").status_code, 200)

    def test_anonymous_or_unknown_role_is_unauthorized(self):
        self.assertEqual(self.notesapp.app.test_client().get("/api/notes/1").status_code, 401)
        self.login_as("unknown", 6, "alice")
        self.assertEqual(self.client.get("/api/notes/1").status_code, 401)
