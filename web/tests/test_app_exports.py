"""HMAC export/upload integration checks using disposable PostgreSQL schemas."""

import csv
import io
from unittest.mock import patch

from export_integrity import ExportHMAC, ExportVerificationError
from test_app_comments import PostgresAppTestCase


class AppExportTests(PostgresAppTestCase):
    def setUp(self):
        super().setUp()
        self.signer = ExportHMAC(bytes(range(32)))  # Test-only key.
        patcher = patch.object(self.notesapp, "export_hmac", self.signer)
        patcher.start()
        self.addCleanup(patcher.stop)

    def upload(self, value, filename="grades_export.csv"):
        return self.client.post("/verify-export", data={"file": (io.BytesIO(value), filename)},
                                content_type="multipart/form-data")

    def test_export_body_contains_decrypted_comments_and_a_valid_final_hmac(self):
        before = self.stored_rows()
        for path in ("/export.csv", "/export.csv?class_id=1"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertIn("grades_export.csv", response.headers["Content-Disposition"])
            self.assertEqual(response.headers["Cache-Control"], "no-store")
            payload = self.signer.verify_csv(response.data)
            rows = list(csv.reader(io.StringIO(payload.decode("utf-8"), newline="")))
            self.assertEqual(rows[0], ["student", "class", "grade", "comment"])
            self.assertEqual(len(rows), 3)
            self.assertEqual(rows[1][-1], "Alice original")
            self.assertNotIn("aesgcm:v1:", payload.decode("utf-8"))
        self.assertEqual(self.stored_rows(), before)

    def test_empty_class_export_is_also_authenticated(self):
        response = self.client.get("/export.csv?class_id=999999")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.signer.verify_csv(response.data), b"student,class,grade,comment\r\n")

    def test_original_upload_passes_and_changed_grade_fails_without_database_writes(self):
        before = self.stored_rows()
        downloaded = self.client.get("/export.csv").data
        original = self.upload(downloaded)
        self.assertEqual(original.status_code, 200)
        self.assertIn(b"CHECK PASSED", original.data)
        altered = downloaded.replace(b",14.0,", b",18.0,", 1)
        self.assertNotEqual(downloaded, altered)
        changed = self.upload(altered)
        self.assertEqual(changed.status_code, 400)
        self.assertIn(b"CHECK FAILED", changed.data)
        self.assertEqual(self.stored_rows(), before)

    def test_missing_or_damaged_authentication_and_wrong_key_fail_on_upload(self):
        downloaded = self.client.get("/export.csv").data
        payload = self.signer.verify_csv(downloaded)
        for value in (payload, downloaded[:-1], ExportHMAC(b"w"*32).sign_csv(payload)):
            with self.subTest(value=value):
                response = self.upload(value)
                self.assertEqual(response.status_code, 400)
                self.assertIn(b"CHECK FAILED", response.data)

    def test_file_name_is_not_trusted_and_payload_is_not_rendered(self):
        payload = b"student,class,grade,comment\r\nalice,Math,14,<script>fail()</script>\r\n"
        response = self.upload(self.signer.sign_csv(payload), "<img onerror=fail()>.csv")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"<script>fail()", response.data)
        self.assertNotIn(b"<img onerror", response.data)

    def test_verification_page_and_missing_file_errors(self):
        page = self.client.get("/verify-export")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'multipart/form-data', page.data)
        self.assertNotIn(b"CHECK PASSED", page.data)
        self.assertNotIn(b"CHECK FAILED", page.data)
        self.assertEqual(self.client.post("/verify-export", data={}).status_code, 400)
        self.assertEqual(self.upload(b"", "").status_code, 400)

    def test_export_and_verification_require_a_teacher_session(self):
        for identity in (("student", 6, "alice"), ("admin", 1, "admin"), None):
            if identity:
                self.login_as(*identity)
            else:
                with self.client.session_transaction() as session:
                    session.clear()
            for path in ("/export.csv", "/verify-export"):
                self.assertEqual(self.client.get(path).status_code, 302)
            self.assertEqual(self.upload(self.signer.sign_csv(b"header\r\n")).status_code, 302)

    def test_size_limits_apply_to_signing_upload_and_multipart_envelope(self):
        downloaded = self.client.get("/export.csv").data
        with patch("export_integrity.MAX_EXPORT_BYTES", 32), patch.object(self.notesapp, "MAX_EXPORT_BYTES", 32):
            self.assertEqual(self.client.get("/export.csv").status_code, 413)
            self.assertEqual(self.upload(downloaded).status_code, 413)
            response = self.client.post("/verify-export", data=b"x"*(64*1024+33),
                                        content_type="application/octet-stream")
            self.assertEqual(response.status_code, 413)

    def test_ciphertext_tampering_is_rejected_before_any_export_can_be_signed(self):
        self.set_comment(1, "aesgcm:v1:invalid!")
        response = self.client.get("/export.csv")
        self.assertEqual(response.status_code, 500)
        self.assertNotIn(b"# HMAC:", response.data)
        with self.assertRaises(ExportVerificationError):
            self.signer.verify_csv(response.data)
