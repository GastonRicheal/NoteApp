# Class 8 — Grade access fix

**Before the fix, by source review:** The old handler filtered by note ID alone after authentication. It did not require the note's owner to match the caller. No cross-account grade or comment was retrieved from the unfixed app.

**Fix:** The [note handler](../web/app.py) restricts the database lookup to the current student's own record unless the authenticated caller has a teacher or admin role. The check precedes comment decryption. A missing record and a record the student is not allowed to read both return HTTP 404 with the same response, so this endpoint does not reveal whether the denied note exists.

**Post-fix verification:** The [regression tests](../web/tests/test_app_auth.py) use synthetic notes in a disposable database schema. A student requesting another student's fixture note receives **404** via either session or bearer authentication, and no decryption is attempted. An authenticated student reading her own fixture note receives **200**. A teacher can still read a student's fixture note, and admin access is preserved. Anonymous requests receive **401**.
