# Class 8 — Grade access fix

Source: [Class 8 lab brief](https://kristenpire.github.io/epita-security-labs/class8/read-anyones-grade/).

**Before the fix — source review:** The [old note handler](https://github.com/GastonRicheal/NoteApp/blob/6d1bf8159740c246bd1dbbce2f631f356ad07778/web/app.py#L246-L268) authenticated the caller and looked up the note by ID. It did not compare ownership. No cross-account grade or comment was retrieved from the unfixed app, so the before-fix live observation is not present.

**Fix:** The [note handler](../web/app.py) restricts the lookup to the student's own record unless the authenticated caller has a teacher or admin role. Authorization happens before comment decryption. **404 Not Found** was chosen so that a denied note and a missing note give the same response.

## Observed results on the fixed app

The [recorded test output](../class07/evidence/regression-results.txt) comes from [integration tests](../web/tests/test_app_auth.py) with synthetic notes in disposable PostgreSQL schemas:

- **Student, another owner's fixture:** **404** with both browser session and bearer authentication. No decryption was attempted.
- **Student, missing fixture:** **404** with the same response as the denied request.
- **Student, own fixture:** **200**, with the expected owner and comment verified in the test.
- **Teacher and administrator:** **200** for a student fixture under the lab's role policy.
- **Unauthenticated or unknown role:** **401**.

Use the [Class 7 run command](../class07/LOGIN_FIX.md#run-the-checks) to repeat these checks. Fixture note IDs are isolated from the classroom seed database. These results cover the single-note API, not the access policies of other routes.
