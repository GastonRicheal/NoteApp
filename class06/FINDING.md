# Class 6 — JWT finding from source review

Baseline: [NotesApp before the fix](https://github.com/GastonRicheal/NoteApp/blob/6d1bf8159740c246bd1dbbce2f631f356ad07778/web/app.py#L102-L128). This is a source-review finding; the live exploitation exercise was not performed.

- **Data at risk:** Grades and comments belonging to other students. No other student's record was retrieved.
- **Finding 1:** The original verifier returned claims for an unsigned token without authenticating them.
- **Finding 2:** The original server used a short, hard-coded HS256 signing secret. No secret-cracking experiment was performed.
- **Why it matters:** The verifier let untrusted token metadata govern verification, and the signing key did not provide meaningful resistance to guessing.

The corresponding defensive changes and tests are in the [Class 7 report](../class07/LOGIN_FIX.md).
