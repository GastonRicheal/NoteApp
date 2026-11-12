# Class 8 — Grade access fix

Source: [Class 8 lab brief](https://kristenpire.github.io/epita-security-labs/class8/read-anyones-grade/).

**Before the fix — live observation:** A logged-in student read another student's row. Against the pre-fix revision (`6d1bf81`) `GET /api/notes/3` with alice's own token returned **200** and bob's grade and comment; no forgery was needed, because the [old note handler](https://github.com/GastonRicheal/NoteApp/blob/6d1bf8159740c246bd1dbbce2f631f356ad07778/web/app.py#L246-L268) authenticated the caller and never compared the owner. The [Class 6 attack replay](../class06/ATTACK.md) records the same request, and the [permission matrix](evidence/access-baseline.txt) records it by role.

**Fix:** The [note handler](../web/app.py) restricts the lookup to the student's own record unless the authenticated caller has a teacher or admin role. Authorization happens before comment decryption. **404 Not Found** was chosen so that a denied note and a missing note give the same response.

## Hand-in

```text
IDOR FIX — NotesApp flaw #7 (broken access control) closed
  Proof you got in:   as alice, /api/notes/3 returned bob's grade: 12.6 — "Solid work, keep it up."
  Fix:                api_notes refuses a note whose student_id is not the caller's,
                      unless the caller is a teacher/admin
  Code chosen:        returns  [x] 404 not found   [ ] 403 forbidden
  Proof it's closed:  as alice, /api/notes/3   -> 404 not found
                      as alice, /api/notes/1   -> 200, her own note
                      as prof.turing, /api/notes/3 -> 200, works
```

Both columns are measured, not asserted: the leak is
[access-baseline.txt](evidence/access-baseline.txt) and the closure is
[access-after-fix.txt](evidence/access-after-fix.txt).

**Prediction, recorded before Part 1 (with the pair).**

| question | predicted | why |
|---|---|---|
| What happens if alice asks for `/api/notes/3`, a note that is not hers? | **someone else's grade comes back** | the handler only asks "are you logged in?"; the note id in the URL names the object directly, so authentication alone decides the outcome |

## Observed results on the fixed app

The [permission matrix](evidence/access-after-fix.txt) replays the three roles
against the repaired stack over HTTP, and the [recorded regression output](../class07/evidence/regression-results.txt)
comes from [integration tests](../web/tests/test_app_auth.py) with synthetic
notes in disposable PostgreSQL schemas. Both agree:

- **Student, another owner's row:** **404** with both browser session and bearer authentication. No decryption is attempted.
- **Student, missing row:** **404**, the same response as the denied request — a caller cannot tell a hidden row from an absent one.
- **Student, own row:** **200**, with the expected owner and a decrypted comment.
- **Teacher and administrator:** **200** for a student's row under the lab's role policy.
- **Unauthenticated or unknown role:** **401**.

Use the [replay harness](../class06/replay/README.md) to repeat these checks:
`python class08/replay/permissions.py --base <url> --expect fixed`, or
`--expect vulnerable` against the pre-fix stack. The rows are the classroom seed
data — note 1 belongs to alice (user 6) and note 3 to bob (user 7) — so the
denied read is another student's grade, not a synthetic fixture. These results
cover the single-note API, not the access policies of other routes.
