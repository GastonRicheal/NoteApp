# Class 6 — JWT authentication finding

Source: [Class 6 lab brief](https://kristenpire.github.io/epita-security-labs/class6/forge-a-token/). Reviewed the [pre-fix verifier at `6d1bf81`](https://github.com/GastonRicheal/NoteApp/blob/6d1bf8159740c246bd1dbbce2f631f356ad07778/web/app.py#L102-L128).

## Hand-in

```text
FORGED-TOKEN FINDING — NotesApp flaw #4 (auth)
  What I read:   bob's grade (12.6) and comment ("Solid work, keep it up."), via /api/notes/3
  Break 1:       a JWT with "alg":"none" and no signature; role set to "teacher"
  Break 2:       cracked the HS256 secret (s3cr3t) from a wordlist; signed a real teacher token
  Why it worked: the server let the TOKEN choose how to verify, AND its secret was guessable
```

**Prediction, recorded before running (with the pair).**

| question | predicted | why |
|---|---|---|
| Will the server accept a token with no signature at all? | **yes** | the header travels inside the token, and it is the header that names the algorithm; if `none` is honoured, "check the seal" becomes "skip the seal", decided by the sender |
| The server now demands a real HS256 signature — can you still forge a teacher token? | **yes** | HS256 is symmetric, so the same secret signs and verifies; a dictionary word can be guessed, and because the token is not secret the guess can be tested offline against a token we already hold |

Both predictions held. The measurements are in [ATTACK.md](ATTACK.md).

- **What was read:** The verifier and signing-key configuration were reviewed.
- **Finding 1 — unsigned tokens:** The `none` branch returned claims without verifying their authenticity. This affected the trustworthiness of caller identity and role.
- **Finding 2 — signing key:** The baseline used a short, committed HS256 key. A valid signature is not evidence of a trustworthy issuer when the signing key is public.
- **Why this matters:** Authentication must derive trust from server policy and a protected key. Caller-supplied metadata cannot decide whether verification is required.

## Live observation

Both findings were then reproduced over HTTP against the pre-fix revision
(`6d1bf81`) in an isolated stack. An unsigned token claiming `role=teacher` was
accepted and returned another student's grade; the committed key was recovered
from a bearer token with a 46-entry wordlist in 0.18 ms, and a token signed with
it was accepted as well. The repaired build refuses both with **401**.

Method, exact requests, scope and the reproduction commands are in
[ATTACK.md](ATTACK.md); raw output is in
[evidence/attack-baseline.txt](evidence/attack-baseline.txt) and
[evidence/attack-after-fix.txt](evidence/attack-after-fix.txt). The [Class 7
report](../class07/LOGIN_FIX.md) records the repair, and the [Class 8
report](../class08/ACCESS_FIX.md) records the missing ownership check that made
the same grade reachable even without a forgery.

