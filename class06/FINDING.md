# Class 6 — JWT authentication finding

Source: [Class 6 lab brief](https://kristenpire.github.io/epita-security-labs/class6/forge-a-token/). Reviewed the [pre-fix verifier at `6d1bf81`](https://github.com/GastonRicheal/NoteApp/blob/6d1bf8159740c246bd1dbbce2f631f356ad07778/web/app.py#L102-L128).

- **What was read:** The verifier and signing-key configuration were reviewed. No grade or comment was retrieved from the pre-fix app.
- **Finding 1 — unsigned tokens:** The `none` branch returned claims without verifying their authenticity. This affected the trustworthiness of caller identity and role.
- **Finding 2 — signing key:** The baseline used a short, committed HS256 key. A valid signature is not evidence of a trustworthy issuer when the signing key is public.
- **Why this matters:** Authentication must derive trust from server policy and a protected key. Caller-supplied metadata cannot decide whether verification is required.

**Evidence boundary:** No token-forgery or key-guessing experiment was performed. The course's live observation is not present. The [Class 7 report](../class07/LOGIN_FIX.md) records the repair and the measured behavior of the fixed app.
