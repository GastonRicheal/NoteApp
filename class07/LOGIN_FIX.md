# Class 7 — Login fix

**Fix 1.** The server accepts only `HS256`. It verifies the signature before trusting identity claims, rejects unsigned or malformed input, and does not fall back to a browser cookie when a supplied bearer token is invalid.

**Fix 2.** A locally generated 256-bit random signing key replaces the course default. Compose mounts it as a secret and passes its path in `JWT_SECRET_FILE`; a non-Compose deployment may provide a Base64 `JWT_SECRET`. Missing or short keys prevent startup. The real key is excluded from Git. In production it belongs in a managed secret store. The separate Flask cookie signing key is derived from the provisioned key so a publicly known cookie key cannot undermine the API's identity check.

**Verification.** [Regression tests](../web/tests/test_app_auth.py) use disposable database fixtures and no privilege-escalation payloads:

- Unsigned and unsupported token formats with empty claims are rejected.
- A legitimately issued student token returns HTTP 401 after a simulated signing key rotation.
- A normal student login issues a signed token, and the authenticated student can read her own fixture note (HTTP 200).

The key-rotation test does not replay a forged token. Browser sessions from before the update need a fresh sign-in.
