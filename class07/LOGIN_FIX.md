# Class 7 — Login fix

Source: [Class 7 lab brief](https://kristenpire.github.io/epita-security-labs/class7/fix-the-login/).

**Fix 1.** The server accepts only `HS256`. It verifies the signature before trusting identity claims, rejects unsigned or malformed input, and does not fall back to a browser cookie when a supplied bearer token is invalid.

**Fix 2.** A locally generated 256-bit random signing key replaces the course default. Compose mounts it as a secret and passes its path in `JWT_SECRET_FILE`; a non-Compose deployment may provide a Base64 `JWT_SECRET`. Missing or short keys prevent startup. The real key is excluded from Git. In production it belongs in a managed secret store. The separate Flask cookie signing key is derived from the provisioned key so a publicly known cookie key cannot undermine the API's identity check.

## Hand-in

```text
LOGIN FIX — NotesApp flaw #4 (auth) closed
  Fix 1:  verify_jwt rejects alg:none and pins algorithm to HS256
  Fix 2:  JWT_SECRET is long + random, read from the environment (no s3cr3t, no default)
  Proof:  alg:none token        -> 401 unauthorized
          s3cr3t-signed token   -> 401 unauthorized
          real alice login      -> 200, her own note returned
```

Both forged tokens are the artifacts kept from Class 6; the replay is
[here](../class06/evidence/attack-after-fix.txt).

**Prediction, recorded before the fixes (with the pair).**

| question | predicted | why |
|---|---|---|
| After all three fixes, will the old forged tokens still work? | **no** | rule 1 refuses the unsigned token before any signature is looked for, and the new key means the old signed token no longer matches |
| Will a normal login still work? | **yes** | nothing about the caller's credentials changed; only how a token is verified |

## Observed results

The [regression tests](../web/tests/test_app_auth.py) ran against the repaired app using disposable PostgreSQL schemas. The [recorded test output](evidence/regression-results.txt) covers the following assertions:

- **Unsigned or unsupported format, empty claims:** the verifier rejected it and the note API returned **401 Unauthorized**.
- **Signing key rotation:** a legitimately issued student token returned **200** for its owner's fixture before the simulated rotation and **401 Unauthorized** afterward.
- **Normal student login:** login returned **302** and issued a signed token; the owner then received **200** for her fixture note.
- **Missing or short key:** key loading failed; a malformed bearer credential also returned **401** even when a valid browser session was present.

The rotation test demonstrates invalidation of an earlier legitimate token. The
course's replay of the previously forged tokens was also performed: both Class 6
artifacts were sent to the repaired app and answered **401**, against **200** on
the pre-fix build, and a fresh login still reads its own row. See the
[Class 6 attack replay](../class06/ATTACK.md) and
[evidence/attack-after-fix.txt](../class06/evidence/attack-after-fix.txt).
Browser sessions from before the update need a fresh sign-in.

## Run the checks

From a running stack built with this checkout:

```sh
docker compose exec -T -e NOTESAPP_TEST_DB=1 web python -m unittest discover -s tests -p test_app_auth.py -v
```

Tests create and remove their own schemas and do not use real grades. The evidence contains no keys, tokens, or response data.
