# Class 6 — Live forgery replay against the pre-fix build

Source: [Class 6 lab brief](https://kristenpire.github.io/epita-security-labs/class6/forge-a-token/).

[FINDING.md](FINDING.md) records a source review. The course lab asks for a live
observation, and the repaired app cannot supply one — the fix removes the
behaviour under test. This page records the missing observation, taken against
the pre-fix revision in an isolated stack.

## Target and method

| | |
|---|---|
| Vulnerable revision | [`6d1bf81`](https://github.com/GastonRicheal/NoteApp/blob/6d1bf8159740c246bd1dbbce2f631f356ad07778/web/app.py#L102-L128) — `verify_jwt` with the `none` branch, `JWT_SECRET=s3cr3t` |
| Stack | Compose project `attack-prefix`, web on `127.0.0.1:8090`, `postgres:15` with a disposable volume seeded from `db/init.sql` |
| Repaired stack | The local `noteapp` project on `127.0.0.1:8080`, left untouched and measured with the same script |
| Harness | [`replay/attack.py`](replay/attack.py) — seven steps, standard library only |
| Raw output | [attack-baseline.txt](evidence/attack-baseline.txt), [attack-after-fix.txt](evidence/attack-after-fix.txt), [ci-replay.txt](evidence/ci-replay.txt), [ci-prefix-replay.txt](evidence/ci-prefix-replay.txt) |

The two stacks run from the same `db/init.sql`, so the compared rows are the
same rows. Nothing was written to either database.

## Results

| # | Request | Pre-fix | Repaired |
|---|---|---|---|
| 1 | log in `alice` / `alicepw` | 200, bearer token issued | 200, token issued |
| 2 | alice reads note 1 (her own row) | 200 | 200 |
| 3 | alice reads note 3 (bob's row) with her own token | **200** | **404** |
| 4 | unsigned token (`{"alg":"none"}`, `role=teacher`) reads note 3 | **200** | **401** |
| 5 | signing key recovered offline from alice's token | **`s3cr3t`** | not recovered |
| 6 | teacher token signed with that key reads note 3 | **200** | **401** |
| 7 | anonymous request | 401 | 401 |

Step 2 is the control: the repaired build is not rejecting everything — the
same account still reads its own row.

## What came back

From step 3 and step 4, verbatim:

```json
{"id": 3, "student": "bob", "grade": 12.6, "comment": "Solid work, keep it up."}
```

That is bob's grade, read by alice's session. In step 3 no forgery was involved
at all — the IDOR in `api_notes` is enough (see [Class 8](../class08/ACCESS_FIX.md)).
Step 4 then repeats it with a token that has no signature.

## The unsigned token

```text
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjo2LCJyb2xlIjoidGVhY2hlciJ9.
```

Two base64url JSON fields and an empty signature. The header says `none`, and
`verify_jwt` at `6d1bf81` returned the payload on that word alone. This is the
artifact the Class 6 slides show.

## The signing key

```text
target   : the bearer token issued at login (157 chars)
wordlist : 46 candidate keys
work     : one HMAC-SHA256 per candidate over the 113-byte signing input
result   : CRACKED -- 's3cr3t' at candidate #23, 0.18 ms
```

The key guess is tested **offline**, against a token the attacker already holds;
the server logs no request because none is made. Against the repaired build the
same 46 candidates return nothing, because the key is 256 random bits provisioned
at startup rather than a value written into `docker-compose.yml`.

## Scope

- Only `GET /api/notes/<id>` was attacked. Session handling, `/teacher`, the
  export route and the admin tools were not exercised here.
- Rows read are the seeded course fixtures (`db/init.sql`), not real student
  records. The lab stack uses its own PostgreSQL volume; the course stack was
  not modified.
- Read-only: no writes, no deletions, no denial of service, no shell. The
  `attack-prefix` stack and its volume were removed after the run.

## Reproduce

```sh
git worktree add ../NoteApp-prefix 6d1bf81
python scripts/generate_comment_key.py  --path ../NoteApp-prefix/.secrets/comment_key.b64
python scripts/generate_export_hmac_key.py --path ../NoteApp-prefix/.secrets/export_hmac_key.b64
PREFIX_DIR=../NoteApp-prefix docker compose -p attack-prefix \
    -f class06/replay/docker-compose.prefix.yml up -d --build

python class06/replay/attack.py --base http://127.0.0.1:8090 --expect vulnerable
python class06/replay/attack.py --base http://127.0.0.1:8080 --expect fixed
```

On Windows PowerShell, set `$env:PREFIX_DIR = '..\NoteApp-prefix'` first. The
script exits non-zero if any observed status differs from the build it was told
to expect, so the evidence cannot silently drift.

The second command also runs in CI on every push, against the stack the workflow
just built. The "401 after the fix" result is therefore re-checked automatically
rather than only recorded here; [ci-replay.txt](evidence/ci-replay.txt) is the
transcript from that step, and the run that produced it is
[43188295570](https://github.com/GastonRicheal/NoteApp/actions/runs/43188295570).

The baseline can be regenerated in CI too, on demand rather than on every push:
[`replay-prefix.yml`](../.github/workflows/replay-prefix.yml) runs this same
pre-fix stack from a `workflow_dispatch` job and returns the same statuses
(run [43189297737](https://github.com/GastonRicheal/NoteApp/actions/runs/43189297737),
39 s; transcript in [ci-prefix-replay.txt](evidence/ci-prefix-replay.txt)).

## Conclusion

The flaw was real and reachable over HTTP, not only visible in the source: an
empty signature and a guessed key each produced a teacher identity that the
pre-fix app accepted, and both returned another student's grade. After the
Class 7 changes the same two tokens return 401, and the same script documents
that as well.
