# Class 4: protect the grades export

Implements the course's “NotesApp: protect the grades export” exercise: append an
HMAC using a server-only secret, then detect a change to one exported grade.

## Run the demonstration

Follow the [root startup instructions](README.md#requirements-and-startup).

1. Log in at <http://localhost:8080> as `prof.turing` / `teach123`.
2. Select **Export all grades (HMAC)**, or **export signed CSV** for one class.
3. Open **Verify a grades export** and upload the downloaded `grades_export.csv`.
   The original displays **CHECK PASSED**.
4. Save a copy, change exactly one grade, keep the original HMAC footer, and
   upload the copy. It displays **CHECK FAILED**.

Verification authenticates an uploaded file without importing it or changing
grades. Local exported CSVs and demo screenshots are not source files and are
excluded from this submission.

## Design

`web/export_integrity.py` authenticates the exact UTF-8 CSV bytes with
HMAC-SHA256, including the four-column header, every record and CRLF line endings.
Its input is `notesapp:grades-export:v1`, a zero byte, and the CSV payload.
Authenticated AES-GCM comments are decrypted before export. A fixed final line
`# HMAC: sha256:<64 lowercase hexadecimal digits>` carries the HMAC and is not
included in its own input.

Verification splits only the final fixed-format footer. It does not normalize
line endings, parse/reserialize CSV, or discard whitespace before comparing with
`hmac.compare_digest`. The signed file is limited to 5 MiB. Multipart uploads
are bounded as well, and filenames/file contents are not rendered as HTML.

`scripts/generate_export_hmac_key.py` generates a separate 32-byte random key in
`.secrets/export_hmac_key.b64`, preserves an existing valid key, and never prints
the key. Compose mounts it at `/run/secrets/export_hmac_key`. The key is not sent
to browsers, stored in the CSV/database, reused from AES, or included in Git.

A server maintainer with this key can also verify locally:

```sh
python scripts/verify_grade_export.py path/to/grades_export.csv
```

Exit codes: 0 valid, 1 failed/oversized, 2 file/key setup error. Do not distribute
the server key to students for verification.

## Checks

```sh
docker compose exec -T -e NOTESAPP_TEST_DB=1 web python -m unittest discover -s tests -v
```

All 38 combined AES-GCM/HMAC checks must pass. The 20 HMAC checks cover unchanged
exports, one-grade changes, wrong keys, plain-SHA256 forgeries, missing/damaged/
appended footers, line ending changes, Unicode/multiline data, upload permissions,
size limits and preservation of database rows. Tests use disposable schemas.
Earlier browser verification also confirmed that an export made before a web
restart still passes after the restart with the same key.

HMAC supplies integrity and authentication by a key holder, not CSV encryption
or freshness/replay protection. A key holder can issue a new valid tag; HMAC
does not detect an incorrect grade that already existed before export. Other
teaching flaws remain. Project 1 remains a dated historical threat analysis.
