**Name:** ZHANG FANGYUCHEN

**Student ID:** 2023901700

# NotesApp security coursework

Coursework fork of [KristenPire/NoteApp](https://github.com/KristenPire/NoteApp).
This submission contains the work completed before Class 5:

- **Session 3 homework:** AES-256-GCM protection for stored note comments.
- **Project 1:** numbered data-flow diagrams, trust boundaries, a STRIDE risk
  register, likelihood x impact scores, and fixes for the three highest risks.
- **Class 4:** HMAC-SHA256 authentication and verification of grade CSV exports.

This is a deliberately vulnerable teaching application. Other planted course
flaws remain; the added controls do not make it suitable for a real deployment.
Class 5 HTTPS/Argon2 lab changes are outside this submission.

## Submission materials

- [Session 3 implementation and verification](HOMEWORK_SESSION03.md)
- [Project 1 report and three-minute presentation](project1/README.md)
- [Class 4 HMAC implementation and verification](CLASS04_HMAC_EXPORT.md)

Project 1 is an explicitly dated 9 October 2026 analysis. Its code fingerprints
identify that historical review, not the later HMAC implementation.

## Requirements and startup

Use Docker with the Compose plugin and Python 3.11+ for the standard-library
key-generation scripts. Application dependencies are installed inside Docker.
On systems whose Python command is `python3`, use it instead of `python` below.

```sh
git clone https://github.com/GastonRicheal/NoteApp.git
cd NoteApp
python scripts/generate_comment_key.py
python scripts/generate_export_hmac_key.py
docker compose up -d --build --wait
```

Open <http://localhost:8080>. Check readiness with
`curl http://localhost:8080/healthz` (expected: `ok`). On first startup, PostgreSQL
loads the course seed data and the web startup migration encrypts its comments
before serving requests.

Course seed accounts:

- Student: `alice` / `alicepw`
- Teacher: `prof.turing` / `teach123`
- Admin: `admin` / `admin123`

These are public course credentials, not production secrets. PostgreSQL and the
other intentionally weak teaching settings are retained from the supplied app.

## Verify the homework

```sh
docker compose exec -T -e NOTESAPP_TEST_DB=1 web python -m unittest discover -s tests -v
docker compose exec -T web python migrate_comments.py --dry-run
```

The submission has 38 unit/integration checks. Database integration tests use
disposable `test_comment_crypto_*` schemas, not the application's public tables.
CI generates temporary keys and verifies startup and all checks on a fresh seed
database. See [the workflow](.github/workflows/coursework.yml).

For the HMAC demonstration, log in as the teacher, download a signed grades CSV,
and upload it on **Verify a grades export**. The original passes. Change one
grade while keeping its HMAC footer; verification fails. Upload verification
does not import grades or write to the database.

## Key and data handling

The two generated keys have different purposes and live in Git-ignored
`.secrets/` files. Compose mounts them as secrets. No existing key, database
dump, exported grade data, private TLS key, packet capture or local cache is
part of this submission. Preserve your own keys and database volume together;
regenerating or replacing a key does not recover old encrypted data or validate
exports signed with another key.

Stop with `docker compose down`; the named database volume is retained. Never
delete that volume when you need the existing coursework data.

## Updating the fork

Only the fork owner should update the upstream remote and review incoming
changes before merging, particularly when local coursework is uncommitted:

```sh
git remote add upstream https://github.com/KristenPire/NoteApp.git
git fetch upstream
git merge upstream/main
```

Add `upstream` only once. After reviewing and testing a merge, push the approved
changes to your own fork and rebuild the web image.
