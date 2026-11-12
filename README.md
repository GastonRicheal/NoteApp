**Name:** ZHANG FANGYUCHEN

**Student ID:** 2023901700

# NotesApp security coursework

Coursework fork of [KristenPire/NoteApp](https://github.com/KristenPire/NoteApp).
This fork contains the following coursework:

- **Session 3 homework:** AES-256-GCM protection for stored note comments.
- **Project 1:** numbered data-flow diagrams, trust boundaries, a STRIDE risk
  register, likelihood x impact scores, and fixes for the three highest risks.
- **Class 4:** HMAC-SHA256 authentication and verification of grade CSV exports.
- **Class 5:** HTTPS traffic auditing, certificate trust, and login-time Argon2id
  password migration, with measured password-audit findings.
- **Class 6:** source review of the original JWT verification flaw, plus a live
  replay of both forgeries against the pre-fix build.
- **Class 7:** HS256-only verification and a provisioned random signing key.
- **Class 8:** server-side note ownership checks and access regressions.

This is a deliberately vulnerable teaching application. Other planted course
flaws remain; the added controls do not make it suitable for a real deployment.

## Submission materials

- [Session 3 implementation and verification](HOMEWORK_SESSION03.md)
- [Project 1 report and three-minute presentation](project1/README.md)
- [Class 4 HMAC implementation and verification](CLASS04_HMAC_EXPORT.md)
- [Class 5 required audit sheets and supporting evidence](class05/README.md)
- [Class 6 source-review finding](class06/FINDING.md)
- [Class 6 live forgery replay against the pre-fix build](class06/ATTACK.md)
- [Class 7 login fix and regression evidence](class07/LOGIN_FIX.md)
- [Class 8 grade access fix and regression evidence](class08/ACCESS_FIX.md)
- [Replay harness and reproduction steps](class06/replay/README.md)

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
python scripts/generate_jwt_key.py
docker compose up -d --build --wait
```

Open <http://localhost:8080>. Check readiness with
`curl http://localhost:8080/healthz` (expected: `ok`). On first startup, PostgreSQL
loads the course seed data and the web startup migration encrypts its comments
before serving requests.

The three keys those scripts generate are runtime secrets, not source. They live
in `.secrets/`, which Git ignores, and Compose mounts them into the container as
files. In a real deployment they belong in a secrets store — never in a
committed file, and never in an image layer.

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

The submission has 52 unit/integration checks. Database integration tests use
disposable `test_comment_crypto_*` schemas, not the application's public tables.
CI generates temporary keys and verifies startup and all checks on a fresh seed
database, then checks the HTTPS entrance and closure of the direct HTTP port.
See [the workflow](.github/workflows/coursework.yml).

For the HMAC demonstration, log in as the teacher, download a signed grades CSV,
and upload it on **Verify a grades export**. The original passes. Change one
grade while keeping its HMAC footer; verification fails. Upload verification
does not import grades or write to the database.

## Key and data handling

The three generated keys have different purposes and live in Git-ignored
`.secrets/` files. Compose mounts them as secrets. No existing key, database
dump, exported grade data, private TLS key, packet capture or local cache is
part of this submission. Preserve your own keys and database volume together;
regenerating or replacing a key does not recover old encrypted data or validate
exports signed with another key.

Compose sets `JWT_SECRET_FILE` to the mounted signing key. Without Compose,
provide `JWT_SECRET` as 32 random bytes encoded in Base64, or point
`JWT_SECRET_FILE` to a file with that value. Use a secret manager in a real
deployment. Existing browser sessions are invalidated by the switch from the
course default; sign in again after rebuilding.

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

## Class 5 labs: HTTPS and password storage

The required findings sheets are [the transit audit](class05/TRANSIT_AUDIT.md)
and [the password audit](class05/PASSWORD_AUDIT.md), with only their necessary
supporting evidence. The pair for these labs is ZHANG FANGYUCHEN and LYU SONGYUAN.

For the HTTPS lab, Docker Compose 2.24+ and OpenSSL are required. Generate your
own certificate and private key once; neither generated file is committed.
Create `nginx/certs` first (`mkdir -p nginx/certs` on Linux/macOS, or the following
PowerShell command on Windows):

```powershell
New-Item -ItemType Directory -Force nginx/certs
```

Use the course's certificate parameters:

```sh
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout nginx/certs/notesapp.key -out nginx/certs/notesapp.crt -subj "/CN=localhost"
```

If OpenSSL on Windows cannot find `openssl.cnf`, use the configuration file
installed with your OpenSSL distribution through `-config <path-to-openssl.cnf>`.
Do not replace an existing private key when you want to retain that certificate.
Start the HTTPS entrance with both Compose files:

```powershell
docker compose down
docker compose -f docker-compose.yml -f docker-compose.https.yml up -d --build
```

This serves `https://localhost` through nginx and explicitly removes the base
8080 port using `!reset []`. The certificate is self-signed for the lab and is
not trusted by the browser; never commit the private key. The course cleanup is:

```powershell
docker compose -f docker-compose.yml -f docker-compose.https.yml down
docker compose up -d
```

After cleanup, the default entrance is `http://localhost:8080`. Login supports
Argon2id: a legacy plaintext password is upgraded only after a successful login.
Our recorded evidence verifies Alice's migration and second login. A new clone
starts with the course seed accounts; log in once to migrate each account.
The username SQL concatenation remains as explicitly required by the course.

The course MD5 demonstration uses simulated course data and the unmodified public
wordlist. Run from the project root:

```sh
python crack/make_dump.py
python crack/crack.py
```

The generated simulated dump stays local. The published findings retain the
original measured results; rerunning on another machine need not give the same
timings. Private keys, session cookies, raw captures, detailed local transcripts
and review archives are excluded from the submission.
