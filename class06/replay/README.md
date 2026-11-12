# Class 6 / 8 replay harness

Two scripts that speak HTTP to a running NotesApp and print a verdict:

- `attack.py` — the Class 6 forgery (unsigned token, offline key recovery,
  signed forgery) plus the Class 8 cross-account read.
- `../class08/replay/permissions.py` — the Class 8 role x note permission matrix.

Both take `--expect vulnerable` or `--expect fixed`, so the same script documents
the pre-fix behaviour and the repaired behaviour, and refuses to claim a pass it
did not observe. Standard library only; no dependencies to install.

## Run against the repaired stack

```sh
docker compose up -d --wait
python class06/replay/attack.py --base http://127.0.0.1:8080 --expect fixed
python class08/replay/permissions.py --base http://127.0.0.1:8080 --expect fixed
```

## Run against the pre-fix build

The vulnerable build lives at `6d1bf81`. Run it from a second checkout so the
repaired tree is never modified, and on its own ports so the two stacks do not
collide:

```sh
git worktree add ../NoteApp-prefix 6d1bf81

python scripts/generate_comment_key.py     --path ../NoteApp-prefix/.secrets/comment_key.b64
python scripts/generate_export_hmac_key.py --path ../NoteApp-prefix/.secrets/export_hmac_key.b64

PREFIX_DIR=../NoteApp-prefix docker compose -p attack-prefix \
    -f class06/replay/docker-compose.prefix.yml up -d --build

python class06/replay/attack.py --base http://127.0.0.1:8090 --expect vulnerable
python class08/replay/permissions.py --base http://127.0.0.1:8090 --expect vulnerable
```

On Windows PowerShell:

```powershell
$env:PREFIX_DIR = '..\NoteApp-prefix'
docker compose -p attack-prefix -f class06/replay/docker-compose.prefix.yml up -d --build
python class06/replay/attack.py --base http://127.0.0.1:8090 --expect vulnerable
```

`docker-compose.prefix.yml` publishes `8090` for the web service and keeps its
data in the `pgdata_attack` volume, so it can run beside the normal stack
(`8080`) without touching either the database or the code under test.

## Tear down

```sh
docker compose -p attack-prefix -f class06/replay/docker-compose.prefix.yml down -v
git worktree remove ../NoteApp-prefix
```

The `-v` matters: it removes the disposable database with the seeded fixtures.

## Notes

- Login uses the seed accounts from `db/init.sql`: `alice/alicepw`,
  `prof.turing/teach123`, `admin/admin123`.
- The bearer token is read from the student dashboard, which embeds it as
  `const TOKEN = ...` — the same token the browser uses.
- `wordlist.txt` holds 46 common weak JWT secrets. It exists to show that the
  pre-fix key is guessable, not to attack anything else.
