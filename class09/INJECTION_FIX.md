# Class 9 — Injection fix

Source: [Class 9 lab brief](https://kristenpire.github.io/epita-security-labs/class9/injection/).

Two flaws, one mistake: the server builds a sentence out of what the user typed and hands it to
something that obeys it. Flaw #8 did that in SQL, flaw #9 in a shell. Both were measured on the
pre-fix revision (`8ed4c88`), both were closed in [web/app.py](../web/app.py), and the same inputs
were replayed against the rebuilt stack.

## Flaw #8 — SQL injection on the login

Pre-fix code ([web/app.py](../web/app.py)):

```python
# Flaw #8: SQL injection. Query built by string concatenation, no params.
query = (
    "SELECT id, username, role, password FROM users "
    "WHERE username = '" + username + "'"
)
cur.execute(query)
```

### The lab payload on this revision

The brief assumes `... AND password = '<password>'` is glued in as well, so that `admin' -- `
strikes the password clause out. This fork changed that in Class 5: the password was taken out of
SQL and is verified in Python, Argon2id aware. The literal payload therefore returns admin's row
and is then refused by the Python check:

| attempt | result |
|---|---|
| `admin' -- ` / `anything` | login refused — `Invalid credentials.` |
| `'` alone | the raw PostgreSQL error was returned before the fix: `unterminated quoted string at or near "'''"` |

The injection itself is still live through the username, so the equivalent payload forges the row
instead of commenting out the check:

```text
username  zzz' UNION SELECT 1,'admin','admin','anything' --
password  anything
```

`cur.fetchone()` returns our row, whose `password` column is the string we chose, so the Python
comparison compares our string with itself. Measured on the pre-fix build: `POST /login` → **302**
(session issued) and `GET /admin` → **200**, with no real password used anywhere.

One consequence is worth recording: the pre-fix handler upgrades a plaintext password on every
successful login, and it did that to the row we supplied. The replay wrote the hash of `anything`
into admin's row, which broke `admin/admin123` until the seed row was restored for Part 3. The
injection was not just an authentication bypass; it was destructive.

Evidence: [part1-sqli.txt](evidence/part1-sqli.txt).

## Flaw #9 — command injection on the admin ping

Pre-fix code ([web/app.py](../web/app.py)):

```python
# Flaw #9: command injection via os/system shell.
host = request.form.get("host", "")
cmd = "ping -c 1 " + host
result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
```

With a real admin session, `host = 127.0.0.1; id; head -2 /etc/passwd` returned the ping, then
`uid=0(root) gid=0(root) groups=0(root)`, then the first two lines of `/etc/passwd`. The container
has no `USER` directive, so the shell handed us root inside it. Evidence:
[part3-cmdi.txt](evidence/part3-cmdi.txt).

## The fix

**Login — pass data as data.** The username is a bound parameter; the password check stays in
Python, where it can compare a plaintext value today and an Argon2id hash after the Class 5
migration:

```python
query = "SELECT id, username, role, password FROM users WHERE username = %s"
cur.execute(query, (username,))
```

This is the one-line idea of the class. It is not `AND password = %s`: the password column holds
`$argon2id$...` after the first successful login, so a SQL equality on the typed password would
stop matching real users. The database is asked only which row the *name* addresses; whether the
caller may become that user is decided in Python, against the stored hash.

**Ping — no shell, one argument.** `host` is one element of an argument list from start to finish:

```python
if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
    output = "Invalid host: use only letters, digits, dots and hyphens."
else:
    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True, text=True, timeout=10,
    )
```

The argument list is the wall; `[A-Za-z0-9.-]+` is the second wall suggested by the brief. It is
not the fix — validation is bypassable by a future route change, and the shell can be removed
without it.

## Hand-in

```text
INJECTION FIX — NotesApp flaws #8 (SQL injection) and #9 (command injection) closed

  SQLi proof (break):   username  admin' --   -> refused on this revision (Class 5 moved
                        the password check out of SQL; see above), so the same flaw was
                        shown with  username zzz' UNION SELECT 1,'admin','admin','anything' --
                        password  anything    -> admin session, /admin 200
  SQLi fix:             login() uses cur.execute("... WHERE username = %s", (username,));
                        the Argon2id check stays in Python — no string gluing in the sentence
  SQLi proof (closed):  same username now  -> "Invalid credentials." + /admin 302

  CmdI proof (break):   host  127.0.0.1; id   returned -> uid=0(root) gid=0(root) groups=0(root)
  CmdI fix:             admin_ping() uses subprocess.run(["ping","-c","1",host], ...),
                        no shell=True, plus a [A-Za-z0-9.-]+ host check
  CmdI proof (closed):  same host now -> "Invalid host: use only letters, digits, dots and
                        hyphens."  (argument-list-only build: ping: ...: Name or service not known)

  Real use still works: alice login OK [x]   plain 127.0.0.1 ping OK [x]
```

Every value above is measured, not asserted:

- [part2-sqli-fixed.txt](evidence/part2-sqli-fixed.txt) — both SQLi payloads and the syntax probe
  after the parameterised query, plus the destructive side effect recorded on the pre-fix build.
- [part3-cmdi-fixed.txt](evidence/part3-cmdi-fixed.txt) — the injection is gone, the marker check
  returns `False` for `uid=0`, `root:` and `/bin/bash`, and a plain `127.0.0.1` still pings.
- [part4-regression.txt](evidence/part4-regression.txt) — alice logs in on a plaintext seed row,
  logs in again after the row becomes Argon2id, a wrong password is refused, both SQLi payloads are
  inert, and the admin page and plain ping still work.
- [regression-suite.txt](evidence/regression-suite.txt) — `Ran 52 tests ... OK`, and the Class 6 and
  Class 8 replays still match their fixed-build expectations.

## Predictions

Recorded before any attack was sent ([predictions.txt](evidence/predictions.txt)):

| question | predicted | why |
|---|---|---|
| Does the literal `admin' -- ` log in on the pre-fix revision? | **no** | the password clause is no longer in the sentence, so `--` has nothing to remove; the Python check still runs |
| If not, can SQL still authenticate? | **yes, with UNION** | a forged row whose `password` column is the caller's own string passes the Python equality |
| Does the command injection run as root? | **yes** | `shell=True`, `;`, and a container with no `USER` directive |
| Do the real features survive the fixes? | **yes** | only how the sentence is built changes, not the credentials |

Only the first answer differs from the brief's expectation, and it is a property of this fork's
Class 5 work, not of the fix.

## Reproducing

The lab stack in this checkout was published on **8081**, because 8080 was already taken by
another NotesApp checkout on this machine. The compose project was run separately
(`-p class9lab`) and the port override lives outside the Git tree, so nothing about the repository
depends on it.

```bash
python scripts/generate_comment_key.py
python scripts/generate_export_hmac_key.py
python scripts/generate_jwt_key.py
docker compose -p class9lab up -d --build --wait
python class09/replay/injection.py --base http://localhost:8080 --expect fixed
```

Against the pre-fix revision, the same harness gives the red result — both flaws present — while
the lab's literal payload still reports "no session". That run is kept as
[replay-vulnerable.txt](evidence/replay-vulnerable.txt), and the green one as
[replay-fixed.txt](evidence/replay-fixed.txt). The harness is part of the CI workflow: a push that
re-opens either hole fails the build.

## Cleanup and what was not uploaded

The stack is stopped with `docker compose -p class9lab down` (the `pgdata` volume keeps the lab
data). Runtime keys in `.secrets/` are generated locally and ignored by Git; session cookies stayed
in a temporary directory. The only credentials in this folder are the course seed values that
already ship in `db/init.sql`, and the only `/etc/passwd` bytes are the two default container
accounts the lab asks for.
