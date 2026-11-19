# Class 11 — CSRF fix

Source: [Class 11 lab brief](https://kristenpire.github.io/epita-security-labs/class11/csrf/).

Class 10 ran Eve's code inside the victim's page. Here Eve needs **no code in NotesApp at all**: a
page she controls makes the teacher's browser send the "change grade" request, and the browser
attaches the teacher's session cookie by itself. The server only asked *"is the cookie valid?"*,
never *"did my own form send this?"* (NotesApp flaw #11).

## Part 1 — a valid cookie is the only check

As `prof.turing`, a POST with nothing but the cookie was accepted:

```bash
curl -s -b teacher.jar -H "Origin: http://evil.example" \
     -d "note_id=10&grade=20&comment=Perfect work." \
     http://localhost:8081/grades -o /dev/null -w "forged request: HTTP %{http_code}\n"
```

It returned **302** (saved, redirect back) and eve's dashboard then showed note 10 = **20.0**,
*"Perfect work."* ([part1-forged.txt](evidence/part1-forged.txt)). The `Origin: evil.example`
header was ignored; the app does not consult it.

## Part 2 — zero clicks, real browser

Eve's page is a form with hidden fields plus a script that submits it on load:

```html
<form id="f" action="http://localhost:8081/grades" method="POST">
  <input type="hidden" name="note_id" value="10">
  <input type="hidden" name="grade"   value="19.5">
  <input type="hidden" name="comment" value="Changed by Eve's page.">
</form>
<script>document.getElementById("f").submit();</script>
```

It was served as a second site on port 9000 (`python -m http.server 9000`) from a folder **outside**
the NotesApp clone. Logged in as `prof.turing` in an InPrivate Edge window, opening
`http://localhost:9000/prize.html` changed note 10 to **19.5 / "Changed by Eve's page."** with no
click on NotesApp at all ([csrf-browser-before.png](evidence/csrf-browser-before.png)). The teacher
just visited a link.

## Part 3 — the fix: a stamp only our own pages can print

A per-session random token is printed by every real form and checked on every state-changing POST:

```python
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"   # defence in depth, not the wall


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST" and request.endpoint != "login":
        expected = session.get("csrf")
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
        if (not expected
                or not hmac.compare_digest(sent.encode("utf-8"), expected.encode("utf-8"))):
            abort(400, "CSRF token missing or wrong")
```

Every POST form now starts with the stamp:

```html
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
```

That is the lab's four forms — one in [teacher.html](../web/templates/teacher.html) and three in
[admin.html](../web/templates/admin.html) — plus one this fork needs for its Class 4 upload form in
[verify_export.html](../web/templates/verify_export.html). The blanket rule has an exception only
for `login`, so the upload form has to carry a token too; otherwise a real feature breaks.

Two implementation choices worth naming:

- **The token lives in the signed session cookie**, so the server can compare without extra storage,
  and a client cannot read another session's value. The comparison is done on bytes to avoid a
  `TypeError` (and a 500) on a non-ASCII guess; a wrong guess is simply a 400.
- **`X-CSRF-Token` is accepted as well as the form field.** A cross-site page cannot set a custom
  header without a CORS preflight, so this does not weaken the check, and it lets command-line
  clients and the test suite drive the app without faking a browser page.

The unit tests were updated accordingly: form posts send the token, and the oversized raw-body test
for `/verify-export` sends it as a header so the pre-parse size guard can still be exercised.
[class09/replay/injection.py](../class09/replay/injection.py) now reads the token from `/admin`
before posting to the ping route, which is why the Class 9 replay still passes on the final build.

## Part 4 — forged refused, real forms still work

| request | result |
|---|---|
| forged POST `/grades` (cookie only, no token) | **400** `CSRF token missing or wrong` |
| same POST with a wrong token | **400** |
| real teacher form: load `/teacher` (prints token), then save | **302**, eve back to **9.1**, *"Very strong final exam."* |
| admin: add user `csrf_probe_…` | **302**, user appears |
| admin: delete that user | **302**, user gone |
| admin ping with token | **200**, `PING 127.0.0.1 ...` |
| admin ping without token | **400** |
| evil page opened as the logged-in teacher | **400 Bad Request**, note 10 unchanged |
| real teacher form in the browser | saved, redirect back to `/teacher` |

The admin page printed **37** hidden token inputs for its **37** POST forms (one delete form per
user, the create form and the ping form) in the captured run. The measurements are in
[part2-fixed.txt](evidence/part2-fixed.txt), the refused browser page in
[csrf-browser-after.png](evidence/csrf-browser-after.png), and the browser real-form save in
[teacher-form-browser.png](evidence/teacher-form-browser.png).

## Hand-in

```text
CSRF FIX — NotesApp flaw #11 closed

  Break:  logged in as prof.turing, opened localhost:9000/prize.html
          note 10 became -> 19.5, "Changed by Eve's page."   (curl replay: 302, eve saw 20.0)
  Fix:    per-session token (secrets.token_urlsafe), checked on every POST,
          hidden csrf_token field in teacher.html (1 form) + admin.html (3 forms),
          and the fork's verify_export.html (1 form); SameSite=Lax as a second wall
  Closed: same page now -> 400 Bad Request, grade unchanged
  Real use still works: teacher saves a grade [x]  admin adds a user [x]  admin ping [x]
```

## Predictions

Expected before running the checkpoints:

| question | expected | why |
|---|---|---|
| A POST with only the teacher cookie | **302, accepted** | the server checks the cookie, never the request's origin |
| The evil page opened by a logged-in teacher | **grade changes, no click** | the browser attaches `localhost` cookies to the cross-site POST |
| After the token check | **400** for the forged request, **302** for the real form | only the real page prints the token, and another site cannot read it |
| Old Class 9/10 curl commands after the fix | **400** | they post without a token; the fix is supposed to notice |

All four matched.

## Replaying it

```bash
python class11/replay/csrf.py --base http://localhost:8081 --expect fixed
```

The harness logs in, sends the cookie-only forged POST, checks the token on the teacher page, saves
a grade through the real token flow, and checks the administrator page stamps every POST form. It
runs in CI after the Class 10 replay.

Both directions were measured: [replay-vulnerable.txt](evidence/replay-vulnerable.txt) against the
pre-fix revision `14c0ca0` (forged request accepted) and
[replay-fixed.txt](evidence/replay-fixed.txt) against this submission (forged request refused).

## Notes

- `SameSite=Lax` is not the fix. It is a browser seatbelt that would not have stopped this lab's
  attack anyway — `localhost:9000` and `localhost:8080` are the same site, so the browser sends the
  cookie. The server-side token is what refuses the request.
- The token is a **session** secret, not a per-request nonce: it stops cross-site forging, which is
  what flaw #11 is. Replay of a stolen token is a different problem (that is what HTTPS and short
  sessions are for).
- This fix changes the older labs' command line: Class 9's ping and Class 10's comment POST now need
  the token (or its header). Their evidence files were captured before this class; the replay
  harnesses were updated to fetch the token, which is also what the lab's troubleshooting note
  predicts.
