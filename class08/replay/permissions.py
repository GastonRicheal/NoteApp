"""Class 8 permission matrix for GET /api/notes/<id>.

    python permissions.py --base http://127.0.0.1:8090 --expect vulnerable

Three accounts (student, teacher, administrator) against three note ids
(alice's own row, bob's row, a row that does not exist).  The session cookie
is used, exactly as a browser would: the note API accepts either a session or
a bearer token.

--expect grades the run against the build's intended policy, so the same
script records the pre-fix behaviour and the repaired behaviour.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

# reuse the tiny HTTP client from the Class 6 replay harness
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..",
                 "class06", "replay")))

from attack import ALICE_NOTE, BOB_NOTE, Client  # noqa: E402

MISSING_NOTE = 999

ACTORS = [
    ("alice", "alicepw", "student"),
    ("prof.turing", "teach123", "teacher"),
    ("admin", "admin123", "admin"),
]

NOTES = [
    (ALICE_NOTE, "alice's own"),
    (BOB_NOTE, "bob's"),
    (MISSING_NOTE, "missing"),
]

# What each role should get.  Pre-fix, the note handler never compares owners,
# so every authenticated role reads every existing note.
EXPECT = {
    "vulnerable": {
        ("student", "own"): 200, ("student", "foreign"): 200,
        ("student", "missing"): 404,
        ("teacher", "own"): 200, ("teacher", "foreign"): 200,
        ("teacher", "missing"): 404,
        ("admin", "own"): 200, ("admin", "foreign"): 200,
        ("admin", "missing"): 404,
        ("anonymous", "foreign"): 401,
    },
    "fixed": {
        ("student", "own"): 200, ("student", "foreign"): 404,
        ("student", "missing"): 404,
        ("teacher", "own"): 200, ("teacher", "foreign"): 200,
        ("teacher", "missing"): 404,
        ("admin", "own"): 200, ("admin", "foreign"): 200,
        ("admin", "missing"): 404,
        ("anonymous", "foreign"): 401,
    },
}


def kind(note_id: int) -> str:
    return {ALICE_NOTE: "own", BOB_NOTE: "foreign"}.get(note_id, "missing")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--expect", choices=["vulnerable", "fixed"], required=True)
    a = ap.parse_args()

    print("=" * 68)
    print("NotesApp permission matrix -- GET /api/notes/<id>  (Class 8)")
    print(f"target : {a.base}")
    print(f"expect : {a.expect} build")
    print(f"run at : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 68)
    print()
    print(f"  {'actor':<14}{'role':<10}{'note 1 (alice)':>16}{'note 3 (bob)':>15}"
          f"{'note 999':>11}")

    observed: dict[tuple[str, str], int] = {}
    for user, password, role in ACTORS:
        client = Client(a.base)
        st, _ = client.post_form("/login", {"username": user, "password": password})
        row = f"  {user:<14}{role:<10}"
        if st not in (200, 302):
            print(row + "  login failed")
            return 1
        for note_id, label in NOTES:
            status, body = client.get(f"/api/notes/{note_id}")
            observed[(role, kind(note_id))] = status
            row += f"{status:>16}" if note_id == ALICE_NOTE else f"{status:>15}"
        print(row)

    anon = Client(a.base)
    status, _ = anon.get(f"/api/notes/{BOB_NOTE}")
    observed[("anonymous", "foreign")] = status
    print(f"  {'(no login)':<14}{'anonymous':<10}{'-':>16}{status:>15}{'-':>11}")

    print()
    want = EXPECT[a.expect]
    ok = True
    print(f"  {'check':<34}{'observed':>10}{'expected':>10}")
    print("  " + "-" * 52)
    for key, expected in want.items():
        role, which = key
        got = observed.get(key)
        match = got == expected
        ok = ok and match
        print(f"  {role + ': ' + which:<34}{str(got):>10}{str(expected):>10}"
              f"   {'MATCH' if match else 'DIFF'}")
    print("  " + "-" * 52)
    print("VERDICT: " + ("matches the policy of this build" if ok
                         else "does NOT match the policy of this build"))

    if a.expect == "vulnerable":
        print()
        print("Reading: a logged-in student reads bob's row with 200 and no error.")
        print("The handler authenticated the caller and never compared the owner.")
    else:
        print()
        print("Reading: a student's foreign read is 404, the same answer as a")
        print("missing row, so the response does not reveal whether the row exists.")
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
