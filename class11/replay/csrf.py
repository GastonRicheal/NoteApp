"""Replay the Class 11 CSRF lab against a running NotesApp.

Eve never touches NotesApp: a page she controls makes the teacher's browser POST
to ``/grades`` with the teacher's cookie attached. The vulnerable build accepts
it because a valid cookie is the only check. The fix requires a per-session
token that only NotesApp's own pages print.

Usage:
    python class11/replay/csrf.py --base http://localhost:8080 --expect fixed
    python class11/replay/csrf.py --base http://localhost:8081 --expect vulnerable

The script writes to the disposable lab database only (note 10's grade/comment).
It exits non-zero unless every observation matches the expected build.
"""

import argparse
import http.cookiejar
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

# The forged body from the lab: note 10 is eve's Mathematics grade.
FORGED = {"note_id": "10", "grade": "20", "comment": "Perfect work."}
# The real teacher form restores the seed grade.
REAL = {"note_id": "10", "grade": "9.1", "comment": "Very strong final exam."}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _opener():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), _NoRedirect()
    )


def _request(opener, url, data=None):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    request = urllib.request.Request(url, data=body)
    try:
        with opener.open(request, timeout=15) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")
    except urllib.error.URLError as error:
        raise SystemExit(f"cannot reach {url}: {error.reason}") from None


def _login(opener, base, username, password):
    return _request(opener, f"{base}/login", {"username": username, "password": password})[0]


def _token(opener, base, path):
    html = _request(opener, f"{base}{path}")[1]
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return match.group(1) if match else None


def collect(base):
    observations = []

    teacher = _opener()
    observations.append(("teacher login (prof.turing)", _login(teacher, base, "prof.turing", "teach123") == 302))

    # The attack: cookie only, no page, no token.
    forged_status = _request(teacher, f"{base}/grades", dict(FORGED))[0]
    observations.append(("forged POST (cookie only) is accepted", forged_status == 302))

    token = _token(teacher, base, "/teacher")
    observations.append(("teacher page prints a CSRF token", bool(token)))
    data = dict(REAL)
    if token:
        data["csrf_token"] = token
    observations.append(("real form POST with token is saved", _request(teacher, f"{base}/grades", data)[0] == 302))

    admin = _opener()
    observations.append(("admin login (admin)", _login(admin, base, "admin", "admin123") == 302))
    admin_html = _request(admin, f"{base}/admin")[1]
    classes = len(re.findall(r'<form method="post"', admin_html))
    tokens = len(re.findall(r'name="csrf_token"', admin_html))
    observations.append(("admin page stamps every POST form", classes >= 3 and tokens == classes))

    ping_status = _request(admin, f"{base}/admin/ping", {"host": "127.0.0.1"})[0]
    observations.append(("admin ping without token is refused", ping_status == 400))

    return observations


def main():
    parser = argparse.ArgumentParser(description="Replay the Class 11 CSRF lab")
    parser.add_argument("--base", default="http://localhost:8080")
    parser.add_argument("--expect", choices=("vulnerable", "fixed"), required=True)
    args = parser.parse_args()
    base = args.base.rstrip("/")

    observations = collect(base)
    if args.expect == "vulnerable":
        expected = {
            "teacher login (prof.turing)": True,
            "forged POST (cookie only) is accepted": True,
            "teacher page prints a CSRF token": False,
            "real form POST with token is saved": True,
            "admin login (admin)": True,
            "admin page stamps every POST form": False,
            "admin ping without token is refused": False,
        }
    else:
        expected = {
            "teacher login (prof.turing)": True,
            "forged POST (cookie only) is accepted": False,
            "teacher page prints a CSRF token": True,
            "real form POST with token is saved": True,
            "admin login (admin)": True,
            "admin page stamps every POST form": True,
            "admin ping without token is refused": True,
        }
    print("=" * 68)
    print("NotesApp Class 11 CSRF replay (flaw #11)")
    print(f"target : {base}")
    print(f"expect : {args.expect} build")
    print("=" * 68)
    print()
    failures = 0
    for name, observed in observations:
        want = expected.get(name)
        mark = "MATCH " if observed == want else "DIFFER"
        failures += observed != want
        print(f"  {mark} {name:52s} observed {str(observed):5s} expected {str(want)}")
    print()
    if failures:
        print(f"VERDICT: {failures} observation(s) differ from the expected {args.expect} build")
        return 1
    print(f"VERDICT: matches the expected behaviour for the {args.expect} build")
    return 0


if __name__ == "__main__":
    sys.exit(main())

