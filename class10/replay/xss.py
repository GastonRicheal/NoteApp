"""Replay the Class 10 stored-XSS lab against a running NotesApp.

The trap: a teacher stores ``<script>alert('XSS by Eve')</script>`` as a grade
comment on note 1. On the vulnerable build the dashboard/teacher templates wrap
the comment in ``{% autoescape false %}``, so alice's page carries live code.
The fix restores the default escaping, so the same bytes come back as text.

Usage:
    python class10/replay/xss.py --base http://localhost:8080 --expect fixed
    python class10/replay/xss.py --base http://localhost:8081 --expect vulnerable

The script writes to the disposable lab database only (note 1's comment and
grade). It exits non-zero unless every observation matches the expected build.
"""

import argparse
import http.cookiejar
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

PAYLOAD = "<script>alert('XSS by Eve')</script>"
ESCAPED_PAYLOAD = "&lt;script&gt;alert(&#39;XSS by Eve&#39;)&lt;/script&gt;"
NORMAL = "score < 10 on part 1 & 2, see me & retry"
ESCAPED_NORMAL = "score &lt; 10 on part 1 &amp; 2, see me &amp; retry"


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
    """The hidden token a real page prints (Class 11), or None on older builds."""
    html = _request(opener, f"{base}{path}")[1]
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return match.group(1) if match else None


def _set_comment(opener, base, token, payload):
    data = {"note_id": "1", "grade": "16.2", "comment": payload}
    if token:
        data["csrf_token"] = token
    return _request(opener, f"{base}/grades", data)[0]


def collect(base):
    observations = []

    teacher = _opener()
    observations.append(("teacher login (prof.turing)", _login(teacher, base, "prof.turing", "teach123") == 302))
    token = _token(teacher, base, "/teacher")
    observations.append(("teacher page prints a CSRF token", bool(token)))

    observations.append(("teacher stores the script comment", _set_comment(teacher, base, token, PAYLOAD) == 302))

    alice = _opener()
    observations.append(("alice login", _login(alice, base, "alice", "alicepw") == 302))
    html = _request(alice, f"{base}/dashboard")[1]
    observations.append(("alice page carries live <script>", PAYLOAD in html))
    observations.append(("alice page shows the escaped script", ESCAPED_PAYLOAD in html))

    observations.append(("teacher stores normal text with < and &", _set_comment(teacher, base, token, NORMAL) == 302))
    html = _request(alice, f"{base}/dashboard")[1]
    observations.append(("normal text is escaped, not markup",
                         ESCAPED_NORMAL in html and not re.search(r"score\s*<", html)))

    return observations


def main():
    parser = argparse.ArgumentParser(description="Replay the Class 10 stored XSS")
    parser.add_argument("--base", default="http://localhost:8080")
    parser.add_argument("--expect", choices=("vulnerable", "fixed"), required=True)
    args = parser.parse_args()
    base = args.base.rstrip("/")

    observations = dict(collect(base))
    if args.expect == "vulnerable":
        expected = {
            "teacher login (prof.turing)": True,
            "teacher page prints a CSRF token": False,
            "teacher stores the script comment": True,
            "alice login": True,
            "alice page carries live <script>": True,
            "alice page shows the escaped script": False,
            "teacher stores normal text with < and &": True,
            "normal text is escaped, not markup": False,
        }
    else:
        expected = {
            "teacher login (prof.turing)": True,
            "teacher page prints a CSRF token": True,
            "teacher stores the script comment": True,
            "alice login": True,
            "alice page carries live <script>": False,
            "alice page shows the escaped script": True,
            "teacher stores normal text with < and &": True,
            "normal text is escaped, not markup": True,
        }

    print("=" * 68)
    print("NotesApp Class 10 stored XSS replay (flaw #10)")
    print(f"target : {base}")
    print(f"expect : {args.expect} build")
    print("=" * 68)
    print()
    failures = 0
    for name, observed in observations.items():
        want = expected[name]
        mark = "MATCH " if observed == want else "DIFFER"
        failures += observed != want
        print(f"  {mark} {name:44s} observed {str(observed):5s} expected {str(want)}")
    print()
    if failures:
        print(f"VERDICT: {failures} observation(s) differ from the expected {args.expect} build")
        return 1
    print(f"VERDICT: matches the expected behaviour for the {args.expect} build")
    return 0


if __name__ == "__main__":
    sys.exit(main())
