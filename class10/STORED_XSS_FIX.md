# Class 10 — Stored XSS fix

Source: [Class 10 lab brief](https://kristenpire.github.io/epita-security-labs/class10/stored-xss/).

Class 9 was injection on the way in — typed text became a command on the server. This class is
injection on the way out — stored text became **code in someone else's browser**. One flag in two
templates did it: `{% autoescape false %}` around the grade comment (NotesApp flaw #10).

## Part 1 — the trap fires

With a teacher session, note 1's comment was set to a program instead of a comment:

```bash
curl -s -b teacher.jar \
     --data-urlencode "note_id=1" \
     --data-urlencode "grade=16.2" \
     --data-urlencode "comment=<script>alert('XSS by Eve')</script>" \
     http://localhost:8081/grades -o /dev/null -w "comment saved: HTTP %{http_code}\n"
```

The saved page for alice carried the tag **unescaped** — `POST /grades` → **302**, and
`GET /dashboard` contained the literal `<script>alert('XSS by Eve')</script>` inside the comment
cell ([part1-xss.txt](evidence/part1-xss.txt)). A browser does not show that text, it runs it:
opening the dashboard as **alice / alicepw** in a real InPrivate Edge window popped the dialog
([xss-alert.png](evidence/xss-alert.png)).

It is **stored**: the teacher wrote it once, and it runs for every reader of that note. The script
executes with the reader's session, not the author's.

## Part 2 — put the glass back

The fix is not a blacklist of "bad words" — no list survives a determined payload. The fix is to
stop switching the safety off. In [web/templates/dashboard.html](../web/templates/dashboard.html)
and [web/templates/teacher.html](../web/templates/teacher.html):

```html
<!-- BEFORE (flaw #10): the comment is handed to the browser as live code -->
<td>{% autoescape false %}{{ n.comment }}{% endautoescape %}</td>

<!-- AFTER: the template escapes by default; <script> is shown as text -->
<td>{{ n.comment }}</td>
```

After a rebuild, the same comment comes back as
`&lt;script&gt;alert(&#39;XSS by Eve&#39;)&lt;/script&gt;` in both the student and teacher views
([part2-xss-fixed.txt](evidence/part2-xss-fixed.txt)). Reloading alice's dashboard in the browser
showed the characters as text and no dialog ([xss-escaped.png](evidence/xss-escaped.png)).

## Part 3 and 4 — closed, and normal comments still work

Re-posting the exact payload as the teacher produced no live `<script>` in alice's page; the raw
tag is absent and only the escaped form remains. Normal prose is unaffected: `score < 10 on part 1
& 2, see me & retry` is sent as `score &lt; 10 on part 1 &amp; 2, see me &amp; retry`, so the
browser displays a less-than sign and an ampersand rather than parsing markup
([part2-xss-fixed.txt](evidence/part2-xss-fixed.txt), Part 4 section).

A fix that would mangle plain text is not a fix, so this is part of the evidence, not an
afterthought.

## Hand-in

```text
STORED XSS FIX — NotesApp flaw #10 closed

  Break:  comment on note 1 =  <script>alert('XSS by Eve')</script>
          opened as alice -> the alert fired in Edge (InPrivate), and the page carried
                             the literal <script> tag in the comment cell
  Fix:    removed {% autoescape false %} in dashboard.html AND teacher.html
  Closed: same comment now shows as text -> &lt;script&gt;alert(&#39;XSS by Eve&#39;)&lt;/script&gt;,
          no alert, no live tag in either view
  Real use still works:  "score < 10 ... & retry" displays correctly [x]
```

Evidence: [xss-alert.png](evidence/xss-alert.png) (pre-fix browser),
[part1-xss.txt](evidence/part1-xss.txt) (pre-fix HTTP), [xss-escaped.png](evidence/xss-escaped.png)
(post-fix browser), [part2-xss-fixed.txt](evidence/part2-xss-fixed.txt) (post-fix HTTP and normal
text), and the replay harness below.

## Predictions

Expected before running the checkpoints:

| question | expected | why |
|---|---|---|
| Alice opens her dashboard after the teacher's comment | the **alert runs** and the page holds a live `<script>` | `autoescape false` hands the stored text to the browser as HTML |
| After removing the wrapper | the tag is **shown as text**, no alert | the template engine `<` → `&lt;` by default |
| After the fix, a normal comment with `<` and `&` | still **displays as written** | escaping converts the characters, it does not delete or mangle them |

All three matched the measurement.

## Replaying it

The lab stack used **8081**, because 8080 was already serving another NotesApp checkout on this
machine (independent compose project, no repository change):

```bash
python class10/replay/xss.py --base http://localhost:8081 --expect fixed
```

The harness logs in as the teacher and alice, stores the script comment, checks that alice's page
does not carry a live tag, checks the escaped form, and re-posts the normal `<`/`&` sentence. It is
part of CI, so a template that re-opens the hole fails the build.

Both directions were measured: [replay-vulnerable.txt](evidence/replay-vulnerable.txt) against the
pre-fix revision `14c0ca0` (live tag present) and [replay-fixed.txt](evidence/replay-fixed.txt)
against this submission (escaped).

## Notes

- The fix keeps rich text *out* of the comment on purpose. If HTML ever becomes a requirement, the
  answer is a server-side allow-list sanitiser (e.g. `bleach`), not `autoescape false`.
- The XSS trap that was planted during the lab is still in note 1's comment in the disposable local
  database, now inert; it is what the screenshots and the replay exercise.
