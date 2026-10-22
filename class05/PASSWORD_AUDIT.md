# NOTESAPP PASSWORD AUDIT

**Pair:** ZHANG FANGYUCHEN and LYU SONGYUAN

**Date:** 22 October 2026

**Scope:** The course's simulated accounts, its public wordlist, and our own
NotesApp clone.

## FINDING 1 — stored passwords (unsalted MD5)

- **Cracked:** 4/6 in 1.0 ms, using the unmodified course public
  wordlist. [Actual output](evidence/md5-attack-result.txt).
- **Held out & why:** `marie` (`mariepw`) and `raj` (`Gv7#pLm2!xQ`) were not
  guessed because their passwords were absent from this candidate list. Marie
  still uses a predictable pattern; Raj uses a longer random password. Surviving
  this dictionary does not prove that every possible attack fails.
- **Severity:** High, because a small public wordlist recovered four of six
  passwords in about one millisecond.
- **Fix:** Use Argon2id with a random salt and an appropriate time/memory cost,
  and encourage strong passwords.

The downloaded wordlist contains 170 nonempty entries; the page describes it as
approximately 190. We did not tailor or expand it. The MD5 file is simulated
course data; NotesApp itself originally stored plaintext passwords.

## FINDING 2 — the fix, measured

| Hash | Guesses / second | Estimated guesses / day |
| --- | ---: | ---: |
| MD5 | 1,976,990.52 | 170,811,980,618 |
| Argon2 | 20.89 | 1,804,729 |

**Argon2 is approximately 94,647 times slower per
guess.** One Argon2 hash took 47.874 ms.
[Exact measurements](evidence/password-benchmark.json).

**Verdict:** MD5 lets an attacker test common passwords almost instantly;
Argon2 makes a large guessing campaign much more expensive and may exceed the
attacker's resources. It raises the cost of guesses, rather than making weak
passwords impossible to crack.

The benchmark follows the course scaffold: 100,000 MD5 hashes and one Argon2 hash
inside the web container. Per-day figures are guesses/second x 86,400, not an
observed 24-hour attack. These are measurements on this laptop, not every
attacker's hardware.

## STATE

NotesApp now supports Argon2id password storage. Alice migrated during a normal
successful login. Logging in again succeeded using the existing hash, without
changing it. [Storage evidence](evidence/password-storage.json);
[second browser login](evidence/argon2-relogin.json).

Other legacy accounts migrate on their next successful login; no bulk migration
was run. The username SQL concatenation remains, as explicitly required by the
course for a later class. The app remains running at `http://localhost:8080`.

**Requirement source:** [Lab 2 — Password storage audit](https://kristenpire.github.io/epita-security-labs/class5/password-audit/).
