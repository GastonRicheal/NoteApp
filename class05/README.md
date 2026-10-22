# Class 5 — HTTPS and password audit submission

**Pair:** ZHANG FANGYUCHEN and LYU SONGYUAN

**Student ID (ZHANG FANGYUCHEN):** 2023901700

**Reviewed against current course pages:** 22 October 2026.

## Required hand-in

The course requests two findings sheets, not a command transcript or a code
dump. Read these two files first:

1. [Lab 1 — Transit audit](TRANSIT_AUDIT.md), with HTTP/HTTPS before-and-after
   screenshots and the actual certificate comparison.
2. [Lab 2 — Password audit](PASSWORD_AUDIT.md), with two findings, the measurement
   table and the verified Argon2 migration state.

The `evidence/` folder contains only the small set of evidence referenced by the
two sheets. The HTTP screenshot is a lossless crop of the actual capture: it
retains the request and credential line, and omits the response containing a
session cookie. No retained pixels were changed or AI-redrawn. The HTTPS
screenshot is unchanged. Numeric results are from the original measurements,
not a fresh run chosen to replace them. Original screenshots, raw captures and
detailed test logs remain local and are not published.

## Completion checks

- Lab 0: Docker Compose, NotesApp, Wireshark and loopback capture verified.
- Lab 1: HTTP credentials captured; HTTPS configured with nginx; direct port
  8080 removed while HTTPS was active; credentials not readable in the HTTPS
  capture; local/GitHub certificate issuers compared; course Cleanup completed.
- Lab 2: course dictionary attack run; Argon2 added with login-time migration;
  Alice's changed storage checked; second login verified; guessing rates and
  per-day estimates calculated.
- 43 application/unit checks previously passed, including the five new
  password checks using disposable PostgreSQL tables.
- The existing 60 encrypted note comments and their recovered-data digest were
  preserved.
- Optional exercises were not required and were not performed.

## Recorded predictions and judgments

- HTTPS capture: password should not be directly readable.
- MD5 attack: predicted 6/6 in approximately 100 ms; measured 4/6 in 1.0 ms.
- Alice migration: predicted that the stored password had changed to a hash;
  confirmed `$argon2id$...` after login.
- Speed: predicted Argon2 would be 3 times slower; measured approximately
  94,647 times slower in the course benchmark.
- Both exposure findings were judged High with reasons recorded in the sheets.

The implementation and evidence collection were assisted by automation, which
the course permits. The predictions above were supplied by the user before the
corresponding result was checked. Severity choices were supplied by the user
after reviewing the findings; the certificate-trust explanation was assisted
after the user's initial answer.

## Local state and exclusions

Current entrance: <http://localhost:8080>, following Lab 1 Cleanup and Lab 2.
The required HTTPS configuration, password-migration code and audit evidence are
included in this coursework update. Generate deployment-specific keys and the
lab certificate yourself using the root README; they are not repository files.

Private keys, AES/HMAC secrets, application session configuration, database
exports, caches, browser profiles, raw network captures and unrelated course
materials are not included in this submission. Only course accounts and simulated
data were used.

Sources: [course home](https://kristenpire.github.io/epita-security-labs/),
[Lab 0](https://kristenpire.github.io/epita-security-labs/class5/setup/),
[Lab 1](https://kristenpire.github.io/epita-security-labs/class5/https-lab/),
[Lab 2](https://kristenpire.github.io/epita-security-labs/class5/password-audit/).
