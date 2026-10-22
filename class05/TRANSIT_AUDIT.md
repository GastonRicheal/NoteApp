# NOTESAPP TRANSIT AUDIT

**Pair:** ZHANG FANGYUCHEN and LYU SONGYUAN

**Date:** 22 October 2026

**Scope:** Our own NotesApp clone and our own loopback traffic.

## FINDING 1 — login over plain HTTP

- **Exposed:** The username and password in clear text.
- **Evidence:** The captured HTTP request body contains the exact line
  `username=alice&password=alicepw`.
  [Before screenshot](evidence/http-before.png). The actual screenshot is cropped
  immediately after the request body to omit the response/session cookie;
  retained request pixels are unchanged.
- **Who reads it:** An attacker able to observe the unencrypted client/server
  traffic.
- **Severity:** High, because intercepted credentials let an attacker impersonate
  the user and access their personal information.
- **Fix:** Put an nginx TLS reverse proxy in front of NotesApp and remove the
  published Flask HTTP port (`8080`).

## FIX VERIFIED — re-captured under HTTPS

**Password readable? No.** We repeated the login as `alice` over HTTPS and
captured 86 loopback packets. TLS application data was present, but no HTTP
packets were decoded and no clear-text login credentials were found in any of
the four TCP streams, without TLS session keys.
[After screenshot](evidence/https-after.png).

nginx configuration validation passed; the HTTPS login succeeded; the HTTPS
health endpoint returned 200; and the old `localhost:8080` entrance refused
connections while the HTTPS configuration was active.

## FINDING 2 — certificate trust

- **GitHub issued by:** Sectigo Public Server Authentication CA DV E36.
- **Our localhost certificate issued by:** localhost.
- **Trust ours lacks:** A valid certificate chain to a CA trusted by the browser.
- **Verdict:** Encryption protects data in transit, but it does not by itself
  prove the server's identity; our self-signed certificate has no trusted CA
  vouching for it.

[Actual certificate comparison](evidence/certificate-comparison.json). GitHub
loaded with normal certificate verification; the local lab certificate required
bypassing certificate errors.

## STATE

NotesApp was served over HTTPS with the lab self-signed certificate, and the fix
was verified. We then performed the course's **Cleanup**: removed the HTTPS
stack and restored `http://localhost:8080` for Lab 2, preserving the database.
The HTTPS configuration and original capture remain locally available.

**Requirement source:** [Lab 1 — Traffic-in-transit audit](https://kristenpire.github.io/epita-security-labs/class5/https-lab/).
