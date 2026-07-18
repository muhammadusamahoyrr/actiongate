---
name: tamper-demo
description: Prove the actiongate audit log is tamper-evident (safe, runs on a throwaway database)
---

Run `actiongate tamper-demo` and walk the user through the output:

- ACT 1 seals real audit events into a signed epoch and verifies them (`ok:true`).
- ACT 2 plays a malicious DBA: the append-only trigger is disabled and an approval event is rewritten — the database accepts it.
- ACT 3 re-verifies from raw rows and public keys only: `ok:false`, naming the exact tampered event.

Emphasize: this runs on a scratch database that is dropped afterwards; the user's real audit chain is never touched. The same `verify` binary works on their real chain any time.
