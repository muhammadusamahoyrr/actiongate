# ActionGate — Embedded PostgreSQL Plan (v5)

> **Goal:** remove the Docker dependency so a fresh Windows machine, with no
> developer tooling and no network access, installs ActionGate and gets a real,
> persistent, tamper-evident PostgreSQL cluster managed entirely by the
> `actiongate` binary. "No administrator knowledge of PostgreSQL is required at
> any point" is the entire point of embedded mode.

## Changelog v4 → v5 (the reviewed changes)

These are the deltas from v4; the rest of the document is v4 carried forward and
folded in.

1. **SQLite is explicitly ruled out, with the real reason.** `go.mod` pins
   `github.com/riverqueue/river` on the `riverpgxv5` driver. River is
   PostgreSQL-only; SQLite would mean rewriting the approval/job queue and
   forking `verify` into two backends. Same-engine-both-sides is what makes the
   parity NFR nearly free. **Postgres stays.**
2. **Init order corrected for River's own schema.**
   `initdb → goose (app schema) → river migrate → tenant → keys → seal epoch 0`.
   v4 omitted River's migrations.
3. **Version aligned to PostgreSQL 18 across ALL deployment modes.** Docker and
   CI are on `postgres:16-alpine` today; embedded was pinned to `18.3.0` in
   isolation, which would make the byte-identical-`verify` parity test compare
   two different majors. **Bump Docker + CI to 18 as well.** Pin the exact patch
   `18.3.0` and verify the vendored binary source publishes it for all three
   platforms before pinning.
4. **Determinism via the builtin locale provider.** Every `initdb` uses
   `--locale-provider=builtin --builtin-locale=C.UTF-8` (PG17+). Identical
   collation/case semantics on every platform within a major — the ideal setting
   for the cross-platform parity NFR, and faster besides.
5. **Local DB access control (new, V1-blocking).** `initdb` defaults local auth
   to `trust`; a security product cannot ship that. Hardened at init: bind
   `127.0.0.1` only, random free high port persisted to `dev.json`,
   `scram-sha-256`, random 32-byte password, `pg_hba.conf` with no `trust` line,
   and restrictive ACLs on `pgdata\`.
6. **Durability asserted, not assumed (V1-blocking).** `fsync`,
   `synchronous_commit`, `full_page_writes` stay `on`; the health check refuses
   to start if `fsync=off`. The "survives a power-cord pull" DoD is otherwise
   unenforceable.
7. **Windows blue-green swap uses a directory junction, not a tree rename.**
   `MoveFileEx` is atomic only for files and fails under AV/indexer handle
   contention. `DataPath` becomes a junction flipped between `pgdata_A` /
   `pgdata_B`; all rename/junction ops retry-with-backoff on
   `ERROR_SHARING_VIOLATION`, `MOVEFILE_DELAY_UNTIL_REBOOT` as last resort.
8. **`pg_ctl stop -m fast` is the strong default.** `-m immediate` skips the
   checkpoint and forces WAL crash recovery on next boot — it manufactures the
   exact Step-4 disaster we guard against. Immediate is a bounded last resort,
   logged loudly.
9. **Developer Edition never uses `pg_upgrade`.** `pg_upgrade` needs two major
   binary sets bundled at once. Major upgrades use the same dump→restore-into-
   new-dir path as backups, reusing the Step 7 staging-verify-swap discipline.

---

## Step 1 — Confirm basics
- Confirm the PostgreSQL License permits redistributing binaries; keep a copy in
  `docs/legal/`.
- Pin an **exact patch version — `18.3.0`** (not a floating `18.3.x`) so every
  developer and CI run tests the identical binary. Bump deliberately on security
  fixes; record the new pinned version explicitly. **Confirm the vendored binary
  source ships 18.3.0 for Windows amd64, macOS arm64+x64, Linux amd64 before
  pinning.**
- **Align Docker + CI to PostgreSQL 18 too** so embedded and Docker modes are the
  same major (parity NFR).
- Target platforms: Windows amd64, macOS arm64+x64, Linux amd64.

## Step 2 — Abstraction layer
**`DatabaseRuntime`** — runs and manages the embedded Postgres process only.
Knows nothing about the audit chain.
```go
type DatabaseRuntime interface {
    Start(ctx context.Context) error
    Stop(ctx context.Context, mode ShutdownMode) error
    Health(ctx context.Context) (HealthReport, error)
    Backup(ctx context.Context, path string) error   // V1 scope: see Step 7
    Restore(ctx context.Context, path string) error  // into a NEW location — see Step 7
    DSN() string                                      // how callers connect
}

type ShutdownMode int
const (
    ShutdownFast      ShutdownMode = iota // pg_ctl stop -m fast (default)
    ShutdownImmediate                     // bounded last resort; logs loudly
)

type ComponentHealth struct {
    Healthy bool
    Message string   // e.g. "migration 17 missing" — not just false
}

type HealthReport struct {
    Version  string   // ActionGate binary version — first question support always asks
    Database ComponentHealth
    Schema   ComponentHealth
    Tenant   ComponentHealth
    Keys     ComponentHealth
    Sealer   ComponentHealth
}
```
`HealthReport`'s explicit, message-carrying fields power `/healthz` and
`actiongate doctor` directly. "Schema: ✖ migration 17 missing" is diagnosable
from the output alone; "Schema: ✖ false" is not.

Audit-chain concerns (`Checkpoint{SealedEpochID, RootHash}`,
`CurrentCheckpoint()`, `Verify()`) stay entirely in the existing verifier
package. `DatabaseRuntime` and the verifier never reference each other directly —
orchestration in `cmd/actiongate` calls both.

**Build note (from research):** the `fergusstrange/embedded-postgres` ecosystem
gives us proven per-platform binary sourcing (`BinariesPath` = no download when
`bin/` is pre-vendored; `RuntimePath` = ephemeral, recreated each start;
`DataPath` = persistent — exactly our Step 3 layout). But that library targets
*ephemeral test* databases and its `Start/Stop` is thinner than Steps 4–6 need.
**Borrow its binary layer; own the lifecycle** (`initdb`/`pg_ctl`/`postgres`
wrapper) so we control crash-recovery classification, advisory-lock migrations,
drain-then-fast-stop, and health probing. M1 may start on the library and
refactor the lifecycle down in a later milestone.

## Step 3 — Storage layout
```
%APPDATA%\actiongate\
  ├── dev.json          (adds: db_port, db_password)
  ├── pgdata\           (PERSISTENT — a junction to pgdata_A or pgdata_B)
  ├── pgruntime\        (EPHEMERAL — extracted binaries, recreated each Start)
  └── backups\
```
- `DataPath` frozen after install; relocation only via
  `actiongate storage migrate <newpath>` (verify current backup → copy → verify
  copy independently → atomic switch). **Failed verification at any step →
  abort, leave the original `DataPath` completely untouched, report failure.** No
  partial migration state is ever left live.
- First test (Milestone 1): start → write a row → stop → start → assert row
  exists.

## Step 4 — Cluster detection (with binary/schema compatibility check)
```
Does pgdata\PG_VERSION exist?
  NO  → Fresh install. Clean partial contents. initdb (hardened; Step 5)
        → goose (app schema) → river migrate → tenant → keys → seal epoch 0.
  YES → Read stored schema version AND the minimum-compatible-binary-version
        recorded in the metadata table.
        Current ActionGate binary version >= recorded minimum?
          NO  → Refuse to start. "This database requires ActionGate vX.Y+."
          YES → Schema matches expected goose version?
                YES → Continue.
                Older, recognized → acquire pg_advisory_lock immediately before
                  running migrations; release via defer on ALL paths (a panic
                  mid-migration must not leak the lock and deadlock every future
                  start). Prevents two instances racing migrations during a
                  rolling restart. Fail partway → roll back, fail loudly.
                Unrecognized/corrupted → FAIL LOUDLY → Disaster Recovery.
```
Goose version alone only proves schema shape; the binary-version check proves the
running binary knows how to safely operate on it. Both are required.

## Step 5 — Startup sequence (hardened)
```
1. Step 4 cluster detection.
2. On FRESH init, the initdb is hardened:
   - --locale-provider=builtin --builtin-locale=C.UTF-8 --encoding=UTF8
   - listen_addresses = '127.0.0.1'   (never '*'; Windows has no unix sockets)
   - a random free high port, probed at init, persisted to dev.json.db_port
   - password_encryption = scram-sha-256
   - a random 32-byte password, persisted to dev.json.db_password (0600)
   - pg_hba.conf: every 'trust' replaced with
       host actiongate ag 127.0.0.1/32 scram-sha-256
       host actiongate ag ::1/128      scram-sha-256
   - Windows: icacls pgdata\ to service account + Admins only.
3. DatabaseRuntime.Start().
   - If Postgres reports crash-recovery FAILURE (not "no cluster found", but
     "found a cluster, WAL replay could not complete") → STOP. Never fall
     through to initdb. Point the operator to `actiongate restore`.
4. Durability guard: SHOW fsync — refuse to start if it is 'off'
   (also assert synchronous_commit, full_page_writes are on).
5. Composite health check (configurable timeout, default 90s, minimum 30s —
   corporate machines with real-time AV scanning every extracted file are
   meaningfully slower), progress shown every few seconds; checks all
   HealthReport fields.
6. All pass → start control plane.
7. Then → start the Sealer (its own health reflected back into HealthReport for
   ongoing /healthz monitoring).
```

## Step 6 — Shutdown sequence
```
1. Drain new gateway requests.
2. Stop new approvals from being created.
3. Let the Sealer finish its current in-flight batch.
4. Flush structured logs (Step 12).
5. pg_ctl stop -m fast   (DEFAULT — clean checkpoint, warm next start).
   -m immediate only as a bounded-timeout last resort, logged loudly, because
   the next start then pays for WAL crash recovery.
```

## Step 7 — Backup / Restore (scope and safety made explicit)
- **Developer Edition uses logical backups (`pg_dump`)** — portable,
  deterministic, simple. An intentional tier choice, not a limitation.
  Team/Enterprise editions may use physical backups (`pg_basebackup`/pgBackRest)
  once audit histories reach the millions-of-events range where `pg_dump` restore
  time becomes impractical. Written down now so it isn't rediscovered as a
  surprise.
- Every backup records: **ActionGate version, PostgreSQL version,
  schema/migration version, timestamp, backup type (`logical`), tenant ID.**
  Before restoring, compare the recorded ActionGate version against the running
  binary; warn explicitly if the backup predates a version the current binary no
  longer restores cleanly.
- **Optional, not required for V1:** AES-256 password-protected backup
  encryption. Documented now because backups land in Dropbox/OneDrive the user
  doesn't fully control, and an unencrypted audit-history dump in cloud storage is
  a real exposure.
- Orchestration (`cmd/actiongate`, not inside `DatabaseRuntime`):
```
backup:
  checkpoint := verifier.CurrentCheckpoint()
  runtime.Backup(path)               // pg_dump
  write checkpoint alongside the backup

restore:
  runtime.Restore(path) INTO A STAGING DataPath — never the live one
  result := verifier.Verify(fromRecordedCheckpoint)  // chain + signatures +
                                                     // epoch ordering + root hash
  FAIL on any mismatch → staging discarded, live cluster untouched
  PASS → atomically swap staging into place (Step 9's junction-flip pattern)
```
Restore never replaces the live cluster directly — staging, verify, then swap.

## Step 8 — Crash recovery testing
1. Postgres-level: kill mid-write, restart, confirm WAL crash recovery + correct
   Step 4 classification.
2. Whole-workflow-level: power loss during pending approval/River job/grant →
   reconciliation sweep resolves correctly.
3. Real-world reboot: Windows Update-style auto-reboot; service self-recovers to
   full health.

## Step 9 — Packaging (Windows-realistic blue-green via junction)
`MoveFileEx` is atomic **only for files** (`MOVEFILE_REPLACE_EXISTING |
MOVEFILE_WRITE_THROUGH`, same volume) and fails with `ERROR_SHARING_VIOLATION`
when AV/Search-Indexer holds a handle after service stop. You cannot atomically
replace a populated directory this way. Solution:
```
1. Install new version to a separate, parallel location.
2. Verify the new install independently — ALL four of:
   - binary checksum matches the signed release manifest
   - the executable actually launches
   - embedded PostgreSQL starts successfully
   - the full Step 5 health check passes
   Any one failing means "verify" failed — none is optional.
3. Stop the running service.
4. SWAP via directory junction: DataPath is a junction pointing at pgdata_A or
   pgdata_B; the swap deletes+recreates the junction (one tiny fs op, both trees
   retained for instant rollback). Every rename/junction op retries with backoff
   on ERROR_SHARING_VIOLATION / ERROR_ACCESS_DENIED; MOVEFILE_DELAY_UNTIL_REBOOT
   is the documented last resort.
5. Start the new service.
6. Startup/health check fails → automatic rollback (re-flip the junction) and
   restart on the previous install.
```
- **Installer never downloads anything at any point. Offline install is fully
  supported** — every binary is pre-bundled (`BinariesPath`, no runtime fetch). A
  real selling point for security-conscious and corporate-locked-down users.

## Step 10 — Upgrade strategy (unreachable-by-accident API)
`prepareUpgrade`/`performUpgrade`/`verifyUpgrade`/`commitUpgrade` are **unexported
functions inside an internal upgrade package**, with exactly one exported
entrypoint used only by the CLI:
```go
// internal/upgrade/upgrade.go
package upgrade
func Run(opts Options) error // the ONLY exported symbol; called only from
                              // cmd/actiongate's "cluster upgrade" command
// internally, in strict order:
//   prepareUpgrade()  → produces a verified backup first
//   performUpgrade()  → Developer Edition: dump/restore INTO A NEW data
//                        directory (NOT pg_upgrade — that needs two major
//                        binary sets bundled; the old dir is untouched)
//   verifyUpgrade()   → full verify() against the pre-upgrade checkpoint +
//                        Step 5 health check against the NEW dir. No switch yet.
//   commitUpgrade()   → only now, junction-flip the active cluster to the new dir
```
Splitting `verifyUpgrade` from `commitUpgrade` keeps "verified" and "live"
distinct. Go's compiler enforces that no other package calls the steps.
`UpgradeSchema()` (ActionGate's own goose migrations) stays separate and automatic
on service start, per Step 4.

## Step 11 — Disaster Recovery
```
1. Restore latest backup via Step 7's staging-then-verify-then-swap flow.
2. Full verify() must pass against the recorded checkpoint.
3. Resume service only after verify passes.
4. NEVER auto-recreate a fresh tenant as a fallback.
```

## Step 12 — Structured Logging
JSON-structured logs throughout. Any startup-failure log entry must always
include: embedded Postgres version, cluster path, current schema/migration
version, and exactly which `HealthReport` component failed. Turns "it doesn't
work" into something diagnosable from one log line.

## Step 13 — `actiongate doctor`
One command, human-readable, checks everything end to end:
```
$ actiongate doctor
✔ Database
✔ Service
✔ Policies
✔ Hooks
✔ Verify
✔ Signing keys
✔ Sealer
✔ Embedded PostgreSQL
Everything healthy.
```
Reuses `HealthReport` plus policy/hook/verify checks already built elsewhere —
presentation over existing checks, not new logic.

## Step 14 — Failure Matrix (final)

| Failure | Expected behavior |
|---|---|
| No `pgdata/` or missing `PG_VERSION` | Initialize fresh cluster (hardened initdb) |
| `pgdata/` exists, schema unrecognized/corrupted | Fail loudly → Disaster Recovery |
| Binary version incompatible with stored schema | Refuse start, name the required version |
| Schema outdated but recognized | Run pending migrations (advisory-locked) |
| Migration fails partway | Roll back, fail loudly |
| **Cluster found but WAL recovery fails to complete** | STOP — never fall through to initdb. Direct to `actiongate restore`. |
| `fsync=off` detected at startup | Refuse to start (durability guard) |
| DB port already in use | Probe next free port at init; persisted port reused thereafter |
| Disk full during normal write | Read-only error, surfaced clearly |
| Disk full during WAL replay at startup | Refuse to loop; surface "free disk space or restore from backup." Never auto-`pg_resetwal`. |
| Permission denied on DataPath | Explain the exact fix |
| Power loss during idle | WAL crash recovery, automatic |
| Power loss during pending approval/River job/grant | Reconciliation sweep → correct terminal state |
| Clock jumps backwards | Audit chain unaffected — ordering is by sealed sequence number |
| Corrupted signing keys | Fail closed |
| Installer interrupted mid-extraction | Existing working install untouched (blue-green junction) |
| Postgres subprocess won't start | Structured log names the exact failing component |
| Backup corrupted / checkpoint mismatch on restore | Refuse restore, staging discarded, live cluster untouched |
| Backup process interrupted before completion | Marked incomplete at write time; **never offered as a restore candidate** |

## Storage Requirements
- **Minimum**: 2 GB free disk.
- **Recommended**: SSD, 10 GB free.
- **Post-V1 note:** the audit log is append-only (rows can't be deleted without
  breaking the chain), so it grows unbounded. A future epoch-archival story (seal
  + export cold epochs, keep recent hot) is required before long-lived installs
  hit the floor.

## Performance Targets (measured on a defined reference machine — targets, not guarantees)
- **Warm restart** (existing `pgdata`, clean `-m fast` prior shutdown): startup to
  healthy **< 5 seconds**.
- **Cold fresh-install** (`initdb` + tenant + keys): bounded by the Step 5 timeout
  (default 90s), not the 5s warm target — genuinely different operations, different
  budgets; don't let one become the other's SLO.
- **Fast-path decision latency** (allow/deny, excluding human-approval wait):
  **< 250ms**.
- **Verify scaling** — no unbenchmarked number claimed. Target: **`verify` scales
  linearly with audit history and stays practical for typical developer
  workloads.** Publish a real number only once measured.

## Disaster Recovery — official workflow (named commands)
The documented, supported recovery path is exactly three commands, in order:
`actiongate restore` → `actiongate verify` → `actiongate doctor`. Nothing else is
an official recovery path — this goes in `docs/recovery.md`, referenced from every
"FAIL LOUDLY" branch in Step 4 and Step 14.

## Non-Functional Requirement + CI enforcement
**Every embedded-PostgreSQL release must produce identical `verify` output to the
Docker/PostgreSQL deployment, for the same audit history.** Enforced in CI: run
the full integration suite twice — once against Docker Postgres, once against
embedded — same audit-history fixture, assert byte-identical `verify` results. A
mismatch fails the build. **Both sides must be the same major (PG18)**, and the
lifecycle/parity tests must run **per-OS** (Windows service-stop semantics ≠
SIGTERM), not on Linux CI alone.

## Definition of Done
Fresh Windows machine. No developer tooling installed. Install ActionGate using
the signed installer — no network access required. The embedded PostgreSQL cluster
initializes automatically, survives reboot (manual power-cord pull and a real
OS-triggered auto-reboot), preserves tenant state and audit history, passes full
verification, and Claude Code can be protected with a single command.
`actiongate doctor` reports everything healthy. **No administrator knowledge of
PostgreSQL is required at any point.**
