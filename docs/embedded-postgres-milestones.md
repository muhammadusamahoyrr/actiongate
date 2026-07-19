# Embedded PostgreSQL — Milestones

Small, independently shippable slices of [embedded-postgres-plan.md](embedded-postgres-plan.md).
Each milestone lands `gofmt`-clean, `go vet` 0, and green tests before the next
starts. "V1-blocking" milestones must be done before embedded mode is offered to
users; the rest are hardening and can ship incrementally.

Legend: **AC** = acceptance criteria, **T** = tests.

---

## M1 — DatabaseRuntime + embedded startup + persistence  ← current
Prove we can run a real, persistent embedded Postgres managed by our own code.

**Scope**
- `internal/dbruntime` package: `DatabaseRuntime` interface, `HealthReport`,
  `ComponentHealth`, `ShutdownMode` (Step 2).
- Embedded runtime with **persistent `DataPath`** + ephemeral runtime dir; binary
  sourced via `fergusstrange/embedded-postgres` (lifecycle owned by us; refined in
  M4).
- `Start` / `Stop(mode)` / `Health` / `DSN`.
- Basic `HealthReport`: `Database` (can we `SELECT 1`) + `Version`.

**AC**
- A caller can `Start` a runtime pointed at a fresh empty dir; a Postgres process
  comes up and accepts connections on the DSN.
- After `Stop(ShutdownFast)` and a second `Start` on the *same* `DataPath`, data
  written before the stop is still present.
- `Health` returns `Database.Healthy == true` when up, and a non-empty
  `Message` when the DB is unreachable.
- No Docker involved anywhere in the path.

**T**
- `TestPersistence`: start → `CREATE TABLE`/`INSERT` a row → `Stop` → `Start` →
  `SELECT` returns the row. (The Step 3 "first test".)
- `TestHealthReportsDownState`: `Health` on a stopped runtime yields
  `Database.Healthy == false` with a diagnostic message.
- `TestSecondStartNoReinit`: starting on an existing `DataPath` does **not**
  re-`initdb` (row from a prior run still there; `PG_VERSION` untouched).

---

## M2 — Hardened init: access control + durability  (V1-blocking)
Make the embedded cluster safe to run on a shared machine.

**Scope (Step 5)**
- Free port probed by the runtime when `Port == 0`, exposed via `Port()`; the
  caller persists it to `dev.json.db_port` (persistence is M8 integration).
- `listen_addresses='localhost'` (loopback v4+v6 only — avoids the
  127.0.0.1-vs-::1 resolution mismatch the library's own `host=localhost`
  connections hit; still not externally reachable).
- `pg_hba.conf` rewritten to `scram-sha-256` for `local` / `127.0.0.1/32` /
  `::1/128` — no `trust`, upgrading the library's default `password` auth to
  challenge-response. Password is already SCRAM-hashed at init (PG18 default).
- `GeneratePassword()` helper for callers; the runtime takes the password as
  input so it stays stable across restarts of a persistent `DataPath`.
- Durability guard: after start, `SHOW fsync` / `synchronous_commit` /
  `full_page_writes` — refuse to run (stop + error) if any is not `on`.
- POSIX: `chmod 0700` on `pgdata`. **Windows `icacls` lock-down moved to M4**:
  initdb already restricts the dir to the owning user, and applying
  `icacls /inheritance:r` post-init locks our own process out of `pg_hba.conf`.
  Proper SID-based ACLs belong with owned initdb (before population).

**Moved to M4** (needs owned `initdb`, which the library couples inside
`Start()`): `--locale-provider=builtin --builtin-locale=C.UTF-8`. It's a
determinism/parity concern (validated at M8), not access-control/durability, so
it belongs with lifecycle ownership.

**AC**
- A connection attempt with no/wrong password is rejected (no `trust`).
- `Port == 0` yields a working cluster on a probed free port; two concurrent
  `Port == 0` runtimes come up on different ports.
- Startup aborts with a clear error if `fsync=off` is forced via params.
- After start, `pg_hba.conf` contains only `scram-sha-256` methods.

**T**
- `TestRejectsUnauthenticated`, `TestProbesFreePortNoCollision`,
  `TestFsyncOffRefused`, `TestHardenedPgHBA`.

---

## M3 — Cluster detection + migrations + init order  (V1-blocking)
Correctly classify an existing cluster and bring schema up safely.

**Scope (Steps 4)**
- `PG_VERSION` presence check; fresh vs existing.
- Init order: `initdb → goose → river migrate → tenant → keys → seal epoch 0`.
- Metadata table records schema version + minimum-compatible binary version.
- Binary-too-old → refuse with the required version named.
- Migrations run under `pg_advisory_lock`, released via `defer` on all paths.
- **WAL-recovery-failed ≠ no-cluster:** never fall through to `initdb`; direct to
  restore.

**AC / T**
- `TestFreshInitFullOrder` (river schema + tenant + epoch 0 all present).
- `TestOldBinaryRefused`, `TestAdvisoryLockSerializesMigrations`,
  `TestCorruptClusterFailsLoud`.

---

## M4 — Lifecycle ownership + graceful shutdown  (hardening)
Replace library Start/Stop with our own `pg_ctl` wrapper.

**Scope (Step 5, 6)** — own `initdb`/`pg_ctl` over the library's extracted
binaries. Adds `--locale-provider=builtin --builtin-locale=C.UTF-8` (moved from
M2 — needs owned initdb). Graceful shutdown: drain → stop approvals → let sealer
finish → flush logs → `pg_ctl stop -m fast`; `-m immediate` only at bounded
deadline, logged loudly.

**AC / T** — `TestBuiltinLocale` (provider/collation reflect builtin C.UTF-8),
`TestFastStopWarmRestart` (clean stop → next start needs no crash recovery, < 5s),
`TestImmediateStopLogsAndRecovers`.

---

## M5 — HealthReport completeness + `/healthz` + `actiongate doctor`  (hardening)
**Scope (Steps 2, 13)** — fill Schema/Tenant/Keys/Sealer components; wire
`/healthz`; add `actiongate doctor`. (Also diagnoses today's "service RUNNING but
control plane not answering" state.)

**AC / T** — `TestDoctorAllHealthy`, `TestDoctorNamesFailingComponent`,
`TestHealthzReflectsSealer`.

---

## M6 — Backup / Restore (logical) + Disaster Recovery  (V1-blocking for GA)
**Scope (Steps 7, 11)** — `pg_dump` backup with metadata + checkpoint sidecar;
restore into staging → `verify()` → junction-swap; refuse on mismatch, live
untouched; incomplete backups never offered.

**AC / T** — `TestBackupRestoreRoundTrip`, `TestRestoreRejectsTamperedDump`,
`TestIncompleteBackupNotOffered`.

---

## M7 — Packaging / blue-green / upgrade  (hardening)
**Scope (Steps 9, 10)** — junction-based install swap with retry-on-sharing-
violation; `internal/upgrade` with the four-phase unexported API; dump/restore
upgrades (no `pg_upgrade`).

**AC / T** — `TestJunctionSwapRollback`, `TestUpgradeVerifyBeforeCommit`,
`TestSwapRetriesOnSharingViolation` (Windows).

---

## M8 — Integration: replace Docker in `up.go` + CI parity  (V1-blocking for GA)
**Scope (Step 1, NFR)** — `actiongate up` uses embedded runtime instead of
`docker run postgres:16-alpine`; bump Docker/CI to PG18; CI runs the integration
suite twice (Docker + embedded) and asserts **byte-identical `verify`**, per-OS.

**AC / T** — `TestVerifyParityDockerVsEmbedded`, green `actiongate up` on a clean
machine with no Docker.

---

## Sequencing
`M1 → M2 → M3` are the critical path to a safe embedded cluster. `M4/M5` harden
oper/support. `M6` unlocks recovery. `M7` unlocks shipping upgrades. `M8` flips
the default and locks parity. V1-blocking: M1, M2, M3, M8 (+ M6 for GA).
