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

**Scope (Step 4)** — generic, audit-chain-agnostic primitives in `dbruntime`;
the real goose/river/tenant/keys/seal are **injected** so `dbruntime` keeps no
control-plane dependency (real wiring lands at M8):
- `ClassifyCluster` — `PG_VERSION` presence → fresh vs existing.
- `Initialize(dsn, binaryVersion, minBinaryVersion, InitSteps)` runs the ordered
  bootstrap: ensure meta → (if existing) binary-compat gate → `MigrateSchema` →
  (if fresh) `Provision` → record min binary version. `InitSteps{MigrateSchema,
  Provision}` are the injected goose+river / tenant+keys+seal steps.
- `actiongate_meta` records the minimum-compatible binary version (schema version
  itself stays in goose's `goose_db_version`). Binary-too-old → refuse, naming the
  required version, before any migration.
- `WithMigrationLock` — `pg_advisory_lock`, released via `defer` on all paths
  (incl. ctx cancel / panic).
- **WAL-recovery-failed ≠ no-cluster:** `Start` on an existing cluster that won't
  boot returns `*ClusterError` (→ `actiongate restore`); never reinitializes.

**AC / T** (order/gate proven with injected fakes; real presence of
tenant/epoch-0 is an M8 integration test)
- `TestClassifyCluster`, `TestFreshInitFullOrder` (migrate→provision on fresh;
  migrate-only on re-run), `TestOldBinaryRefused` (refused before migrating),
  `TestAdvisoryLockSerializesMigrations` (max 1 concurrent holder),
  `TestCorruptClusterFailsLoud` (`*ClusterError`, `PG_VERSION` intact).

---

## M4 — Lifecycle ownership + graceful shutdown  (hardening)  ✅ done
Replace library Start/Stop with our own `initdb`/`pg_ctl` wrapper.

**Scope (Step 5, 6)** — own `initdb`/`pg_ctl` over binaries the library extracts
once (a throwaway "prime" into a shared `BinariesPath`; offline after cache).
`initdb` now applies `-A scram-sha-256 --encoding=UTF8 --locale-provider=builtin
--builtin-locale=C.UTF-8`; we create the app DB and write strict `pg_hba` before
first boot. `pg_ctl start -w -l <log>` boots; `pg_ctl stop -w -m fast|immediate`
stops (immediate logged loudly). The step-6 drain/sealer sequencing is
orchestration and lands with M5/M8; the DB-process half is here.

**Windows gotchas hit (recorded so they aren't relearned):**
1. `pg_ctl start` with a pipe (`MultiWriter`) as stdio **deadlocks** — the
   long-lived `postgres` child inherits the pipe, never EOFs, `cmd.Run` hangs
   forever. Fix: `-l <logfile>` + null stdio for start; pipes are fine for
   short-lived `initdb`/`stop`.
2. `os.Stat("bin/pg_ctl")` never matches on Windows (file is `pg_ctl.exe`; unlike
   `exec`, `Stat` doesn't append `.exe`) → primed on every start and a second
   concurrent runtime hit "Access is denied" renaming a locked `postgres.exe`.
   Fix: OS-aware `exe()` suffix.
3. `datcollate` holds the libc `lc_*` (system cp1252), not the provider locale —
   assert `datlocprovider='b'` and `datlocale='C.UTF-8'`.

**Still deferred:** Windows `icacls` ACL lockdown (initdb already restricts pgdata
to the owner; SID-based ACLs are low-value vs. risk — revisit only if the service
account ever differs from the installer). The step-6 app-level drain (approvals /
sealer) belongs with M5/M8.

**AC / T** — `TestBuiltinLocale` (`datlocprovider='b'`, `datlocale='C.UTF-8'`),
`TestFastStopWarmRestart` (warm restart faster than cold, data intact — the <5s
figure is a reference-machine target, not a portable test bound),
`TestImmediateStopLogsAndRecovers` (loud log + WAL recovery restores data).

---

## M5 — HealthReport completeness + `/healthz` + `actiongate doctor`  (hardening)  ✅ done
**Scope (Steps 2, 13)** — new `internal/health` package composes a full
`dbruntime.HealthReport` over a `*pgxpool.Pool` (audit-chain-aware, so it lives
outside `dbruntime`): Database (ping), Schema (`goose_db_version`), Tenant
(`configuration_snapshots`, RLS-correct via `app.tenant_id`), Signing keys (every
sealed epoch's `key_id` is in the configured set), Sealer (`audit_epochs`
progression vs `audit_events`). `actiongate doctor` renders ✔/✖ lines from it plus
a live control-plane `/healthz` probe and exits non-zero if unhealthy.
`handleHealthz` now returns the per-component body while keeping the HTTP status
**database-driven** (200 live / 503 down) so existing liveness probes (`up`,
`ag-hook`) keep their contract.

**Dogfooded:** `go run ./cmd/actiongate doctor` on this machine correctly
diagnosed the live "control plane not answering" state — root cause is **Docker
Desktop is off**, so the `actiongate-db` container (current docker-based DB) can't
run and the whole chain fails closed.

**AC / T** — `TestCheckAllHealthy` + `TestCheckNamesFailingComponent`
(health-package equivalents of the doctor all-healthy / named-failure ACs),
`TestCheckKeysUnknownKey`, `TestHealthzReflectsSealer`. All four run against the
**embedded runtime (no Docker)** — the `/healthz` test drives a minimal
`Server{Pool,EpochKeyIDs}` via `httptest` rather than the testcontainers
`servertest` harness, which is Docker-gated (daemon currently off).

---

## M6 — Backup / Restore (cold physical) + Disaster Recovery  (V1-blocking for GA)  ✅ core done
**Revised from logical → cold physical:** the bundled Zonky binaries have no
`pg_dump`/`pg_restore` (only initdb/pg_ctl/postgres), so Developer Edition backs
up with a crash-consistent gzip-`tar` of `pgdata` taken while **stopped** (stdlib
`archive/tar`, no extra binaries). See plan Step 7.

**Scope (Steps 7, 11)** — `dbruntime.Backup` (tar pgdata, refuses if running),
`Restore` (extract into a fresh DataPath; restored cluster keeps the source
credentials), `WriteBackup` (`.partial` → final rename + metadata sidecar so
interrupted backups are never restore candidates), `ListBackups` (only complete
ones, newest first). The restored cluster boots via the normal `Start`
(ClusterPresent) path.

**Deferred to orchestration (M8/GA):** wrapping backup with the audit-chain
`verify()` against a recorded checkpoint, the restore-into-staging→verify→junction-
swap-into-live flow (junction swap is M7), and the `actiongate backup/restore`
CLI. dbruntime provides the primitives; the audit-chain checkpoint stays out of
dbruntime by design.

**AC / T** — `TestBackupRestoreRoundTrip` (stop → backup → restore into fresh
cluster → data present), `TestRestoreRejectsCorruptBackup` (invalid archive
refused), `TestBackupRequiresStopped`, `TestIncompleteBackupNotOffered` (no PG).

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
