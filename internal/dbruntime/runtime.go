// Package dbruntime runs and manages ActionGate's embedded PostgreSQL cluster.
//
// It knows nothing about the audit chain: DatabaseRuntime manages the Postgres
// process and reports health only. Audit-chain concerns (checkpoints, Verify)
// live in the verifier package; orchestration in cmd/actiongate calls both.
//
// See docs/embedded-postgres-plan.md (Step 2) for the design and
// docs/embedded-postgres-milestones.md for the milestone this file lands in
// (M1: interface, embedded startup, persistent DataPath, health reporting).
package dbruntime

import "context"

// ShutdownMode selects how the cluster is stopped.
type ShutdownMode int

const (
	// ShutdownFast maps to `pg_ctl stop -m fast`: a clean checkpoint so the
	// next start is a warm start with no WAL crash recovery. The default.
	ShutdownFast ShutdownMode = iota
	// ShutdownImmediate is a bounded last resort. It skips the checkpoint and
	// forces WAL crash recovery on the next start, so it is logged loudly.
	//
	// M1 note: the embedded library exposes only a graceful stop, so this mode
	// currently behaves like ShutdownFast. M4 wires the real pg_ctl modes.
	ShutdownImmediate
)

// ComponentHealth is the health of one subsystem. Message carries a diagnostic
// even when Healthy is true ("ok") so that "Schema: ✖ migration 17 missing" is
// actionable from the output alone.
type ComponentHealth struct {
	Healthy bool
	Message string
}

// HealthReport is the composite health of the runtime. Its explicit,
// message-carrying fields power /healthz and `actiongate doctor` directly.
//
// M1 populates Version and Database. Schema/Tenant/Keys/Sealer are filled in by
// later milestones (M3, M5) and report an empty, unhealthy component until then.
type HealthReport struct {
	Version  string // ActionGate binary version — the first thing support asks
	Database ComponentHealth
	Schema   ComponentHealth
	Tenant   ComponentHealth
	Keys     ComponentHealth
	Sealer   ComponentHealth
}

// DatabaseRuntime manages the embedded Postgres process lifecycle.
type DatabaseRuntime interface {
	// Start brings the cluster up, initializing a fresh one only if DataPath
	// holds no existing cluster.
	Start(ctx context.Context) error
	// Stop shuts the cluster down using the given mode.
	Stop(ctx context.Context, mode ShutdownMode) error
	// Health probes the running cluster. A down or unreachable database is
	// reported through the returned HealthReport (Database.Healthy == false with
	// a message), not as an error; err is non-nil only for unexpected failures.
	Health(ctx context.Context) (HealthReport, error)
	// DSN is the connection string callers use to reach the cluster.
	DSN() string
}
