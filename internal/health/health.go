// Package health composes an end-to-end HealthReport for an ActionGate
// deployment from live database state. It fills the audit-chain-aware components
// (Schema/Tenant/Keys/Sealer) that dbruntime deliberately does not know about;
// dbruntime supplies only Database. `/healthz` and `actiongate doctor` render
// the result.
package health

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/muhammadusamahoyrr/actiongate/internal/dbruntime"
)

// Options parameterizes a health check.
type Options struct {
	// Version is the ActionGate binary version, surfaced in the report.
	Version string
	// TenantID scopes the tenant-aware checks and sets app.tenant_id so counts
	// are correct even under FORCE ROW LEVEL SECURITY. Optional.
	TenantID string
	// EpochKeyIDs are the signing key ids this deployment is configured with; the
	// Keys check flags any sealed epoch signed by a key not in this set.
	EpochKeyIDs []string
}

// Check runs every component check and returns the composite report. Database is
// checked first; if it is down the remaining components are reported unknown
// rather than emitting misleading errors.
func Check(ctx context.Context, pool *pgxpool.Pool, opts Options) dbruntime.HealthReport {
	rep := dbruntime.HealthReport{Version: opts.Version}

	rep.Database = checkDatabase(ctx, pool)
	if !rep.Database.Healthy {
		down := dbruntime.ComponentHealth{Healthy: false, Message: "not checked: database unavailable"}
		rep.Schema, rep.Tenant, rep.Keys, rep.Sealer = down, down, down, down
		return rep
	}

	rep.Schema = checkSchema(ctx, pool)
	rep.Tenant = checkTenant(ctx, pool, opts.TenantID)
	rep.Keys = checkKeys(ctx, pool, opts.TenantID, opts.EpochKeyIDs)
	rep.Sealer = checkSealer(ctx, pool, opts.TenantID)
	return rep
}

func checkDatabase(ctx context.Context, pool *pgxpool.Pool) dbruntime.ComponentHealth {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := pool.Ping(cctx); err != nil {
		return unhealthy("cannot reach database: %v", err)
	}
	return healthy("reachable")
}

func checkSchema(ctx context.Context, pool *pgxpool.Pool) dbruntime.ComponentHealth {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var version int64
	err := pool.QueryRow(cctx, `SELECT coalesce(max(version_id), 0) FROM goose_db_version`).Scan(&version)
	if err != nil {
		return unhealthy("migrations not applied (%v)", err)
	}
	if version == 0 {
		return unhealthy("no migrations applied")
	}
	return healthy("migrations at version %d", version)
}

func checkTenant(ctx context.Context, pool *pgxpool.Pool, tenantID string) dbruntime.ComponentHealth {
	var n int64
	err := withTenant(ctx, pool, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		q := `SELECT count(*) FROM configuration_snapshots`
		args := []any{}
		if tenantID != "" {
			q += ` WHERE tenant_id = $1`
			args = append(args, tenantID)
		}
		return tx.QueryRow(ctx, q, args...).Scan(&n)
	})
	if err != nil {
		return unhealthy("cannot read tenant state: %v", err)
	}
	if n == 0 {
		return unhealthy("no provisioned tenant (policy snapshot missing)")
	}
	return healthy("provisioned (%d policy snapshot(s))", n)
}

func checkKeys(ctx context.Context, pool *pgxpool.Pool, tenantID string, configured []string) dbruntime.ComponentHealth {
	known := make(map[string]bool, len(configured))
	for _, k := range configured {
		known[k] = true
	}
	var ids []string
	err := withTenant(ctx, pool, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		q := `SELECT DISTINCT key_id FROM audit_epochs`
		args := []any{}
		if tenantID != "" {
			q += ` WHERE tenant_id = $1`
			args = append(args, tenantID)
		}
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	if err != nil {
		return unhealthy("cannot read signing keys: %v", err)
	}
	for _, id := range ids {
		if !known[id] {
			return unhealthy("epoch signed by key %q not in the configured key set", id)
		}
	}
	if len(ids) == 0 {
		if len(configured) == 0 {
			return unhealthy("no signing keys configured")
		}
		return healthy("%d signing key(s) configured, no epochs sealed yet", len(configured))
	}
	return healthy("all sealed epochs signed by known keys (%d key id(s))", len(ids))
}

func checkSealer(ctx context.Context, pool *pgxpool.Pool, tenantID string) dbruntime.ComponentHealth {
	var epochs, events int64
	var latest *time.Time
	err := withTenant(ctx, pool, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ew, ev := "", ""
		args := []any{}
		if tenantID != "" {
			ew = ` WHERE tenant_id = $1`
			ev = ` WHERE tenant_id = $1`
			args = append(args, tenantID)
		}
		if err := tx.QueryRow(ctx, `SELECT count(*), max(sealed_at) FROM audit_epochs`+ew, args...).Scan(&epochs, &latest); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_events`+ev, args...).Scan(&events)
	})
	if err != nil {
		return unhealthy("cannot read sealer state: %v", err)
	}
	if epochs == 0 {
		if events == 0 {
			return healthy("no audit activity to seal yet")
		}
		return unhealthy("%d audit event(s) but no sealed epoch — sealer not progressing", events)
	}
	when := "unknown"
	if latest != nil {
		when = latest.UTC().Format(time.RFC3339)
	}
	return healthy("%d epoch(s) sealed, latest at %s", epochs, when)
}

// withTenant runs fn in a transaction, first setting app.tenant_id when a tenant
// is given so tenant-scoped tables read correctly under FORCE ROW LEVEL SECURITY.
func withTenant(ctx context.Context, pool *pgxpool.Pool, tenantID string, fn func(context.Context, pgx.Tx) error) error {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := pool.Begin(cctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(cctx) }()
	if tenantID != "" {
		if _, err := tx.Exec(cctx, `SELECT set_config('app.tenant_id', $1, true)`, tenantID); err != nil {
			return err
		}
	}
	if err := fn(cctx, tx); err != nil {
		return err
	}
	return tx.Commit(cctx)
}

func healthy(format string, a ...any) dbruntime.ComponentHealth {
	return dbruntime.ComponentHealth{Healthy: true, Message: fmt.Sprintf(format, a...)}
}

func unhealthy(format string, a ...any) dbruntime.ComponentHealth {
	return dbruntime.ComponentHealth{Healthy: false, Message: fmt.Sprintf(format, a...)}
}

// AllHealthy reports whether every component in a report is healthy.
func AllHealthy(rep dbruntime.HealthReport) bool {
	for _, c := range []dbruntime.ComponentHealth{rep.Database, rep.Schema, rep.Tenant, rep.Keys, rep.Sealer} {
		if !c.Healthy {
			return false
		}
	}
	return true
}
