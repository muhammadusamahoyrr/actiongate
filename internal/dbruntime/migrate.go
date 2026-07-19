package dbruntime

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// migrationAdvisoryLockKey is a stable 64-bit key ("AGMIGRAT") used to serialize
// ActionGate migrations across processes via pg_advisory_lock, so two instances
// racing during a rolling restart can't run migrations simultaneously.
const migrationAdvisoryLockKey int64 = 0x41474d4947524154

// WithMigrationLock acquires the session-level migration advisory lock, runs fn,
// and releases the lock on all paths (including panics and ctx cancellation). A
// second caller blocks until the first releases.
func WithMigrationLock(ctx context.Context, pool *pgxpool.Pool, fn func(context.Context) error) (err error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("dbruntime: acquire conn for migration lock: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationAdvisoryLockKey); err != nil {
		return fmt.Errorf("dbruntime: acquire migration lock: %w", err)
	}
	// Unlock with a detached context so a cancelled ctx can't leak the lock and
	// deadlock every future migration.
	defer func() {
		uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, uerr := conn.Exec(uctx, "SELECT pg_advisory_unlock($1)", migrationAdvisoryLockKey); uerr != nil && err == nil {
			err = fmt.Errorf("dbruntime: release migration lock: %w", uerr)
		}
	}()

	return fn(ctx)
}
