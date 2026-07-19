package dbruntime

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// InitSteps are the injected, ordered bootstrap steps. dbruntime stays
// audit-chain-agnostic: the caller (cmd/actiongate, at M8) supplies the real
// implementations.
type InitSteps struct {
	// MigrateSchema brings the application (goose) and River schema up. Run on
	// every start; must be idempotent.
	MigrateSchema func(ctx context.Context) error
	// Provision runs one-time setup on a FRESH cluster only: tenant, signing
	// keys, seal epoch 0.
	Provision func(ctx context.Context) error
}

// Initialize runs the Step 4 bootstrap against the cluster reachable at dsn,
// under the migration advisory lock, in strict order:
//
//	ensure meta table → (if existing) binary-compat gate → MigrateSchema →
//	(if fresh) Provision → record min binary version
//
// "Fresh" means the metadata row is absent, so Provision is skipped on every
// later start. The binary-compat gate runs before any migration so an older
// binary never touches a newer schema.
func Initialize(ctx context.Context, dsn, binaryVersion, minBinaryVersion string, steps InitSteps) error {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("dbruntime: open pool for init: %w", err)
	}
	defer pool.Close()

	return WithMigrationLock(ctx, pool, func(ctx context.Context) error {
		if err := EnsureMetaTable(ctx, pool); err != nil {
			return err
		}
		meta, existing, err := ReadMeta(ctx, pool)
		if err != nil {
			return err
		}
		if existing {
			if err := CheckBinaryCompatible(binaryVersion, meta); err != nil {
				return err
			}
		}
		if steps.MigrateSchema != nil {
			if err := steps.MigrateSchema(ctx); err != nil {
				return fmt.Errorf("dbruntime: migrate schema: %w", err)
			}
		}
		if !existing && steps.Provision != nil {
			if err := steps.Provision(ctx); err != nil {
				return fmt.Errorf("dbruntime: provision fresh cluster: %w", err)
			}
		}
		return WriteMeta(ctx, pool, Meta{MinBinaryVersion: minBinaryVersion})
	})
}
