package dbruntime

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/mod/semver"
)

// Meta is ActionGate's cluster-level metadata. The schema version itself is
// tracked by goose (goose_db_version); this table records the compatibility gate
// Step 4 needs: the oldest ActionGate binary allowed to open this database.
type Meta struct {
	MinBinaryVersion string
}

// EnsureMetaTable creates the metadata table if absent (idempotent, safe under
// concurrency via CREATE TABLE IF NOT EXISTS).
func EnsureMetaTable(ctx context.Context, pool *pgxpool.Pool) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS actiongate_meta (
    id                 boolean PRIMARY KEY DEFAULT true,
    min_binary_version text    NOT NULL,
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT actiongate_meta_single_row CHECK (id)
);`
	if _, err := pool.Exec(ctx, ddl); err != nil {
		return fmt.Errorf("dbruntime: ensure meta table: %w", err)
	}
	return nil
}

// ReadMeta returns the metadata row and whether it exists.
func ReadMeta(ctx context.Context, pool *pgxpool.Pool) (Meta, bool, error) {
	var m Meta
	err := pool.QueryRow(ctx, `SELECT min_binary_version FROM actiongate_meta WHERE id`).Scan(&m.MinBinaryVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return Meta{}, false, nil
	}
	if err != nil {
		return Meta{}, false, fmt.Errorf("dbruntime: read meta: %w", err)
	}
	return m, true, nil
}

// WriteMeta upserts the single metadata row.
func WriteMeta(ctx context.Context, pool *pgxpool.Pool, m Meta) error {
	const q = `
INSERT INTO actiongate_meta (id, min_binary_version, updated_at)
VALUES (true, $1, now())
ON CONFLICT (id) DO UPDATE SET min_binary_version = EXCLUDED.min_binary_version, updated_at = now();`
	if _, err := pool.Exec(ctx, q, m.MinBinaryVersion); err != nil {
		return fmt.Errorf("dbruntime: write meta: %w", err)
	}
	return nil
}

// CheckBinaryCompatible refuses to proceed when the running binary is older than
// the database's recorded minimum — an older binary must never silently open a
// newer schema. An empty MinBinaryVersion (or binaryVersion) skips the check.
func CheckBinaryCompatible(binaryVersion string, m Meta) error {
	if m.MinBinaryVersion == "" || binaryVersion == "" {
		return nil
	}
	bv, mv := normalizeVersion(binaryVersion), normalizeVersion(m.MinBinaryVersion)
	if !semver.IsValid(bv) || !semver.IsValid(mv) {
		return fmt.Errorf("dbruntime: cannot compare versions (binary=%q, min=%q)", binaryVersion, m.MinBinaryVersion)
	}
	if semver.Compare(bv, mv) < 0 {
		return fmt.Errorf("dbruntime: this database requires ActionGate %s or newer (this binary is %s)",
			m.MinBinaryVersion, binaryVersion)
	}
	return nil
}

// normalizeVersion adds the leading "v" that golang.org/x/mod/semver requires.
func normalizeVersion(v string) string {
	if v == "" || v[0] == 'v' {
		return v
	}
	return "v" + v
}
