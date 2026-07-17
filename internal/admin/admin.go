// Package admin provides the operator provisioning operations: tenants,
// policy snapshots, and enrollment tokens. Policy content is compiled
// before it is ever stored — an invalid snapshot cannot exist (fail closed
// at provisioning, not at request time).
package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"actiongate/internal/policy"
)

// CreateTenant provisions a new tenant with its version-1 policy snapshot.
func CreateTenant(ctx context.Context, pool *pgxpool.Pool, policyJSON []byte) (uuid.UUID, error) {
	tenantID := uuid.New()
	if _, err := SetPolicy(ctx, pool, tenantID, policyJSON); err != nil {
		return uuid.Nil, err
	}
	return tenantID, nil
}

// SetPolicy validates, compiles, and stores the next snapshot version for a
// tenant. The stored content_hash makes policy_version_evaluated in the
// audit trail verifiable against actual policy content (plan §20.1).
func SetPolicy(ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID, policyJSON []byte) (int64, error) {
	var cfg policy.SnapshotConfig
	if err := json.Unmarshal(policyJSON, &cfg); err != nil {
		return 0, fmt.Errorf("policy content: %w", err)
	}
	engine, err := policy.NewEngine()
	if err != nil {
		return 0, err
	}
	if _, err := engine.Compile(cfg); err != nil {
		return 0, fmt.Errorf("policy rejected: %w", err)
	}
	contentHash := sha256.Sum256(policyJSON)

	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `select set_config('app.tenant_id', $1, true)`, tenantID.String()); err != nil {
		return 0, fmt.Errorf("set tenant: %w", err)
	}
	var version int64
	err = tx.QueryRow(ctx,
		`insert into configuration_snapshots (tenant_id, version, content, content_hash, created_by)
		 values ($1,
		         coalesce((select max(version) from configuration_snapshots where tenant_id = $1), 0) + 1,
		         $2, $3, 'admin')
		 returning version`,
		tenantID, policyJSON, contentHash[:]).Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("store snapshot: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return version, nil
}

// NewEnrollmentToken mints a single-use gateway enrollment token. Only the
// SHA-256 lands in the database; the raw value is printed exactly once.
func NewEnrollmentToken(ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("randomness: %w", err)
	}
	raw := "agenroll_" + base64.RawURLEncoding.EncodeToString(secret)
	sum := sha256.Sum256([]byte(raw))
	if _, err := pool.Exec(ctx,
		`insert into enrollment_tokens (token_hash, tenant_id, expires_at)
		 values ($1, $2, $3)`,
		sum[:], tenantID, time.Now().UTC().Add(ttl)); err != nil {
		return "", fmt.Errorf("store token: %w", err)
	}
	return raw, nil
}
