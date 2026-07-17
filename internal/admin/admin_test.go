package admin

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"actiongate/internal/gateway"
	"actiongate/internal/servertest"
	"actiongate/internal/testdb"
)

func TestAdmin(t *testing.T) {
	pool := testdb.SetupPool(t)
	ctx := context.Background()

	t.Run("create tenant stores a validated v1 snapshot with content hash", func(t *testing.T) {
		policyJSON := []byte(`{"default_decision":"deny","rules":[{"id":"r1","condition":"tool_name == \"bash\"","decision":"allow"}]}`)
		tenantID, err := CreateTenant(ctx, pool, policyJSON)
		if err != nil {
			t.Fatalf("CreateTenant: %v", err)
		}
		var version int64
		var content, contentHash []byte
		if err := pool.QueryRow(ctx,
			`select version, content, content_hash from configuration_snapshots where tenant_id = $1`,
			tenantID).Scan(&version, &content, &contentHash); err != nil {
			t.Fatalf("read snapshot: %v", err)
		}
		want := sha256.Sum256(policyJSON)
		if version != 1 || string(contentHash) != string(want[:]) {
			t.Fatalf("snapshot v%d, hash mismatch=%v", version, string(contentHash) != string(want[:]))
		}
	})

	t.Run("invalid policy is rejected before storage", func(t *testing.T) {
		bad := []byte(`{"rules":[{"id":"r1","condition":"tool_name ==","decision":"allow"}]}`)
		if _, err := CreateTenant(ctx, pool, bad); err == nil {
			t.Fatal("broken CEL stored as a snapshot")
		}
		badDecision := []byte(`{"rules":[{"id":"r1","condition":"true","decision":"maybe"}]}`)
		if _, err := CreateTenant(ctx, pool, badDecision); err == nil {
			t.Fatal("unknown decision stored as a snapshot")
		}
	})

	t.Run("set-policy appends the next immutable version", func(t *testing.T) {
		policyJSON := []byte(`{"default_decision":"allow","rules":[]}`)
		tenantID, err := CreateTenant(ctx, pool, policyJSON)
		if err != nil {
			t.Fatalf("CreateTenant: %v", err)
		}
		v2, err := SetPolicy(ctx, pool, tenantID,
			[]byte(`{"default_decision":"deny","rules":[]}`))
		if err != nil {
			t.Fatalf("SetPolicy: %v", err)
		}
		if v2 != 2 {
			t.Fatalf("version = %d, want 2", v2)
		}
		var count int
		if err := pool.QueryRow(ctx,
			`select count(*) from configuration_snapshots where tenant_id = $1`,
			tenantID).Scan(&count); err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 2 {
			t.Fatalf("snapshots = %d, want 2 (append-only)", count)
		}
	})
}

// The token minted by admin must round-trip through the real Enroll RPC —
// the hashing schemes on both sides must be identical.
func TestEnrollmentTokenRoundTrip(t *testing.T) {
	stack := servertest.Setup(t)
	ctx := context.Background()

	raw, err := NewEnrollmentToken(ctx, stack.Pool, stack.TenantID, time.Hour)
	if err != nil {
		t.Fatalf("NewEnrollmentToken: %v", err)
	}
	state, err := gateway.Enroll(ctx, nil, stack.BaseURL, raw, "admin-minted")
	if err != nil {
		t.Fatalf("Enroll with admin-minted token: %v", err)
	}
	if state.TenantID != stack.TenantID.String() {
		t.Fatalf("enrolled into tenant %s, want %s", state.TenantID, stack.TenantID)
	}
}
