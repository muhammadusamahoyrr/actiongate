// Package servertest stands up the complete control plane — real Postgres,
// live River workers, Sealer-ready schema, HTTP server — for wire-level
// tests. Only ever imported from _test files.
package servertest

import (
	"context"
	"crypto/sha256"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/muhammadusamahoyrr/actiongate/internal/approval"
	"github.com/muhammadusamahoyrr/actiongate/internal/execution"
	"github.com/muhammadusamahoyrr/actiongate/internal/grant"
	"github.com/muhammadusamahoyrr/actiongate/internal/notify"
	"github.com/muhammadusamahoyrr/actiongate/internal/orchestrator"
	"github.com/muhammadusamahoyrr/actiongate/internal/policy"
	"github.com/muhammadusamahoyrr/actiongate/internal/queue"
	"github.com/muhammadusamahoyrr/actiongate/internal/server"
	"github.com/muhammadusamahoyrr/actiongate/internal/testdb"
)

// SlackSigningSecret is the test stack's Slack signing secret, for
// exercising /slack/interaction.
const SlackSigningSecret = "test-slack-signing-secret"

const DefaultPolicy = `{
	"default_decision": "allow",
	"rules": [
		{"id": "deny-secrets", "condition": "tool_name == \"read_file\" && params.path.contains(\".env\")", "decision": "deny", "risk_classification": "secrets"},
		{"id": "approve-destructive", "condition": "tool_name == \"bash\" && params.command.contains(\"rm -rf\")", "decision": "requires_approval", "risk_classification": "destructive"}
	]
}`

type Stack struct {
	Pool     *pgxpool.Pool
	BaseURL  string
	TenantID uuid.UUID
}

// Setup builds the whole control plane with DefaultPolicy for one tenant.
func Setup(t *testing.T) *Stack {
	t.Helper()
	ctx := context.Background()
	pool := testdb.SetupPool(t)
	if err := queue.Migrate(ctx, pool); err != nil {
		t.Fatalf("river migrate: %v", err)
	}
	insertClient, err := queue.NewInsertOnlyClient(pool)
	if err != nil {
		t.Fatalf("insert client: %v", err)
	}
	signer, grantPub, err := grant.NewSigner("grant-1")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	coordinator := &execution.Coordinator{Pool: pool, Queue: insertClient, Signer: signer}
	approvals := &approval.Service{
		Pool: pool, Queue: insertClient,
		TokenSecret: []byte("test-secret-32-bytes-minimum-ok!"),
		Router:      approval.Router{Default: "team-lead"},
		Expiry:      time.Hour,
	}
	orch := &orchestrator.Orchestrator{Pool: pool, Engine: engine, Approvals: approvals, Coordinator: coordinator}

	workers, err := queue.NewWorkers(pool, notify.LogPort{})
	if err != nil {
		t.Fatalf("workers: %v", err)
	}
	if err := execution.RegisterWorker(workers, coordinator); err != nil {
		t.Fatalf("register authorize worker: %v", err)
	}
	workerClient, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		Queues:  map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: 4}},
		Workers: workers,
	})
	if err != nil {
		t.Fatalf("worker client: %v", err)
	}
	if err := workerClient.Start(ctx); err != nil {
		t.Fatalf("worker start: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = workerClient.Stop(stopCtx)
	})

	srv := &server.Server{
		Pool: pool, Orchestrator: orch, Approvals: approvals, Coordinator: coordinator,
		GrantKeyID: signer.KeyID(), GrantPublicKey: grantPub,
		SlackSigningSecret: SlackSigningSecret,
		EpochKeyIDs:        []string{"epoch-1"},
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	tenantID := uuid.New()
	if _, err := pool.Exec(ctx,
		`insert into configuration_snapshots (tenant_id, version, content, content_hash, created_by)
		 values ($1, 1, $2, '\x00', 'test')`, tenantID, DefaultPolicy); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	return &Stack{Pool: pool, BaseURL: ts.URL, TenantID: tenantID}
}

// SeedEnrollmentToken provisions a fresh single-use token for the stack's
// tenant and returns the raw value.
func (s *Stack) SeedEnrollmentToken(t *testing.T) string {
	t.Helper()
	raw := "enroll-" + uuid.NewString()
	sum := sha256.Sum256([]byte(raw))
	if _, err := s.Pool.Exec(context.Background(),
		`insert into enrollment_tokens (token_hash, tenant_id, expires_at)
		 values ($1, $2, now() + interval '1 hour')`, sum[:], s.TenantID); err != nil {
		t.Fatalf("enrollment token: %v", err)
	}
	return raw
}
