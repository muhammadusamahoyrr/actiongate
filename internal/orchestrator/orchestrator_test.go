package orchestrator

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"

	"github.com/muhammadusamahoyrr/actiongate/internal/approval"
	"github.com/muhammadusamahoyrr/actiongate/internal/domain"
	"github.com/muhammadusamahoyrr/actiongate/internal/execution"
	"github.com/muhammadusamahoyrr/actiongate/internal/grant"
	"github.com/muhammadusamahoyrr/actiongate/internal/policy"
	"github.com/muhammadusamahoyrr/actiongate/internal/queue"
	"github.com/muhammadusamahoyrr/actiongate/internal/testdb"
)

type world struct {
	pool  *pgxpool.Pool
	orch  *Orchestrator
	appr  *approval.Service
	coord *execution.Coordinator
	keys  map[string]ed25519.PublicKey
}

func setupWorld(t *testing.T) *world {
	t.Helper()
	pool := testdb.SetupPool(t)
	if err := queue.Migrate(context.Background(), pool); err != nil {
		t.Fatalf("river migrate: %v", err)
	}
	client, err := queue.NewInsertOnlyClient(pool)
	if err != nil {
		t.Fatalf("river client: %v", err)
	}
	signer, pub, err := grant.NewSigner("hot-1")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	appr := &approval.Service{
		Pool: pool, Queue: client,
		TokenSecret: []byte("test-secret-32-bytes-minimum-ok!"),
		Router:      approval.Router{Default: "team-lead"},
		Expiry:      time.Hour,
	}
	coord := &execution.Coordinator{Pool: pool, Queue: client, Signer: signer}
	return &world{
		pool: pool,
		orch: &Orchestrator{Pool: pool, Engine: engine, Approvals: appr, Coordinator: coord},
		appr: appr, coord: coord,
		keys: map[string]ed25519.PublicKey{"hot-1": pub},
	}
}

func newTenant(t *testing.T, pool *pgxpool.Pool, policyJSON string) uuid.UUID {
	t.Helper()
	tenantID := uuid.New()
	if _, err := pool.Exec(context.Background(),
		`insert into configuration_snapshots (tenant_id, version, content, content_hash, created_by)
		 values ($1, 1, $2, '\x00', 'test')`, tenantID, policyJSON); err != nil {
		t.Fatalf("snapshot fixture: %v", err)
	}
	return tenantID
}

const codingAgentPolicy = `{
	"default_decision": "allow",
	"rules": [
		{"id": "deny-secrets", "condition": "tool_name == \"read_file\" && params.path.contains(\".env\")", "decision": "deny", "risk_classification": "secrets"},
		{"id": "approve-destructive", "condition": "tool_name == \"bash\" && params.command.contains(\"rm -rf\")", "decision": "requires_approval", "risk_classification": "destructive"}
	]
}`

func submitInput(tenantID uuid.UUID, tool, paramsJSON string) SubmitInput {
	return SubmitInput{
		TenantID: tenantID, AgentID: "agent-1", SessionID: uuid.New(),
		NativeRequestID: "req-" + uuid.NewString(), ToolName: tool,
		ToolParams: []byte(paramsJSON), Environment: "test", StreamID: uuid.New(),
	}
}

func eventCount(t *testing.T, pool *pgxpool.Pool, tenantID, actionID uuid.UUID, eventType domain.EventType) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`select count(*) from audit_events
		  where tenant_id = $1 and action_request_id = $2 and event_type = $3`,
		tenantID, actionID, string(eventType)).Scan(&n); err != nil {
		t.Fatalf("count events: %v", err)
	}
	return n
}

func TestOrchestrator(t *testing.T) {
	w := setupWorld(t)
	ctx := context.Background()

	t.Run("allow: submit returns a verifiable grant", func(t *testing.T) {
		tenantID := newTenant(t, w.pool, codingAgentPolicy)
		res, err := w.orch.Submit(ctx, submitInput(tenantID, "bash", `{"command":"ls"}`))
		if err != nil {
			t.Fatalf("Submit: %v", err)
		}
		if res.Kind != KindAuthorized || res.State != domain.StateExecutionAuthorized {
			t.Fatalf("result: %+v", res)
		}
		g, err := grant.Verify(res.GrantEnvelope, w.keys, time.Now())
		if err != nil {
			t.Fatalf("grant does not verify: %v", err)
		}
		if g.GetActionId() != res.ActionID.String() || g.GetToolName() != "bash" {
			t.Fatalf("grant content: %+v", g)
		}
		for _, ev := range []domain.EventType{domain.EventActionCreated, domain.EventPolicyEvaluated, domain.EventExecutionAuthorized} {
			if n := eventCount(t, w.pool, tenantID, res.ActionID, ev); n != 1 {
				t.Fatalf("%s events = %d, want 1", ev, n)
			}
		}
		var deadlineJobs int
		if err := w.pool.QueryRow(ctx,
			`select count(*) from river_job
			  where kind = 'outcome_deadline' and args->>'action_id' = $1`,
			res.ActionID.String()).Scan(&deadlineJobs); err != nil {
			t.Fatalf("deadline jobs: %v", err)
		}
		if deadlineJobs != 1 {
			t.Fatalf("outcome_deadline jobs = %d, want 1", deadlineJobs)
		}
	})

	t.Run("deny: explanation names the rule and the action lands Denied", func(t *testing.T) {
		tenantID := newTenant(t, w.pool, codingAgentPolicy)
		res, err := w.orch.Submit(ctx, submitInput(tenantID, "read_file", `{"path":"/app/.env"}`))
		if err != nil {
			t.Fatalf("Submit: %v", err)
		}
		if res.Kind != KindDenied || res.State != domain.StateDenied {
			t.Fatalf("result: %+v", res)
		}
		if res.MatchedRuleID != "deny-secrets" || !strings.Contains(res.Explanation, "deny-secrets") {
			t.Fatalf("explanation missing the rule: %+v", res)
		}
		if n := eventCount(t, w.pool, tenantID, res.ActionID, domain.EventActionDenied); n != 1 {
			t.Fatalf("ActionDenied events = %d, want 1", n)
		}
	})

	t.Run("approval: pending, then resolve, then the worker authorizes", func(t *testing.T) {
		tenantID := newTenant(t, w.pool, codingAgentPolicy)
		res, err := w.orch.Submit(ctx, submitInput(tenantID, "bash", `{"command":"rm -rf /tmp/x"}`))
		if err != nil {
			t.Fatalf("Submit: %v", err)
		}
		if res.Kind != KindPending || res.State != domain.StatePendingApproval {
			t.Fatalf("result: %+v", res)
		}

		// The raw token travels in the queued delivery job (documented V1
		// path) — recover it as the channel would.
		var deliveryArgs []byte
		if err := w.pool.QueryRow(ctx,
			`select args from river_job
			  where kind = 'deliver_approval' and args->>'action_id' = $1`,
			res.ActionID.String()).Scan(&deliveryArgs); err != nil {
			t.Fatalf("delivery job: %v", err)
		}
		var delivered queue.DeliverApprovalArgs
		if err := json.Unmarshal(deliveryArgs, &delivered); err != nil {
			t.Fatalf("delivery args: %v", err)
		}

		resolution, err := w.appr.Resolve(ctx, delivered.CallbackToken, "approved", "alice", "fine")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if resolution.NewState != domain.StateApproved {
			t.Fatalf("resolution: %+v", resolution)
		}

		// The approval committed an authorize_execution job; run its worker.
		var authArgs queue.AuthorizeExecutionArgs
		var raw []byte
		if err := w.pool.QueryRow(ctx,
			`select args from river_job
			  where kind = 'authorize_execution' and args->>'action_id' = $1`,
			res.ActionID.String()).Scan(&raw); err != nil {
			t.Fatalf("authorize job missing — approval did not enqueue it: %v", err)
		}
		if err := json.Unmarshal(raw, &authArgs); err != nil {
			t.Fatalf("authorize args: %v", err)
		}
		worker := &execution.AuthorizeWorker{Coordinator: w.coord}
		if err := worker.Work(ctx, &river.Job[queue.AuthorizeExecutionArgs]{Args: authArgs}); err != nil {
			t.Fatalf("AuthorizeWorker: %v", err)
		}

		status, err := w.orch.Status(ctx, tenantID, res.ActionID)
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		if status.State != domain.StateExecutionAuthorized || status.GrantEnvelope == nil {
			t.Fatalf("status after approval: %+v", status)
		}
		if _, err := grant.Verify(status.GrantEnvelope, w.keys, time.Now()); err != nil {
			t.Fatalf("delivered grant does not verify: %v", err)
		}
	})

	t.Run("retry resumes instead of re-running", func(t *testing.T) {
		tenantID := newTenant(t, w.pool, codingAgentPolicy)
		in := submitInput(tenantID, "bash", `{"command":"ls"}`)
		first, err := w.orch.Submit(ctx, in)
		if err != nil {
			t.Fatalf("first Submit: %v", err)
		}
		second, err := w.orch.Submit(ctx, in) // same session + native id
		if err != nil {
			t.Fatalf("retry Submit: %v", err)
		}
		if second.Kind != KindStatus || second.ActionID != first.ActionID {
			t.Fatalf("retry did not resume: %+v vs %+v", second, first)
		}
		if n := eventCount(t, w.pool, tenantID, first.ActionID, domain.EventActionCreated); n != 1 {
			t.Fatalf("ActionCreated events = %d, want 1", n)
		}
	})

	t.Run("tenant without a snapshot fails closed", func(t *testing.T) {
		_, err := w.orch.Submit(ctx, submitInput(uuid.New(), "bash", `{"command":"ls"}`))
		if err == nil {
			t.Fatal("submit without any policy succeeded — fail-closed violated")
		}
	})

	t.Run("late authorize job no-ops on a terminal action", func(t *testing.T) {
		tenantID := newTenant(t, w.pool, codingAgentPolicy)
		res, err := w.orch.Submit(ctx, submitInput(tenantID, "read_file", `{"path":"/app/.env"}`))
		if err != nil {
			t.Fatalf("Submit: %v", err)
		}
		worker := &execution.AuthorizeWorker{Coordinator: w.coord}
		err = worker.Work(ctx, &river.Job[queue.AuthorizeExecutionArgs]{Args: queue.AuthorizeExecutionArgs{
			TenantID: tenantID, ActionID: res.ActionID, StreamID: uuid.New(),
		}})
		if err != nil {
			t.Fatalf("late authorize must no-op, got %v", err)
		}
	})
}
