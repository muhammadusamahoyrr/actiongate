package approval

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/muhammadusamahoyrr/actiongate/internal/domain"
	"github.com/muhammadusamahoyrr/actiongate/internal/queue"
	"github.com/muhammadusamahoyrr/actiongate/internal/testdb"
	"github.com/muhammadusamahoyrr/actiongate/internal/transition"
)

func newService(t *testing.T, pool *pgxpool.Pool, expiry time.Duration) *Service {
	t.Helper()
	client, err := queue.NewInsertOnlyClient(pool)
	if err != nil {
		t.Fatalf("river client: %v", err)
	}
	return &Service{
		Pool:        pool,
		Queue:       client,
		TokenSecret: []byte("test-secret-32-bytes-minimum-ok!"),
		Router: Router{
			Targets: map[string]string{"destructive": "sre-oncall"},
			Default: "team-lead",
		},
		Expiry: expiry,
	}
}

type fixture struct {
	tenantID uuid.UUID
	actionID uuid.UUID
	streamID uuid.UUID
}

func evaluatedAction(t *testing.T, pool *pgxpool.Pool) fixture {
	t.Helper()
	ctx := context.Background()
	tenantID := uuid.New()
	streamID := uuid.New()
	if _, err := pool.Exec(ctx,
		`insert into configuration_snapshots (tenant_id, version, content, content_hash, created_by)
		 values ($1, 1, '{}', '\x00', 'test')`, tenantID); err != nil {
		t.Fatalf("tenant fixture: %v", err)
	}
	res, err := transition.Create(ctx, pool, transition.CreateRequest{
		TenantID: tenantID, AgentID: "agent-1", SessionID: uuid.New(),
		NativeRequestID: "req-1", ToolName: "bash",
		ToolParams: []byte(`{"command":"rm -rf /tmp/x"}`), Environment: "test",
		PolicyVersion: 1, StreamID: streamID,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := transition.Apply(ctx, pool, transition.Request{
		TenantID: tenantID, ActionID: res.ActionID,
		From: domain.StateCreated, To: domain.StateEvaluated, ExpectedVersion: 0,
		Event: transition.Event{
			StreamID: streamID, Type: domain.EventPolicyEvaluated,
			AttestedBy: domain.AttestedByControlPlane,
		},
	}); err != nil {
		t.Fatalf("advance to Evaluated: %v", err)
	}
	return fixture{tenantID: tenantID, actionID: res.ActionID, streamID: streamID}
}

func request(t *testing.T, svc *Service, f fixture) Requested {
	t.Helper()
	req, err := svc.Request(context.Background(), RequestInput{
		TenantID: f.tenantID, ActionID: f.actionID, StreamID: f.streamID,
		RiskClassification: "destructive", MatchedRuleID: "approve-destructive-shell",
		Title: "Approve rm -rf?", Body: "agent-1 wants bash",
	})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	return req
}

func actionState(t *testing.T, pool *pgxpool.Pool, f fixture) domain.State {
	t.Helper()
	state, _, err := transition.CurrentState(context.Background(), pool, f.tenantID, f.actionID)
	if err != nil {
		t.Fatalf("CurrentState: %v", err)
	}
	return state
}

func TestApprovalService(t *testing.T) {
	pool := testdb.SetupPool(t)
	if err := queue.Migrate(context.Background(), pool); err != nil {
		t.Fatalf("river migrate: %v", err)
	}
	ctx := context.Background()

	t.Run("request creates approval, token, timer, and delivery atomically", func(t *testing.T) {
		svc := newService(t, pool, time.Hour)
		f := evaluatedAction(t, pool)
		req := request(t, svc, f)

		if got := actionState(t, pool, f); got != domain.StatePendingApproval {
			t.Fatalf("state = %s, want PendingApproval", got)
		}
		if req.ApproverTarget != "sre-oncall" {
			t.Fatalf("router picked %q, want sre-oncall", req.ApproverTarget)
		}
		var status string
		var version int32
		if err := pool.QueryRow(ctx,
			`select status, version from approval_requests where id = $1`,
			req.ApprovalRequestID).Scan(&status, &version); err != nil {
			t.Fatalf("approval row: %v", err)
		}
		if status != "pending" || version != 0 {
			t.Fatalf("approval row = (%s, v%d)", status, version)
		}
		// Only the hash is stored — the raw token must not appear.
		var tokenCount int
		if err := pool.QueryRow(ctx,
			`select count(*) from approval_callback_tokens where approval_request_id = $1`,
			req.ApprovalRequestID).Scan(&tokenCount); err != nil {
			t.Fatalf("token row: %v", err)
		}
		if tokenCount != 1 {
			t.Fatalf("token rows = %d, want 1", tokenCount)
		}
		if !strings.HasPrefix(req.Token, "agt1_") {
			t.Fatalf("token format: %q", req.Token)
		}

		var expiryJobs int
		if err := pool.QueryRow(ctx,
			`select count(*) from river_job
			  where kind = 'approval_expiry' and args->>'approval_request_id' = $1`,
			req.ApprovalRequestID.String()).Scan(&expiryJobs); err != nil {
			t.Fatalf("expiry jobs: %v", err)
		}
		if expiryJobs != 1 {
			t.Fatalf("expiry jobs = %d, want 1", expiryJobs)
		}
		var deliveryArgs []byte
		if err := pool.QueryRow(ctx,
			`select args from river_job
			  where kind = 'deliver_approval' and args->>'approval_request_id' = $1`,
			req.ApprovalRequestID.String()).Scan(&deliveryArgs); err != nil {
			t.Fatalf("delivery job: %v", err)
		}
		var delivered queue.DeliverApprovalArgs
		if err := json.Unmarshal(deliveryArgs, &delivered); err != nil {
			t.Fatalf("delivery args: %v", err)
		}
		if delivered.CallbackToken != req.Token || delivered.ApproverTarget != "sre-oncall" {
			t.Fatalf("delivery payload mangled: %+v", delivered)
		}
	})

	t.Run("request refuses an action that is not Evaluated", func(t *testing.T) {
		svc := newService(t, pool, time.Hour)
		f := evaluatedAction(t, pool)
		request(t, svc, f) // now PendingApproval
		_, err := svc.Request(ctx, RequestInput{
			TenantID: f.tenantID, ActionID: f.actionID, StreamID: f.streamID,
			RiskClassification: "destructive",
		})
		if !errors.Is(err, ErrNotAwaiting) {
			t.Fatalf("want ErrNotAwaiting, got %v", err)
		}
	})

	t.Run("approve moves the action to Approved with operator attestation", func(t *testing.T) {
		svc := newService(t, pool, time.Hour)
		f := evaluatedAction(t, pool)
		req := request(t, svc, f)

		res, err := svc.Resolve(ctx, req.Token, "approved", "alice", "looks safe")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.NewState != domain.StateApproved || res.ActionID != f.actionID {
			t.Fatalf("resolution: %+v", res)
		}
		if got := actionState(t, pool, f); got != domain.StateApproved {
			t.Fatalf("state = %s, want Approved", got)
		}
		var attestedBy string
		if err := pool.QueryRow(ctx,
			`select attested_by from audit_events
			  where tenant_id = $1 and action_request_id = $2 and event_type = 'ApprovalGranted'`,
			f.tenantID, f.actionID).Scan(&attestedBy); err != nil {
			t.Fatalf("event: %v", err)
		}
		if attestedBy != "operator:alice" {
			t.Fatalf("attested_by = %q", attestedBy)
		}
		var status string
		var version int32
		var decisions int
		if err := pool.QueryRow(ctx,
			`select a.status, a.version,
			        (select count(*) from approval_decisions d where d.approval_request_id = a.id)
			   from approval_requests a where a.id = $1`,
			req.ApprovalRequestID).Scan(&status, &version, &decisions); err != nil {
			t.Fatalf("approval row: %v", err)
		}
		if status != "approved" || version != 1 || decisions != 1 {
			t.Fatalf("approval = (%s, v%d, %d decisions)", status, version, decisions)
		}
	})

	t.Run("deny moves the action to Denied", func(t *testing.T) {
		svc := newService(t, pool, time.Hour)
		f := evaluatedAction(t, pool)
		req := request(t, svc, f)
		res, err := svc.Resolve(ctx, req.Token, "denied", "bob", "too risky")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.NewState != domain.StateDenied {
			t.Fatalf("resolution: %+v", res)
		}
		if got := actionState(t, pool, f); got != domain.StateDenied {
			t.Fatalf("state = %s, want Denied", got)
		}
	})

	t.Run("token replay is rejected", func(t *testing.T) {
		svc := newService(t, pool, time.Hour)
		f := evaluatedAction(t, pool)
		req := request(t, svc, f)
		if _, err := svc.Resolve(ctx, req.Token, "approved", "alice", ""); err != nil {
			t.Fatalf("first Resolve: %v", err)
		}
		_, err := svc.Resolve(ctx, req.Token, "denied", "mallory", "flip it")
		if !errors.Is(err, ErrAlreadyResolved) {
			t.Fatalf("want ErrAlreadyResolved, got %v", err)
		}
		if got := actionState(t, pool, f); got != domain.StateApproved {
			t.Fatalf("replay changed the outcome: %s", got)
		}
	})

	t.Run("forged token is rejected before touching the database", func(t *testing.T) {
		svc := newService(t, pool, time.Hour)
		f := evaluatedAction(t, pool)
		req := request(t, svc, f)
		// Flip a payload character: HMAC must fail.
		forged := []byte(req.Token)
		i := len(tokenPrefix) + 3
		if forged[i] == 'A' {
			forged[i] = 'B'
		} else {
			forged[i] = 'A'
		}
		_, err := svc.Resolve(ctx, string(forged), "approved", "mallory", "")
		if !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("want ErrTokenInvalid, got %v", err)
		}
		if _, err := svc.Resolve(ctx, "agt1_garbage", "approved", "mallory", ""); !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("want ErrTokenInvalid for garbage, got %v", err)
		}
	})

	t.Run("expired token is rejected", func(t *testing.T) {
		svc := newService(t, pool, time.Millisecond)
		f := evaluatedAction(t, pool)
		req := request(t, svc, f)
		time.Sleep(50 * time.Millisecond)
		_, err := svc.Resolve(ctx, req.Token, "approved", "alice", "")
		if !errors.Is(err, ErrTokenExpired) {
			t.Fatalf("want ErrTokenExpired, got %v", err)
		}
	})

	t.Run("concurrent approve and deny: exactly one wins", func(t *testing.T) {
		svc := newService(t, pool, time.Hour)
		f := evaluatedAction(t, pool)
		req := request(t, svc, f)

		var wg sync.WaitGroup
		results := make([]error, 2)
		outcomes := make([]Resolution, 2)
		decisions := []string{"approved", "denied"}
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				outcomes[i], results[i] = svc.Resolve(ctx, req.Token, decisions[i], "racer", "")
			}(i)
		}
		wg.Wait()

		winners := 0
		var winner Resolution
		for i := 0; i < 2; i++ {
			if results[i] == nil {
				winners++
				winner = outcomes[i]
			} else if !errors.Is(results[i], ErrAlreadyResolved) {
				t.Fatalf("loser got unexpected error: %v", results[i])
			}
		}
		if winners != 1 {
			t.Fatalf("winners = %d, want exactly 1", winners)
		}
		if got := actionState(t, pool, f); got != winner.NewState {
			t.Fatalf("state %s does not match winner %s", got, winner.NewState)
		}
		var decisionRows int
		if err := pool.QueryRow(ctx,
			`select count(*) from approval_decisions where approval_request_id = $1`,
			req.ApprovalRequestID).Scan(&decisionRows); err != nil {
			t.Fatalf("decisions: %v", err)
		}
		if decisionRows != 1 {
			t.Fatalf("decision rows = %d, want exactly 1", decisionRows)
		}
	})
}
