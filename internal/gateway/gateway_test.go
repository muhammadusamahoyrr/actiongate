package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/muhammadusamahoyrr/actiongate/internal/domain"
	"github.com/muhammadusamahoyrr/actiongate/internal/queue"
	"github.com/muhammadusamahoyrr/actiongate/internal/servertest"
	"github.com/muhammadusamahoyrr/actiongate/internal/transition"
)

func enrolledGateway(t *testing.T, stack *servertest.Stack) *Gateway {
	t.Helper()
	state, err := Enroll(context.Background(), nil, stack.BaseURL, stack.SeedEnrollmentToken(t), "test-gw")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	return &Gateway{State: state}
}

func checkInput(tool string, params map[string]any) CheckInput {
	return CheckInput{
		AgentID:         "agent-1",
		SessionID:       uuid.NewString(),
		NativeRequestID: uuid.NewString(),
		ToolName:        tool,
		Params:          params,
		Environment:     "test",
		Wait:            20 * time.Second,
	}
}

func TestGateway(t *testing.T) {
	stack := servertest.Setup(t)
	ctx := context.Background()

	t.Run("state round-trips through the file with private key intact", func(t *testing.T) {
		gw := enrolledGateway(t, stack)
		path := filepath.Join(t.TempDir(), "gateway.json")
		if err := gw.State.Save(path); err != nil {
			t.Fatalf("Save: %v", err)
		}
		loaded, err := LoadState(path)
		if err != nil {
			t.Fatalf("LoadState: %v", err)
		}
		if loaded.Credential != gw.State.Credential || loaded.GatewayID != gw.State.GatewayID {
			t.Fatalf("state mangled: %+v", loaded)
		}
		if _, err := loaded.PrivateKey(); err != nil {
			t.Fatalf("PrivateKey: %v", err)
		}
		if _, err := loaded.PublicKeys(); err != nil {
			t.Fatalf("PublicKeys: %v", err)
		}
	})

	t.Run("allowed action: check verifies the grant, report closes the loop", func(t *testing.T) {
		gw := enrolledGateway(t, stack)
		res, err := gw.Check(ctx, checkInput("bash", map[string]any{"command": "ls"}))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if !res.Allowed || res.Grant.GrantID == "" {
			t.Fatalf("result: %+v", res)
		}
		if _, ok := gw.State.PendingReceipts[res.ActionID]; !ok {
			t.Fatal("grant not remembered for report")
		}
		report, err := gw.Report(ctx, ReportInput{ActionID: res.ActionID, Status: "success"})
		if err != nil {
			t.Fatalf("Report: %v", err)
		}
		if !report.Accepted || report.Duplicate {
			t.Fatalf("report: %+v", report)
		}
		if _, ok := gw.State.PendingReceipts[res.ActionID]; ok {
			t.Fatal("grant not forgotten after report")
		}
		// The control plane recorded the terminal state.
		actionID := uuid.MustParse(res.ActionID)
		state, _, err := transition.CurrentState(ctx, stack.Pool, stack.TenantID, actionID)
		if err != nil {
			t.Fatalf("CurrentState: %v", err)
		}
		if state != domain.StateSucceeded {
			t.Fatalf("control plane state = %s, want Succeeded", state)
		}
	})

	t.Run("denied action returns the rule and no grant", func(t *testing.T) {
		gw := enrolledGateway(t, stack)
		res, err := gw.Check(ctx, checkInput("read_file", map[string]any{"path": "/app/.env"}))
		if !errors.Is(err, ErrDenied) {
			t.Fatalf("want ErrDenied, got %v", err)
		}
		if res.Allowed || res.RuleID != "deny-secrets" {
			t.Fatalf("result: %+v", res)
		}
		if len(gw.State.PendingReceipts) != 0 {
			t.Fatal("denied action left a pending grant")
		}
	})

	t.Run("pending action resolves after a human approves mid-poll", func(t *testing.T) {
		gw := enrolledGateway(t, stack)
		in := checkInput("bash", map[string]any{"command": "rm -rf /tmp/x"})

		type outcome struct {
			res CheckResult
			err error
		}
		done := make(chan outcome, 1)
		go func() {
			res, err := gw.Check(ctx, in)
			done <- outcome{res, err}
		}()

		// Approve through the public callback endpoint, as Slack would.
		approveViaCallback(t, stack, in.NativeRequestID)

		select {
		case o := <-done:
			if o.err != nil {
				t.Fatalf("Check after approval: %v", o.err)
			}
			if !o.res.Allowed || o.res.Grant.GrantID == "" {
				t.Fatalf("result: %+v", o.res)
			}
			report, err := gw.Report(ctx, ReportInput{
				ActionID: o.res.ActionID, Status: "partial",
				Error: "one file left", SideEffects: []string{"deleted /tmp/x/a"},
			})
			if err != nil || !report.Accepted {
				t.Fatalf("partial report: %+v err=%v", report, err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("check never resolved")
		}
	})

	t.Run("report without a checked grant is refused locally", func(t *testing.T) {
		gw := enrolledGateway(t, stack)
		_, err := gw.Report(ctx, ReportInput{ActionID: uuid.NewString(), Status: "success"})
		if err == nil {
			t.Fatal("report accepted without a grant")
		}
	})

	t.Run("a gateway with swapped control keys refuses the grant", func(t *testing.T) {
		gw := enrolledGateway(t, stack)
		// Simulate key pinning gone wrong: replace the pinned keys.
		for id := range gw.State.ControlKeys {
			gw.State.ControlKeys[id] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
		}
		_, err := gw.Check(ctx, checkInput("bash", map[string]any{"command": "ls"}))
		if !errors.Is(err, ErrGrantBad) {
			t.Fatalf("want ErrGrantBad, got %v", err)
		}
	})
}

// approveViaCallback waits for the delivery job belonging to the action with
// the given native request id, then approves it through the HTTP callback.
func approveViaCallback(t *testing.T, stack *servertest.Stack, nativeRequestID string) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(20 * time.Second)
	var raw []byte
	for {
		// The action id isn't known to the test; find the newest delivery
		// job and use it (each subtest uses a fresh tenant-scoped action).
		err := stack.Pool.QueryRow(ctx,
			`select args from river_job where kind = 'deliver_approval'
			  order by id desc limit 1`).Scan(&raw)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("delivery job never appeared (native request %s): %v", nativeRequestID, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	var delivered queue.DeliverApprovalArgs
	if err := json.Unmarshal(raw, &delivered); err != nil {
		t.Fatalf("delivery args: %v", err)
	}
	body, _ := json.Marshal(map[string]string{
		"token": delivered.CallbackToken, "decision": "approved",
		"approver_id": "alice", "reason": "test",
	})
	resp, err := http.Post(stack.BaseURL+"/approval/callback", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("callback status %d", resp.StatusCode)
	}
}
