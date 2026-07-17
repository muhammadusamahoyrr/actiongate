package server_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	actiongatev1 "github.com/muhammadusamahoyrr/actiongate/gen/actiongate/v1"
	"github.com/muhammadusamahoyrr/actiongate/gen/actiongate/v1/actiongatev1connect"
	"github.com/muhammadusamahoyrr/actiongate/internal/grant"
	"github.com/muhammadusamahoyrr/actiongate/internal/queue"
	"github.com/muhammadusamahoyrr/actiongate/internal/servertest"
)

type wireWorld struct {
	pool     *pgxpool.Pool
	baseURL  string
	tenantID uuid.UUID
	stack    *servertest.Stack
	client   actiongatev1connect.ControlPlaneServiceClient // unauthenticated
}

func setupWire(t *testing.T) *wireWorld {
	t.Helper()
	stack := servertest.Setup(t)
	return &wireWorld{
		pool: stack.Pool, baseURL: stack.BaseURL, tenantID: stack.TenantID, stack: stack,
		client: actiongatev1connect.NewControlPlaneServiceClient(http.DefaultClient, stack.BaseURL),
	}
}

func (w *wireWorld) seedEnrollmentToken(t *testing.T) string {
	t.Helper()
	return w.stack.SeedEnrollmentToken(t)
}

type enrolledGateway struct {
	client actiongatev1connect.ControlPlaneServiceClient
	keys   map[string]ed25519.PublicKey
	priv   ed25519.PrivateKey
	id     string
}

func (w *wireWorld) enroll(t *testing.T) enrolledGateway {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gateway key: %v", err)
	}
	resp, err := w.client.Enroll(context.Background(), connect.NewRequest(&actiongatev1.EnrollRequest{
		ProtocolVersion: 1, EnrollmentToken: w.seedEnrollmentToken(t),
		GatewayName: "test-gw", GatewayPublicKey: pub,
	}))
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	keys := map[string]ed25519.PublicKey{}
	for _, k := range resp.Msg.GetControlPlaneKeys() {
		keys[k.GetKeyId()] = ed25519.PublicKey(k.GetPublicKey())
	}
	credential := string(resp.Msg.GetGatewayCredential())
	authed := actiongatev1connect.NewControlPlaneServiceClient(
		&http.Client{Transport: authTransport{credential: credential}},
		w.baseURL,
	)
	return enrolledGateway{client: authed, keys: keys, priv: priv, id: resp.Msg.GetGatewayId()}
}

type authTransport struct{ credential string }

func (a authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+a.credential)
	return http.DefaultTransport.RoundTrip(req)
}

func submit(t *testing.T, gw enrolledGateway, tool string, params map[string]any) *actiongatev1.SubmitActionResponse {
	t.Helper()
	st, err := structpb.NewStruct(params)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	resp, err := gw.client.SubmitAction(context.Background(), connect.NewRequest(&actiongatev1.SubmitActionRequest{
		ProtocolVersion: 1, SessionId: uuid.NewString(), NativeRequestId: uuid.NewString(),
		AgentId: "agent-1", ToolName: tool, ToolParams: st, Environment: "test",
	}))
	if err != nil {
		t.Fatalf("SubmitAction: %v", err)
	}
	return resp.Msg
}

func report(t *testing.T, gw enrolledGateway, g *actiongatev1.ExecutionGrant, status actiongatev1.ExecutionStatus) *actiongatev1.ReportOutcomeResponse {
	t.Helper()
	receiptEnvelope, err := grant.SignReceipt(gw.priv, gw.id, &actiongatev1.OutcomeReceipt{
		GrantId: g.GetGrantId(), ActionId: g.GetActionId(), Status: status,
		StartedAt:   timestamppb.New(time.Now().Add(-time.Second)),
		CompletedAt: timestamppb.Now(),
	})
	if err != nil {
		t.Fatalf("sign receipt: %v", err)
	}
	var envelope actiongatev1.ReceiptEnvelope
	if err := proto.Unmarshal(receiptEnvelope, &envelope); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	resp, err := gw.client.ReportOutcome(context.Background(), connect.NewRequest(&actiongatev1.ReportOutcomeRequest{
		ProtocolVersion: 1, Receipt: &envelope,
	}))
	if err != nil {
		t.Fatalf("ReportOutcome: %v", err)
	}
	return resp.Msg
}

// waitForDeliveryToken polls for the queued approval delivery job of an
// action and returns its callback token — standing in for the channel.
func waitForDeliveryToken(t *testing.T, w *wireWorld, actionID string) string {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var raw []byte
	for {
		err := w.pool.QueryRow(context.Background(),
			`select args from river_job
			  where kind = 'deliver_approval' and args->>'action_id' = $1`,
			actionID).Scan(&raw)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("delivery job never appeared: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	var delivered queue.DeliverApprovalArgs
	if err := json.Unmarshal(raw, &delivered); err != nil {
		t.Fatalf("delivery args: %v", err)
	}
	return delivered.CallbackToken
}

func TestWire(t *testing.T) {
	w := setupWire(t)
	ctx := context.Background()

	t.Run("enrollment token is single use", func(t *testing.T) {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		token := w.seedEnrollmentToken(t)
		if _, err := w.client.Enroll(ctx, connect.NewRequest(&actiongatev1.EnrollRequest{
			EnrollmentToken: token, GatewayName: "gw-1", GatewayPublicKey: pub,
		})); err != nil {
			t.Fatalf("first enroll: %v", err)
		}
		_, err := w.client.Enroll(ctx, connect.NewRequest(&actiongatev1.EnrollRequest{
			EnrollmentToken: token, GatewayName: "gw-2", GatewayPublicKey: pub,
		}))
		if connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("replayed token: want PermissionDenied, got %v", err)
		}
	})

	t.Run("unauthenticated calls are rejected", func(t *testing.T) {
		_, err := w.client.SubmitAction(ctx, connect.NewRequest(&actiongatev1.SubmitActionRequest{}))
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("want Unauthenticated, got %v", err)
		}
	})

	t.Run("allow, execute, report: the full happy path over the wire", func(t *testing.T) {
		gw := w.enroll(t)
		resp := submit(t, gw, "bash", map[string]any{"command": "ls"})
		authorized := resp.GetAuthorized()
		if authorized == nil {
			t.Fatalf("want authorized, got %v", resp)
		}
		envBytes, err := proto.Marshal(authorized.GetGrant())
		if err != nil {
			t.Fatalf("marshal envelope: %v", err)
		}
		g, err := grant.Verify(envBytes, gw.keys, time.Now())
		if err != nil {
			t.Fatalf("grant does not verify with enrolled keys: %v", err)
		}

		first := report(t, gw, g, actiongatev1.ExecutionStatus_EXECUTION_STATUS_SUCCEEDED)
		if !first.GetAccepted() || first.GetDuplicate() {
			t.Fatalf("first receipt: %+v", first)
		}
		second := report(t, gw, g, actiongatev1.ExecutionStatus_EXECUTION_STATUS_SUCCEEDED)
		if second.GetAccepted() || !second.GetDuplicate() {
			t.Fatalf("second receipt must be duplicate: %+v", second)
		}

		status, err := gw.client.GetActionStatus(ctx, connect.NewRequest(&actiongatev1.GetActionStatusRequest{
			ActionId: authorized.GetActionId(),
		}))
		if err != nil {
			t.Fatalf("GetActionStatus: %v", err)
		}
		if status.Msg.GetState() != actiongatev1.ActionState_ACTION_STATE_SUCCEEDED {
			t.Fatalf("state = %s", status.Msg.GetState())
		}
		if status.Msg.GetOutcome().GetStatus() != actiongatev1.ExecutionStatus_EXECUTION_STATUS_SUCCEEDED {
			t.Fatalf("outcome = %+v", status.Msg.GetOutcome())
		}
	})

	t.Run("deny is explained over the wire", func(t *testing.T) {
		gw := w.enroll(t)
		resp := submit(t, gw, "read_file", map[string]any{"path": "/app/.env"})
		denied := resp.GetDenied()
		if denied == nil || denied.GetMatchedRuleId() != "deny-secrets" {
			t.Fatalf("want denied by deny-secrets, got %v", resp)
		}
	})

	t.Run("approval loop: pending, callback approve, poll to authorized", func(t *testing.T) {
		gw := w.enroll(t)
		resp := submit(t, gw, "bash", map[string]any{"command": "rm -rf /tmp/x"})
		pending := resp.GetPending()
		if pending == nil {
			t.Fatalf("want pending, got %v", resp)
		}

		// Recover the callback token as the notification channel would.
		var deliveryArgs []byte
		deadline := time.Now().Add(15 * time.Second)
		for {
			err := w.pool.QueryRow(ctx,
				`select args from river_job
				  where kind = 'deliver_approval' and args->>'action_id' = $1`,
				pending.GetActionId()).Scan(&deliveryArgs)
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("delivery job never appeared: %v", err)
			}
			time.Sleep(100 * time.Millisecond)
		}
		var delivered queue.DeliverApprovalArgs
		if err := json.Unmarshal(deliveryArgs, &delivered); err != nil {
			t.Fatalf("delivery args: %v", err)
		}

		body, _ := json.Marshal(map[string]string{
			"token": delivered.CallbackToken, "decision": "approved",
			"approver_id": "alice", "reason": "reviewed",
		})
		cb, err := http.Post(w.baseURL+"/approval/callback", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("callback: %v", err)
		}
		defer func() { _ = cb.Body.Close() }()
		if cb.StatusCode != http.StatusOK {
			t.Fatalf("callback status %d", cb.StatusCode)
		}

		// The running worker authorizes; poll like a real gateway.
		var g *actiongatev1.ExecutionGrant
		deadline = time.Now().Add(20 * time.Second)
		for {
			status, err := gw.client.GetActionStatus(ctx, connect.NewRequest(&actiongatev1.GetActionStatusRequest{
				ActionId: pending.GetActionId(),
			}))
			if err != nil {
				t.Fatalf("GetActionStatus: %v", err)
			}
			if status.Msg.GetState() == actiongatev1.ActionState_ACTION_STATE_EXECUTION_AUTHORIZED {
				envBytes, err := proto.Marshal(status.Msg.GetGrant())
				if err != nil {
					t.Fatalf("marshal envelope: %v", err)
				}
				if g, err = grant.Verify(envBytes, gw.keys, time.Now()); err != nil {
					t.Fatalf("polled grant does not verify: %v", err)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("never authorized; state %s", status.Msg.GetState())
			}
			time.Sleep(200 * time.Millisecond)
		}

		outcome := report(t, gw, g, actiongatev1.ExecutionStatus_EXECUTION_STATUS_FAILED)
		if !outcome.GetAccepted() {
			t.Fatalf("failed receipt not accepted: %+v", outcome)
		}
	})

	t.Run("slack button click resolves an approval", func(t *testing.T) {
		gw := w.enroll(t)
		resp := submit(t, gw, "bash", map[string]any{"command": "rm -rf /tmp/slack"})
		pending := resp.GetPending()
		if pending == nil {
			t.Fatalf("want pending, got %v", resp)
		}
		token := waitForDeliveryToken(t, w, pending.GetActionId())

		payload, _ := json.Marshal(map[string]any{
			"type": "block_actions",
			"user": map[string]any{"id": "U-ALICE"},
			"actions": []map[string]any{{
				"type": "button", "action_id": "approve",
				"block_id": "actiongate_approval", "value": token,
			}},
		})
		body := "payload=" + url.QueryEscape(string(payload))

		post := func(signingSecret string) *http.Response {
			ts := fmt.Sprintf("%d", time.Now().Unix())
			mac := hmac.New(sha256.New, []byte(signingSecret))
			mac.Write([]byte("v0:" + ts + ":" + body))
			req, err := http.NewRequest(http.MethodPost, w.baseURL+"/slack/interaction",
				strings.NewReader(body))
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-Slack-Request-Timestamp", ts)
			req.Header.Set("X-Slack-Signature", "v0="+hex.EncodeToString(mac.Sum(nil)))
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			return res
		}

		// A forged signature must be rejected before anything resolves.
		forged := post("wrong-secret")
		_ = forged.Body.Close()
		if forged.StatusCode != http.StatusForbidden {
			t.Fatalf("forged signature: status %d, want 403", forged.StatusCode)
		}

		genuine := post(servertest.SlackSigningSecret)
		defer func() { _ = genuine.Body.Close() }()
		if genuine.StatusCode != http.StatusOK {
			t.Fatalf("genuine signature: status %d", genuine.StatusCode)
		}

		// The approval resolved with the Slack identity; the worker takes it
		// on to ExecutionAuthorized.
		deadline := time.Now().Add(20 * time.Second)
		for {
			status, err := gw.client.GetActionStatus(ctx, connect.NewRequest(&actiongatev1.GetActionStatusRequest{
				ActionId: pending.GetActionId(),
			}))
			if err != nil {
				t.Fatalf("GetActionStatus: %v", err)
			}
			if status.Msg.GetState() == actiongatev1.ActionState_ACTION_STATE_EXECUTION_AUTHORIZED {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("never authorized; state %s", status.Msg.GetState())
			}
			time.Sleep(200 * time.Millisecond)
		}
		var attestedBy string
		if err := w.pool.QueryRow(ctx,
			`select attested_by from audit_events
			  where tenant_id = $1 and action_request_id = $2 and event_type = 'ApprovalGranted'`,
			w.tenantID, pending.GetActionId()).Scan(&attestedBy); err != nil {
			t.Fatalf("event: %v", err)
		}
		if attestedBy != "operator:slack:U-ALICE" {
			t.Fatalf("attested_by = %q", attestedBy)
		}
	})

	t.Run("receipt signed with the wrong key is rejected", func(t *testing.T) {
		gw := w.enroll(t)
		resp := submit(t, gw, "bash", map[string]any{"command": "ls"})
		authorized := resp.GetAuthorized()
		if authorized == nil {
			t.Fatalf("want authorized, got %v", resp)
		}
		envBytes, _ := proto.Marshal(authorized.GetGrant())
		g, err := grant.Verify(envBytes, gw.keys, time.Now())
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
		forged := gw
		forged.priv = wrongPriv
		receiptEnvelope, err := grant.SignReceipt(forged.priv, forged.id, &actiongatev1.OutcomeReceipt{
			GrantId: g.GetGrantId(), ActionId: g.GetActionId(),
			Status:    actiongatev1.ExecutionStatus_EXECUTION_STATUS_SUCCEEDED,
			StartedAt: timestamppb.Now(),
		})
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		var envelope actiongatev1.ReceiptEnvelope
		_ = proto.Unmarshal(receiptEnvelope, &envelope)
		_, err = gw.client.ReportOutcome(ctx, connect.NewRequest(&actiongatev1.ReportOutcomeRequest{Receipt: &envelope}))
		if connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("want PermissionDenied, got %v", err)
		}
	})
}
