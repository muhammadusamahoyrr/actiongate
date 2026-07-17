// Package gateway is the customer-side core (plan §2): enroll once, then
// route agent actions through the control plane and execute only under a
// verified, unexpired ExecutionGrant. Verification is local and total:
// signature against pinned keys, params_hash against a locally recomputed
// fingerprint, action and tool identity, expiry. A grant that fails any
// check is treated as no grant at all.
package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	actiongatev1 "actiongate/gen/actiongate/v1"
	"actiongate/gen/actiongate/v1/actiongatev1connect"
	"actiongate/internal/fingerprint"
	"actiongate/internal/grant"
)

var (
	ErrDenied      = errors.New("action denied by policy")
	ErrTimedOut    = errors.New("timed out waiting for a decision")
	ErrGrantBad    = errors.New("grant failed local verification")
	ErrNotEnrolled = errors.New("gateway is not enrolled")
)

type Gateway struct {
	State *State
	// HTTPClient defaults to http.DefaultClient.
	HTTPClient *http.Client
	Now        func() time.Time

	// mu guards State.PendingReceipts: the MCP proxy dispatches tool calls
	// concurrently.
	mu sync.Mutex
}

func (g *Gateway) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func (g *Gateway) httpClient() *http.Client {
	if g.HTTPClient != nil {
		return g.HTTPClient
	}
	return http.DefaultClient
}

func (g *Gateway) client() (actiongatev1connect.ControlPlaneServiceClient, error) {
	if g.State == nil || g.State.Credential == "" {
		return nil, ErrNotEnrolled
	}
	return actiongatev1connect.NewControlPlaneServiceClient(
		&http.Client{
			Transport: credentialTransport{
				base:       g.httpClient().Transport,
				credential: g.State.Credential,
			},
			Timeout: g.httpClient().Timeout,
		},
		g.State.ServerURL,
	), nil
}

type credentialTransport struct {
	base       http.RoundTripper
	credential string
}

func (t credentialTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+t.credential)
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

// Enroll performs first-time setup: generates the gateway keypair, exchanges
// the enrollment token, and returns the state to persist. The private key
// never leaves the machine.
func Enroll(ctx context.Context, httpClient *http.Client, serverURL, enrollmentToken, name string) (*State, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	client := actiongatev1connect.NewControlPlaneServiceClient(httpClient, serverURL)
	resp, err := client.Enroll(ctx, connect.NewRequest(&actiongatev1.EnrollRequest{
		ProtocolVersion:  1,
		EnrollmentToken:  enrollmentToken,
		GatewayName:      name,
		GatewayPublicKey: pub,
	}))
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	controlKeys := map[string]string{}
	for _, k := range resp.Msg.GetControlPlaneKeys() {
		controlKeys[k.GetKeyId()] = base64.StdEncoding.EncodeToString(k.GetPublicKey())
	}
	return &State{
		ServerURL:       serverURL,
		GatewayID:       resp.Msg.GetGatewayId(),
		TenantID:        resp.Msg.GetTenantId(),
		Credential:      string(resp.Msg.GetGatewayCredential()),
		PrivateKeySeed:  base64.StdEncoding.EncodeToString(priv.Seed()),
		ControlKeys:     controlKeys,
		PendingReceipts: map[string]Grant{},
	}, nil
}

type CheckInput struct {
	AgentID         string
	SessionID       string
	NativeRequestID string
	ToolName        string
	Params          map[string]any
	Environment     string
	// Wait bounds how long to poll for a human decision; zero means a
	// single submit with no polling.
	Wait time.Duration
}

type CheckResult struct {
	Allowed     bool
	ActionID    string
	Grant       Grant
	RuleID      string
	Explanation string
}

// Check submits the action and resolves it to allowed (with a verified
// grant, remembered for Report) or denied. Pending decisions are polled
// until Wait elapses.
func (g *Gateway) Check(ctx context.Context, in CheckInput) (CheckResult, error) {
	client, err := g.client()
	if err != nil {
		return CheckResult{}, err
	}
	params, err := structpb.NewStruct(in.Params)
	if err != nil {
		return CheckResult{}, fmt.Errorf("params: %w", err)
	}
	resp, err := client.SubmitAction(ctx, connect.NewRequest(&actiongatev1.SubmitActionRequest{
		ProtocolVersion: 1,
		SessionId:       in.SessionID,
		NativeRequestId: in.NativeRequestID,
		AgentId:         in.AgentID,
		ToolName:        in.ToolName,
		ToolParams:      params,
		Environment:     in.Environment,
	}))
	if err != nil {
		return CheckResult{}, fmt.Errorf("submit: %w", err)
	}

	switch r := resp.Msg.GetResult().(type) {
	case *actiongatev1.SubmitActionResponse_Authorized:
		return g.acceptGrant(in, r.Authorized.GetActionId(), r.Authorized.GetGrant())
	case *actiongatev1.SubmitActionResponse_Denied:
		return CheckResult{
			Allowed: false, ActionID: r.Denied.GetActionId(),
			RuleID: r.Denied.GetMatchedRuleId(), Explanation: r.Denied.GetExplanation(),
		}, ErrDenied
	case *actiongatev1.SubmitActionResponse_Pending:
		return g.poll(ctx, client, in, r.Pending.GetActionId())
	case *actiongatev1.SubmitActionResponse_Completed:
		return CheckResult{Allowed: false, ActionID: r.Completed.GetActionId()},
			fmt.Errorf("action already completed with status %s", r.Completed.GetStatus())
	default:
		return CheckResult{}, fmt.Errorf("unexpected response %T", r)
	}
}

func (g *Gateway) poll(ctx context.Context, client actiongatev1connect.ControlPlaneServiceClient, in CheckInput, actionID string) (CheckResult, error) {
	deadline := g.now().Add(in.Wait)
	for {
		if g.now().After(deadline) {
			return CheckResult{ActionID: actionID}, ErrTimedOut
		}
		select {
		case <-ctx.Done():
			return CheckResult{ActionID: actionID}, ctx.Err()
		case <-time.After(time.Second):
		}
		status, err := client.GetActionStatus(ctx, connect.NewRequest(&actiongatev1.GetActionStatusRequest{
			ProtocolVersion: 1, ActionId: actionID,
		}))
		if err != nil {
			return CheckResult{ActionID: actionID}, fmt.Errorf("poll: %w", err)
		}
		switch status.Msg.GetState() {
		case actiongatev1.ActionState_ACTION_STATE_EXECUTION_AUTHORIZED:
			return g.acceptGrant(in, actionID, status.Msg.GetGrant())
		case actiongatev1.ActionState_ACTION_STATE_DENIED:
			return CheckResult{Allowed: false, ActionID: actionID, Explanation: "denied by approver or policy"}, ErrDenied
		case actiongatev1.ActionState_ACTION_STATE_EXPIRED:
			return CheckResult{Allowed: false, ActionID: actionID, Explanation: "approval expired"}, ErrDenied
		case actiongatev1.ActionState_ACTION_STATE_CANCELLED,
			actiongatev1.ActionState_ACTION_STATE_SUPERSEDED_BY_POLICY:
			return CheckResult{Allowed: false, ActionID: actionID, Explanation: "withdrawn"}, ErrDenied
		}
	}
}

// acceptGrant is the trust boundary: nothing executes unless every check
// passes against locally held keys and locally recomputed content identity.
func (g *Gateway) acceptGrant(in CheckInput, actionID string, envelope *actiongatev1.GrantEnvelope) (CheckResult, error) {
	if envelope == nil {
		return CheckResult{ActionID: actionID}, fmt.Errorf("%w: no envelope", ErrGrantBad)
	}
	envelopeBytes, err := proto.Marshal(envelope)
	if err != nil {
		return CheckResult{ActionID: actionID}, fmt.Errorf("%w: %v", ErrGrantBad, err)
	}
	keys, err := g.State.PublicKeys()
	if err != nil {
		return CheckResult{ActionID: actionID}, err
	}
	verified, err := grant.Verify(envelopeBytes, keys, g.now())
	if err != nil {
		return CheckResult{ActionID: actionID}, fmt.Errorf("%w: %v", ErrGrantBad, err)
	}
	if verified.GetActionId() != actionID || verified.GetToolName() != in.ToolName {
		return CheckResult{ActionID: actionID}, fmt.Errorf("%w: grant is for a different action or tool", ErrGrantBad)
	}
	canonical, err := canonicalParams(in.Params)
	if err != nil {
		return CheckResult{ActionID: actionID}, err
	}
	localFingerprint, err := fingerprint.Fingerprint(in.AgentID, in.ToolName, canonical)
	if err != nil {
		return CheckResult{ActionID: actionID}, err
	}
	if string(localFingerprint) != string(verified.GetParamsHash()) {
		return CheckResult{ActionID: actionID}, fmt.Errorf("%w: params_hash does not match this request's content", ErrGrantBad)
	}

	stored := Grant{
		GrantID:   verified.GetGrantId(),
		ActionID:  actionID,
		ExpiresAt: verified.GetExpiresAt().AsTime(),
	}
	g.mu.Lock()
	g.State.PendingReceipts[actionID] = stored
	g.mu.Unlock()
	return CheckResult{Allowed: true, ActionID: actionID, Grant: stored}, nil
}

type ReportInput struct {
	ActionID    string
	Status      string // "success" | "failure" | "partial"
	Error       string
	OutputRef   string
	SideEffects []string
	StartedAt   time.Time
	CompletedAt time.Time
}

type ReportResult struct {
	Accepted  bool
	Duplicate bool
}

// Report signs and submits the outcome receipt for a previously checked
// action, then forgets the local grant.
func (g *Gateway) Report(ctx context.Context, in ReportInput) (ReportResult, error) {
	client, err := g.client()
	if err != nil {
		return ReportResult{}, err
	}
	g.mu.Lock()
	stored, ok := g.State.PendingReceipts[in.ActionID]
	g.mu.Unlock()
	if !ok {
		return ReportResult{}, fmt.Errorf("no pending grant for action %s", in.ActionID)
	}
	priv, err := g.State.PrivateKey()
	if err != nil {
		return ReportResult{}, err
	}
	status, err := statusFor(in.Status)
	if err != nil {
		return ReportResult{}, err
	}
	startedAt := in.StartedAt
	if startedAt.IsZero() {
		startedAt = g.now()
	}
	completedAt := in.CompletedAt
	if completedAt.IsZero() {
		completedAt = g.now()
	}
	receipt := &actiongatev1.OutcomeReceipt{
		GrantId:     stored.GrantID,
		ActionId:    in.ActionID,
		Status:      status,
		StartedAt:   timestamppb.New(startedAt),
		CompletedAt: timestamppb.New(completedAt),
		Error:       in.Error,
		OutputRef:   in.OutputRef,
		SideEffects: in.SideEffects,
	}
	envelopeBytes, err := grant.SignReceipt(priv, g.State.GatewayID, receipt)
	if err != nil {
		return ReportResult{}, err
	}
	var envelope actiongatev1.ReceiptEnvelope
	if err := proto.Unmarshal(envelopeBytes, &envelope); err != nil {
		return ReportResult{}, err
	}
	resp, err := client.ReportOutcome(ctx, connect.NewRequest(&actiongatev1.ReportOutcomeRequest{
		ProtocolVersion: 1, Receipt: &envelope,
	}))
	if err != nil {
		return ReportResult{}, fmt.Errorf("report: %w", err)
	}
	g.mu.Lock()
	delete(g.State.PendingReceipts, in.ActionID)
	g.mu.Unlock()
	return ReportResult{
		Accepted:  resp.Msg.GetAccepted(),
		Duplicate: resp.Msg.GetDuplicate(),
	}, nil
}

// canonicalParams reproduces the control plane's canonical bytes exactly:
// the params round-trip structpb (normalizing numbers) and marshal with
// Go's sorted-key JSON encoding — the same sequence the server performs on
// receipt. Both sides computing the same bytes is what makes params_hash
// verifiable.
func canonicalParams(params map[string]any) ([]byte, error) {
	st, err := structpb.NewStruct(params)
	if err != nil {
		return nil, fmt.Errorf("params: %w", err)
	}
	return json.Marshal(st.AsMap())
}

func statusFor(s string) (actiongatev1.ExecutionStatus, error) {
	switch s {
	case "success":
		return actiongatev1.ExecutionStatus_EXECUTION_STATUS_SUCCEEDED, nil
	case "failure":
		return actiongatev1.ExecutionStatus_EXECUTION_STATUS_FAILED, nil
	case "partial":
		return actiongatev1.ExecutionStatus_EXECUTION_STATUS_PARTIALLY_SUCCEEDED, nil
	default:
		return 0, fmt.Errorf("unknown status %q (want success|failure|partial)", s)
	}
}
