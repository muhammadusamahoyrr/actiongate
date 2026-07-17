// Package server binds the wire contract (proto/actiongate/v1) to the
// orchestrated core. It holds no workflow logic: every decision lives in
// the orchestrator, approval service, or coordinator.
package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	actiongatev1 "actiongate/gen/actiongate/v1"
	"actiongate/gen/actiongate/v1/actiongatev1connect"
	"actiongate/internal/approval"
	"actiongate/internal/domain"
	"actiongate/internal/execution"
	"actiongate/internal/grant"
	"actiongate/internal/orchestrator"
)

const (
	protocolVersion = 1
	defaultPollWait = 2 * time.Second
)

type Server struct {
	Pool           *pgxpool.Pool
	Orchestrator   *orchestrator.Orchestrator
	Approvals      *approval.Service
	Coordinator    *execution.Coordinator
	GrantKeyID     string
	GrantPublicKey ed25519.PublicKey
	// SlackSigningSecret enables the /slack/interaction endpoint; empty
	// leaves it unregistered.
	SlackSigningSecret string
	Now                func() time.Time
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Handler returns the http.Handler for the full surface: the ConnectRPC
// service plus the approval callback endpoint.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	path, h := actiongatev1connect.NewControlPlaneServiceHandler(s,
		connect.WithInterceptors(s.authInterceptor()))
	mux.Handle(path, h)
	mux.HandleFunc("POST /approval/callback", s.handleApprovalCallback)
	if s.SlackSigningSecret != "" {
		mux.HandleFunc("POST /slack/interaction", s.handleSlackInteraction)
	}
	return mux
}

type gatewayIdentity struct {
	GatewayID uuid.UUID
	TenantID  uuid.UUID
	PublicKey ed25519.PublicKey
}

type ctxKey struct{}

// authInterceptor authenticates every RPC except Enroll by the gateway's
// bearer credential (stored hashed; the raw credential exists only on the
// gateway). The tenant identity used everywhere downstream comes from this
// lookup — never from request fields.
func (s *Server) authInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if strings.HasSuffix(req.Spec().Procedure, "/Enroll") {
				return next(ctx, req)
			}
			raw := strings.TrimPrefix(req.Header().Get("Authorization"), "Bearer ")
			if raw == "" || raw == req.Header().Get("Authorization") {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing bearer credential"))
			}
			identity, err := s.lookupGateway(ctx, raw)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unknown credential"))
			}
			return next(context.WithValue(ctx, ctxKey{}, identity), req)
		}
	}
}

func identityFrom(ctx context.Context) (gatewayIdentity, error) {
	id, ok := ctx.Value(ctxKey{}).(gatewayIdentity)
	if !ok {
		return gatewayIdentity{}, connect.NewError(connect.CodeUnauthenticated, errors.New("no gateway identity"))
	}
	return id, nil
}

func (s *Server) lookupGateway(ctx context.Context, credential string) (gatewayIdentity, error) {
	sum := sha256.Sum256([]byte(credential))
	var id gatewayIdentity
	var pub []byte
	err := s.Pool.QueryRow(ctx,
		`select gateway_id, tenant_id, public_key from gateways where credential_hash = $1`,
		sum[:]).Scan(&id.GatewayID, &id.TenantID, &pub)
	if err != nil {
		return gatewayIdentity{}, err
	}
	id.PublicKey = ed25519.PublicKey(pub)
	return id, nil
}

func (s *Server) Enroll(ctx context.Context, req *connect.Request[actiongatev1.EnrollRequest]) (*connect.Response[actiongatev1.EnrollResponse], error) {
	m := req.Msg
	if len(m.GetGatewayPublicKey()) != ed25519.PublicKeySize {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("gateway_public_key must be 32 bytes (ed25519)"))
	}
	tokenSum := sha256.Sum256([]byte(m.GetEnrollmentToken()))

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("randomness: %w", err))
	}
	credential := "agc_" + base64.RawURLEncoding.EncodeToString(secret)
	credentialSum := sha256.Sum256([]byte(credential))
	gatewayID, err := uuid.NewV7()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	now := s.now().UTC()

	// Token single-use mark and gateway creation commit together.
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var tenantID uuid.UUID
	err = tx.QueryRow(ctx,
		`update enrollment_tokens set used_at = $1
		  where token_hash = $2 and used_at is null and expires_at > $1
		 returning tenant_id`,
		now, tokenSum[:]).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("enrollment token invalid, used, or expired"))
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if _, err := tx.Exec(ctx,
		`insert into gateways (gateway_id, tenant_id, name, public_key, credential_hash, created_at)
		 values ($1, $2, $3, $4, $5, $6)`,
		gatewayID, tenantID, m.GetGatewayName(), m.GetGatewayPublicKey(), credentialSum[:], now,
	); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&actiongatev1.EnrollResponse{
		GatewayId:         gatewayID.String(),
		TenantId:          tenantID.String(),
		GatewayCredential: []byte(credential),
		ControlPlaneKeys: []*actiongatev1.SigningKey{{
			KeyId:     s.GrantKeyID,
			Algorithm: grant.Algorithm,
			PublicKey: s.GrantPublicKey,
		}},
	}), nil
}

func (s *Server) SubmitAction(ctx context.Context, req *connect.Request[actiongatev1.SubmitActionRequest]) (*connect.Response[actiongatev1.SubmitActionResponse], error) {
	identity, err := identityFrom(ctx)
	if err != nil {
		return nil, err
	}
	m := req.Msg
	sessionID, err := uuid.Parse(m.GetSessionId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("session_id must be a uuid"))
	}
	params, err := json.Marshal(m.GetToolParams().AsMap())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	in := orchestrator.SubmitInput{
		TenantID:        identity.TenantID,
		AgentID:         m.GetAgentId(),
		SessionID:       sessionID,
		NativeRequestID: m.GetNativeRequestId(),
		ToolName:        m.GetToolName(),
		ToolParams:      params,
		Environment:     m.GetEnvironment(),
		StreamID:        streamFor(identity.TenantID),
	}
	if v := m.GetCorrelationId(); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("correlation_id must be a uuid"))
		}
		in.CorrelationID = &id
	}
	if v := m.GetParentActionId(); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("parent_action_id must be a uuid"))
		}
		in.ParentActionID = &id
	}

	res, err := s.Orchestrator.Submit(ctx, in)
	if err != nil {
		return nil, mapSubmitError(err)
	}
	return connect.NewResponse(s.submitResponse(ctx, identity.TenantID, res)), nil
}

func (s *Server) submitResponse(ctx context.Context, tenantID uuid.UUID, res orchestrator.SubmitResult) *actiongatev1.SubmitActionResponse {
	switch res.Kind {
	case orchestrator.KindAuthorized:
		return &actiongatev1.SubmitActionResponse{Result: &actiongatev1.SubmitActionResponse_Authorized{
			Authorized: &actiongatev1.AuthorizedAction{
				ActionId: res.ActionID.String(),
				Grant:    envelopeMessage(res.GrantEnvelope),
			},
		}}
	case orchestrator.KindPending:
		return &actiongatev1.SubmitActionResponse{Result: &actiongatev1.SubmitActionResponse_Pending{
			Pending: &actiongatev1.PendingAction{
				ActionId:  res.ActionID.String(),
				ExpiresAt: timestamppb.New(res.ExpiresAt),
				PollAfter: timestamppb.New(s.now().Add(defaultPollWait)),
			},
		}}
	case orchestrator.KindDenied:
		return &actiongatev1.SubmitActionResponse{Result: &actiongatev1.SubmitActionResponse_Denied{
			Denied: &actiongatev1.DeniedAction{
				ActionId:      res.ActionID.String(),
				MatchedRuleId: res.MatchedRuleID,
				Explanation:   res.Explanation,
			},
		}}
	default: // KindStatus: a resumed action — express it through the same shapes
		switch res.State {
		case domain.StateExecutionAuthorized:
			return &actiongatev1.SubmitActionResponse{Result: &actiongatev1.SubmitActionResponse_Authorized{
				Authorized: &actiongatev1.AuthorizedAction{
					ActionId: res.ActionID.String(),
					Grant:    envelopeMessage(res.GrantEnvelope),
				},
			}}
		case domain.StatePendingApproval, domain.StateCreated, domain.StateEvaluated, domain.StateApproved, domain.StateExecuting:
			return &actiongatev1.SubmitActionResponse{Result: &actiongatev1.SubmitActionResponse_Pending{
				Pending: &actiongatev1.PendingAction{
					ActionId:  res.ActionID.String(),
					PollAfter: timestamppb.New(s.now().Add(defaultPollWait)),
				},
			}}
		default:
			outcome, err := s.Coordinator.Outcome(ctx, tenantID, res.ActionID)
			if err != nil || outcome == nil {
				outcome = &actiongatev1.ActionOutcome{ActionId: res.ActionID.String()}
			}
			return &actiongatev1.SubmitActionResponse{Result: &actiongatev1.SubmitActionResponse_Completed{
				Completed: outcome,
			}}
		}
	}
}

func (s *Server) GetActionStatus(ctx context.Context, req *connect.Request[actiongatev1.GetActionStatusRequest]) (*connect.Response[actiongatev1.GetActionStatusResponse], error) {
	identity, err := identityFrom(ctx)
	if err != nil {
		return nil, err
	}
	actionID, err := uuid.Parse(req.Msg.GetActionId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("action_id must be a uuid"))
	}
	res, err := s.Orchestrator.Status(ctx, identity.TenantID, actionID)
	if err != nil {
		return nil, mapSubmitError(err)
	}
	resp := &actiongatev1.GetActionStatusResponse{
		ActionId:  actionID.String(),
		State:     stateEnum(res.State),
		PollAfter: timestamppb.New(s.now().Add(defaultPollWait)),
	}
	if res.State == domain.StateExecutionAuthorized && res.GrantEnvelope != nil {
		resp.Grant = envelopeMessage(res.GrantEnvelope)
	}
	if domain.IsTerminal(res.State) {
		if outcome, err := s.Coordinator.Outcome(ctx, identity.TenantID, actionID); err == nil && outcome != nil {
			resp.Outcome = outcome
		}
	}
	return connect.NewResponse(resp), nil
}

func (s *Server) ReportOutcome(ctx context.Context, req *connect.Request[actiongatev1.ReportOutcomeRequest]) (*connect.Response[actiongatev1.ReportOutcomeResponse], error) {
	identity, err := identityFrom(ctx)
	if err != nil {
		return nil, err
	}
	envelope := req.Msg.GetReceipt()
	if envelope == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("receipt required"))
	}
	envelopeBytes, err := proto.Marshal(envelope)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	receipt, err := grant.VerifyReceipt(envelopeBytes, identity.PublicKey)
	if err != nil {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("receipt rejected: %w", err))
	}
	accepted, duplicate, err := s.Coordinator.RecordOutcome(ctx, identity.TenantID, identity.GatewayID.String(), receipt)
	if err != nil {
		if errors.Is(err, execution.ErrUnknownGrant) {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&actiongatev1.ReportOutcomeResponse{
		Accepted:  accepted,
		Duplicate: duplicate,
	}), nil
}

// handleApprovalCallback is the channel-agnostic resolution endpoint: the
// Slack implementation (and tests) POST the callback token and decision
// here. The token is the credential; no other auth is required by design.
func (s *Server) handleApprovalCallback(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token      string `json:"token"`
		Decision   string `json:"decision"`
		ApproverID string `json:"approver_id"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
		return
	}
	res, err := s.Approvals.Resolve(r.Context(), body.Token, body.Decision, body.ApproverID, body.Reason)
	switch {
	case err == nil:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"action_id": res.ActionID.String(),
			"state":     string(res.NewState),
		})
	case errors.Is(err, approval.ErrTokenInvalid):
		http.Error(w, `{"error":"token invalid"}`, http.StatusForbidden)
	case errors.Is(err, approval.ErrTokenExpired):
		http.Error(w, `{"error":"token expired"}`, http.StatusGone)
	case errors.Is(err, approval.ErrAlreadyResolved):
		http.Error(w, `{"error":"already resolved"}`, http.StatusConflict)
	default:
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
	}
}

// streamFor gives each tenant one default audit stream in V1: a stable
// UUIDv5 of the tenant id, so every component derives the same stream
// without coordination.
func streamFor(tenantID uuid.UUID) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("actiongate-stream:"+tenantID.String()))
}

func stateEnum(s domain.State) actiongatev1.ActionState {
	switch s {
	case domain.StateCreated:
		return actiongatev1.ActionState_ACTION_STATE_CREATED
	case domain.StateEvaluated:
		return actiongatev1.ActionState_ACTION_STATE_EVALUATED
	case domain.StatePendingApproval:
		return actiongatev1.ActionState_ACTION_STATE_PENDING_APPROVAL
	case domain.StateApproved:
		return actiongatev1.ActionState_ACTION_STATE_APPROVED
	case domain.StateExecutionAuthorized:
		return actiongatev1.ActionState_ACTION_STATE_EXECUTION_AUTHORIZED
	case domain.StateExecuting:
		return actiongatev1.ActionState_ACTION_STATE_EXECUTING
	case domain.StateSucceeded:
		return actiongatev1.ActionState_ACTION_STATE_SUCCEEDED
	case domain.StateFailed:
		return actiongatev1.ActionState_ACTION_STATE_FAILED
	case domain.StatePartiallySucceeded:
		return actiongatev1.ActionState_ACTION_STATE_PARTIALLY_SUCCEEDED
	case domain.StateOutcomeUnknown:
		return actiongatev1.ActionState_ACTION_STATE_OUTCOME_UNKNOWN
	case domain.StateReconciled:
		return actiongatev1.ActionState_ACTION_STATE_RECONCILED
	case domain.StateDenied:
		return actiongatev1.ActionState_ACTION_STATE_DENIED
	case domain.StateExpired:
		return actiongatev1.ActionState_ACTION_STATE_EXPIRED
	case domain.StateCancelled:
		return actiongatev1.ActionState_ACTION_STATE_CANCELLED
	case domain.StateSupersededByPolicy:
		return actiongatev1.ActionState_ACTION_STATE_SUPERSEDED_BY_POLICY
	default:
		return actiongatev1.ActionState_ACTION_STATE_UNSPECIFIED
	}
}

func envelopeMessage(envelopeBytes []byte) *actiongatev1.GrantEnvelope {
	var env actiongatev1.GrantEnvelope
	if err := proto.Unmarshal(envelopeBytes, &env); err != nil {
		return nil
	}
	return &env
}

func mapSubmitError(err error) error {
	return connect.NewError(connect.CodeFailedPrecondition, err)
}
