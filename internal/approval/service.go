// Package approval is the ApprovalService (plan §3, §9): resolves the
// approver from the risk classification, creates the ApprovalRequest with
// its callback token, expiry timer, and delivery job in ONE transaction,
// and resolves decisions with compare-and-swap so concurrent approvers
// cannot double-resolve. It never knows policy rules and never executes.
package approval

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"

	"actiongate/internal/domain"
	"actiongate/internal/queue"
	"actiongate/internal/transition"
)

var (
	ErrTokenExpired    = errors.New("callback token expired")
	ErrAlreadyResolved = errors.New("approval already resolved")
	ErrNotAwaiting     = errors.New("action is not awaiting approval request")
)

const DefaultExpiry = time.Hour

// Router maps a risk classification to an approver target (plan §9 step 2:
// the ApprovalService resolves the approver, never the PolicyEngine).
type Router struct {
	Targets map[string]string
	Default string
}

func (r Router) Resolve(classification string) string {
	if target, ok := r.Targets[classification]; ok {
		return target
	}
	return r.Default
}

type Service struct {
	Pool        *pgxpool.Pool
	Queue       *river.Client[pgx.Tx]
	TokenSecret []byte
	Router      Router
	Expiry      time.Duration
	Now         func() time.Time
}

func (s *Service) expiry() time.Duration {
	if s.Expiry > 0 {
		return s.Expiry
	}
	return DefaultExpiry
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

type RequestInput struct {
	TenantID           uuid.UUID
	ActionID           uuid.UUID
	StreamID           uuid.UUID
	RiskClassification string
	MatchedRuleID      string
	Title              string
	Body               string
}

type Requested struct {
	ApprovalRequestID uuid.UUID
	ApproverTarget    string
	ExpiresAt         time.Time
	// Token is the raw callback credential, returned for delivery paths and
	// tests; it is stored only as a hash.
	Token string
}

// Request performs the Evaluated → PendingApproval transition. Everything an
// approval needs to be safe exists atomically or not at all: the approval
// row, its token, its expiry timer, and its delivery job commit with the
// state change and the ApprovalRequested event (plan round 5 fix 2).
func (s *Service) Request(ctx context.Context, in RequestInput) (Requested, error) {
	state, version, err := transition.CurrentState(ctx, s.Pool, in.TenantID, in.ActionID)
	if err != nil {
		return Requested{}, err
	}
	if state != domain.StateEvaluated {
		return Requested{}, fmt.Errorf("%w: action is %s", ErrNotAwaiting, state)
	}

	approvalID, err := uuid.NewV7()
	if err != nil {
		return Requested{}, fmt.Errorf("uuidv7: %w", err)
	}
	token, tokenHash, err := mintToken(s.TokenSecret, in.TenantID)
	if err != nil {
		return Requested{}, err
	}
	target := s.Router.Resolve(in.RiskClassification)
	now := s.now().UTC()
	expiresAt := now.Add(s.expiry())

	err = transition.Apply(ctx, s.Pool, transition.Request{
		TenantID:        in.TenantID,
		ActionID:        in.ActionID,
		From:            domain.StateEvaluated,
		To:              domain.StatePendingApproval,
		ExpectedVersion: version,
		Event: transition.Event{
			StreamID:   in.StreamID,
			Type:       domain.EventApprovalRequested,
			AttestedBy: domain.AttestedByControlPlane,
			Metadata: map[string]any{
				"approval_request_id": approvalID.String(),
				"approver_target":     target,
				"risk_classification": in.RiskClassification,
				"matched_rule_id":     in.MatchedRuleID,
			},
		},
		Effects: []transition.Effect{
			func(ctx context.Context, tx pgx.Tx) error {
				_, err := tx.Exec(ctx,
					`insert into approval_requests
					    (id, tenant_id, action_request_id, approver_target, status, version, expires_at, created_at)
					 values ($1, $2, $3, $4, 'pending', 0, $5, $6)`,
					approvalID, in.TenantID, in.ActionID, target, expiresAt, now)
				return err
			},
			func(ctx context.Context, tx pgx.Tx) error {
				_, err := tx.Exec(ctx,
					`insert into approval_callback_tokens
					    (token_hash, tenant_id, approval_request_id, expires_at)
					 values ($1, $2, $3, $4)`,
					tokenHash, in.TenantID, approvalID, expiresAt)
				return err
			},
			queue.InsertJobEffect(s.Queue, queue.ApprovalExpiryArgs{
				TenantID: in.TenantID, ActionID: in.ActionID,
				ApprovalRequestID: approvalID, StreamID: in.StreamID,
			}, &river.InsertOpts{ScheduledAt: expiresAt}),
			queue.InsertJobEffect(s.Queue, queue.DeliverApprovalArgs{
				TenantID: in.TenantID, ActionID: in.ActionID,
				ApprovalRequestID: approvalID, ApproverTarget: target,
				Title: in.Title, Body: in.Body, CallbackToken: token,
			}, nil),
		},
	})
	if err != nil {
		return Requested{}, err
	}
	return Requested{
		ApprovalRequestID: approvalID,
		ApproverTarget:    target,
		ExpiresAt:         expiresAt,
		Token:             token,
	}, nil
}

type Resolution struct {
	ActionID          uuid.UUID
	ApprovalRequestID uuid.UUID
	Decision          string
	NewState          domain.State
}

// Resolve authenticates the callback token, then applies the decision as one
// transaction: action_state CAS first (the §20.2.1 lock order), then the
// token's single-use mark, the approval row's version CAS, and the
// ApprovalDecision record. A concurrent resolver loses the CAS and gets
// ErrAlreadyResolved — the plan §9 double-approval race, closed.
func (s *Service) Resolve(ctx context.Context, token, decision, approverID, reason string) (Resolution, error) {
	if decision != "approved" && decision != "denied" {
		return Resolution{}, fmt.Errorf("unknown decision %q", decision)
	}
	tenantID, tokenHash, err := parseToken(s.TokenSecret, token)
	if err != nil {
		return Resolution{}, err
	}

	// Load the token's world under the tenant's RLS scope.
	var (
		approvalID uuid.UUID
		actionID   uuid.UUID
		usedAt     *time.Time
		expiresAt  time.Time
		status     string
		version    int32
	)
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Resolution{}, fmt.Errorf("begin: %w", err)
	}
	if _, err := tx.Exec(ctx, `select set_config('app.tenant_id', $1, true)`, tenantID.String()); err != nil {
		_ = tx.Rollback(ctx)
		return Resolution{}, fmt.Errorf("set tenant: %w", err)
	}
	err = tx.QueryRow(ctx,
		`select t.approval_request_id, t.used_at, t.expires_at,
		        a.action_request_id, a.status, a.version
		   from approval_callback_tokens t
		   join approval_requests a on a.id = t.approval_request_id
		  where t.token_hash = $1`,
		tokenHash,
	).Scan(&approvalID, &usedAt, &expiresAt, &actionID, &status, &version)
	_ = tx.Rollback(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return Resolution{}, ErrTokenInvalid
	}
	if err != nil {
		return Resolution{}, fmt.Errorf("load token: %w", err)
	}
	switch {
	case usedAt != nil, status != "pending":
		return Resolution{}, ErrAlreadyResolved
	case s.now().After(expiresAt):
		return Resolution{}, ErrTokenExpired
	}

	streamID, err := s.streamOf(ctx, tenantID, actionID)
	if err != nil {
		return Resolution{}, err
	}
	actionState, actionVersion, err := transition.CurrentState(ctx, s.Pool, tenantID, actionID)
	if err != nil {
		return Resolution{}, err
	}
	if actionState != domain.StatePendingApproval {
		return Resolution{}, ErrAlreadyResolved
	}

	toState := domain.StateApproved
	eventType := domain.EventApprovalGranted
	if decision == "denied" {
		toState = domain.StateDenied
		eventType = domain.EventApprovalDenied
	}
	decisionID, err := uuid.NewV7()
	if err != nil {
		return Resolution{}, fmt.Errorf("uuidv7: %w", err)
	}
	decidedAt := s.now().UTC()

	err = transition.Apply(ctx, s.Pool, transition.Request{
		TenantID:        tenantID,
		ActionID:        actionID,
		From:            domain.StatePendingApproval,
		To:              toState,
		ExpectedVersion: actionVersion,
		Event: transition.Event{
			StreamID:   streamID,
			Type:       eventType,
			AttestedBy: domain.AttestedByOperator + ":" + approverID,
			Metadata: map[string]any{
				"approval_request_id": approvalID.String(),
				"approver_id":         approverID,
				"reason":              reason,
			},
		},
		Effects: []transition.Effect{
			func(ctx context.Context, tx pgx.Tx) error {
				tag, err := tx.Exec(ctx,
					`update approval_callback_tokens set used_at = $1
					  where token_hash = $2 and used_at is null`,
					decidedAt, tokenHash)
				if err != nil {
					return fmt.Errorf("mark token used: %w", err)
				}
				if tag.RowsAffected() != 1 {
					return fmt.Errorf("token replay lost the race: %w", ErrAlreadyResolved)
				}
				return nil
			},
			func(ctx context.Context, tx pgx.Tx) error {
				tag, err := tx.Exec(ctx,
					`update approval_requests
					    set status = $1, version = version + 1
					  where id = $2 and status = 'pending' and version = $3`,
					decision, approvalID, version)
				if err != nil {
					return fmt.Errorf("resolve approval: %w", err)
				}
				if tag.RowsAffected() != 1 {
					return fmt.Errorf("approval version conflict: %w", ErrAlreadyResolved)
				}
				return nil
			},
			func(ctx context.Context, tx pgx.Tx) error {
				_, err := tx.Exec(ctx,
					`insert into approval_decisions
					    (id, tenant_id, approval_request_id, approver_id, decision, reason, decided_at)
					 values ($1, $2, $3, $4, $5, $6, $7)`,
					decisionID, tenantID, approvalID, approverID, decision, reason, decidedAt)
				return err
			},
			func(ctx context.Context, tx pgx.Tx) error {
				// An approval is a promise to execute: the authorization job
				// commits with the decision so a crash between "approved"
				// and "grant issued" recovers through the queue.
				if decision != "approved" {
					return nil
				}
				return queue.InsertJobEffect(s.Queue, queue.AuthorizeExecutionArgs{
					TenantID: tenantID, ActionID: actionID, StreamID: streamID,
				}, nil)(ctx, tx)
			},
		},
	})
	if err != nil {
		if errors.Is(err, transition.ErrVersionConflict) || errors.Is(err, transition.ErrInvalidTransition) {
			return Resolution{}, ErrAlreadyResolved
		}
		return Resolution{}, err
	}
	return Resolution{
		ActionID:          actionID,
		ApprovalRequestID: approvalID,
		Decision:          decision,
		NewState:          toState,
	}, nil
}

// streamOf recovers the action's audit stream from its first event — the
// stream is fixed at ActionCreated and every later event follows it.
func (s *Service) streamOf(ctx context.Context, tenantID, actionID uuid.UUID) (uuid.UUID, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `select set_config('app.tenant_id', $1, true)`, tenantID.String()); err != nil {
		return uuid.Nil, fmt.Errorf("set tenant: %w", err)
	}
	var streamID uuid.UUID
	err = tx.QueryRow(ctx,
		`select stream_id from audit_events
		  where tenant_id = $1 and action_request_id = $2
		  order by ingest_seq limit 1`,
		tenantID, actionID).Scan(&streamID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("resolve stream: %w", err)
	}
	return streamID, nil
}
