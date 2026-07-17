// Package orchestrator is the ControlPlaneOrchestrator (plan §3): the ONLY
// component that knows the workflow order. Submit runs intake → policy →
// route (authorize / request approval / deny); Status is the resume path
// for pending actions. It evaluates no policy itself, notifies no one
// itself, and executes nothing itself.
package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/muhammadusamahoyrr/actiongate/internal/approval"
	"github.com/muhammadusamahoyrr/actiongate/internal/domain"
	"github.com/muhammadusamahoyrr/actiongate/internal/execution"
	"github.com/muhammadusamahoyrr/actiongate/internal/policy"
	"github.com/muhammadusamahoyrr/actiongate/internal/transition"
)

type Orchestrator struct {
	Pool        *pgxpool.Pool
	Engine      *policy.Engine
	Approvals   *approval.Service
	Coordinator *execution.Coordinator

	mu       sync.Mutex
	compiled map[snapshotKey]*policy.CompiledSnapshot
}

type snapshotKey struct {
	tenantID uuid.UUID
	version  int64
}

type SubmitInput struct {
	TenantID        uuid.UUID
	AgentID         string
	SessionID       uuid.UUID
	NativeRequestID string
	ToolName        string
	ToolParams      []byte // canonical JSON
	Environment     string
	CorrelationID   *uuid.UUID
	ParentActionID  *uuid.UUID
	StreamID        uuid.UUID
}

type ResultKind string

const (
	KindAuthorized ResultKind = "authorized" // execute under the grant
	KindPending    ResultKind = "pending"    // awaiting a human
	KindDenied     ResultKind = "denied"
	KindStatus     ResultKind = "status" // resume of an in-flight/terminal action
)

type SubmitResult struct {
	Kind          ResultKind
	ActionID      uuid.UUID
	State         domain.State
	GrantEnvelope []byte    // KindAuthorized (and KindStatus when authorized)
	ExpiresAt     time.Time // KindPending: approval deadline
	MatchedRuleID string    // KindDenied
	Explanation   string    // KindDenied (plan §22 explainability)
}

// Submit is the plan §14 handle(): idempotent create → evaluate → route.
// A retry of an already-known request resumes it instead of re-running
// anything (plan §8).
func (o *Orchestrator) Submit(ctx context.Context, in SubmitInput) (SubmitResult, error) {
	snapshot, version, err := o.activeSnapshot(ctx, in.TenantID)
	if err != nil {
		return SubmitResult{}, err
	}

	created, err := transition.Create(ctx, o.Pool, transition.CreateRequest{
		TenantID:        in.TenantID,
		AgentID:         in.AgentID,
		SessionID:       in.SessionID,
		NativeRequestID: in.NativeRequestID,
		ToolName:        in.ToolName,
		ToolParams:      in.ToolParams,
		Environment:     in.Environment,
		CorrelationID:   in.CorrelationID,
		ParentActionID:  in.ParentActionID,
		PolicyVersion:   version,
		StreamID:        in.StreamID,
	})
	if err != nil {
		return SubmitResult{}, err
	}
	if !created.Created {
		return o.resume(ctx, in.TenantID, created.ActionID)
	}
	actionID := created.ActionID

	var params map[string]any
	if err := json.Unmarshal(in.ToolParams, &params); err != nil {
		return SubmitResult{}, fmt.Errorf("params: %w", err)
	}
	decision, err := snapshot.Evaluate(policy.Input{
		AgentID:     in.AgentID,
		ToolName:    in.ToolName,
		Environment: in.Environment,
		Params:      params,
	})
	if err != nil {
		// Fail closed (plan §16): an erroring policy rejects the call; the
		// action stays Created and the error is surfaced, never bypassed.
		return SubmitResult{}, fmt.Errorf("policy evaluation failed closed: %w", err)
	}

	traceJSON, err := json.Marshal(decision.Trace)
	if err != nil {
		return SubmitResult{}, fmt.Errorf("trace: %w", err)
	}
	if err := transition.Apply(ctx, o.Pool, transition.Request{
		TenantID: in.TenantID, ActionID: actionID,
		From: domain.StateCreated, To: domain.StateEvaluated, ExpectedVersion: 0,
		Event: transition.Event{
			StreamID:   in.StreamID,
			Type:       domain.EventPolicyEvaluated,
			AttestedBy: domain.AttestedByControlPlane,
			Metadata: map[string]any{
				"decision":            string(decision.Decision),
				"risk_classification": decision.RiskClassification,
				"matched_rule_id":     decision.MatchedRuleID,
				"policy_version":      version,
				"trace":               json.RawMessage(traceJSON),
			},
		},
	}); err != nil {
		return SubmitResult{}, err
	}

	switch decision.Decision {
	case policy.Allow:
		authorized, err := o.Coordinator.Authorize(ctx, in.TenantID, actionID, in.StreamID)
		if err != nil {
			return SubmitResult{}, err
		}
		return SubmitResult{
			Kind: KindAuthorized, ActionID: actionID,
			State:         domain.StateExecutionAuthorized,
			GrantEnvelope: authorized.EnvelopeBytes,
		}, nil

	case policy.RequiresApproval:
		requested, err := o.Approvals.Request(ctx, approval.RequestInput{
			TenantID: in.TenantID, ActionID: actionID, StreamID: in.StreamID,
			RiskClassification: decision.RiskClassification,
			MatchedRuleID:      decision.MatchedRuleID,
			Title:              fmt.Sprintf("Approval needed: %s by %s", in.ToolName, in.AgentID),
			Body:               fmt.Sprintf("rule %s classified this %s action as %s", decision.MatchedRuleID, in.ToolName, decision.RiskClassification),
		})
		if err != nil {
			return SubmitResult{}, err
		}
		return SubmitResult{
			Kind: KindPending, ActionID: actionID,
			State: domain.StatePendingApproval, ExpiresAt: requested.ExpiresAt,
		}, nil

	default: // policy.Deny
		explanation := fmt.Sprintf("denied by rule %s", decision.MatchedRuleID)
		if err := transition.Apply(ctx, o.Pool, transition.Request{
			TenantID: in.TenantID, ActionID: actionID,
			From: domain.StateEvaluated, To: domain.StateDenied, ExpectedVersion: 1,
			Event: transition.Event{
				StreamID:   in.StreamID,
				Type:       domain.EventActionDenied,
				AttestedBy: domain.AttestedByControlPlane,
				Metadata: map[string]any{
					"matched_rule_id": decision.MatchedRuleID,
					"explanation":     explanation,
				},
			},
		}); err != nil {
			return SubmitResult{}, err
		}
		return SubmitResult{
			Kind: KindDenied, ActionID: actionID, State: domain.StateDenied,
			MatchedRuleID: decision.MatchedRuleID, Explanation: explanation,
		}, nil
	}
}

// Status is the poll/resume path (plan §9: the gateway polls, no held
// connections). When the action is authorized it carries the grant envelope.
func (o *Orchestrator) Status(ctx context.Context, tenantID, actionID uuid.UUID) (SubmitResult, error) {
	return o.resume(ctx, tenantID, actionID)
}

func (o *Orchestrator) resume(ctx context.Context, tenantID, actionID uuid.UUID) (SubmitResult, error) {
	state, _, err := transition.CurrentState(ctx, o.Pool, tenantID, actionID)
	if err != nil {
		return SubmitResult{}, err
	}
	res := SubmitResult{Kind: KindStatus, ActionID: actionID, State: state}
	if state == domain.StateExecutionAuthorized {
		envelope, err := o.Coordinator.LatestEnvelope(ctx, tenantID, actionID)
		if err != nil {
			return SubmitResult{}, err
		}
		res.GrantEnvelope = envelope
	}
	return res, nil
}

// activeSnapshot loads and compiles the tenant's newest ConfigurationSnapshot,
// caching by (tenant, version) — snapshots are immutable, so the cache can
// never serve stale content for a version.
func (o *Orchestrator) activeSnapshot(ctx context.Context, tenantID uuid.UUID) (*policy.CompiledSnapshot, int64, error) {
	var version int64
	var content []byte
	tx, err := o.Pool.Begin(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `select set_config('app.tenant_id', $1, true)`, tenantID.String()); err != nil {
		return nil, 0, fmt.Errorf("set tenant: %w", err)
	}
	err = tx.QueryRow(ctx,
		`select version, content from configuration_snapshots
		  where tenant_id = $1 order by version desc limit 1`,
		tenantID).Scan(&version, &content)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, 0, fmt.Errorf("tenant %s has no configuration snapshot (fail closed)", tenantID)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("load snapshot: %w", err)
	}

	key := snapshotKey{tenantID: tenantID, version: version}
	o.mu.Lock()
	cached, ok := o.compiled[key]
	o.mu.Unlock()
	if ok {
		return cached, version, nil
	}

	var cfg policy.SnapshotConfig
	if err := json.Unmarshal(content, &cfg); err != nil {
		return nil, 0, fmt.Errorf("snapshot %d content: %w", version, err)
	}
	compiled, err := o.Engine.Compile(cfg)
	if err != nil {
		return nil, 0, fmt.Errorf("snapshot %d rejected at load (fail closed): %w", version, err)
	}
	o.mu.Lock()
	if o.compiled == nil {
		o.compiled = make(map[snapshotKey]*policy.CompiledSnapshot)
	}
	o.compiled[key] = compiled
	o.mu.Unlock()
	return compiled, version, nil
}
