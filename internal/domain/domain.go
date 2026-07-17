// Package domain holds the state machine (plan §7) and the audit event
// vocabulary (plan §5). These are the authoritative definitions; the proto
// enums mirror them for the wire.
package domain

type State string

const (
	StateCreated             State = "Created"
	StateEvaluated           State = "Evaluated"
	StatePendingApproval     State = "PendingApproval"
	StateApproved            State = "Approved"
	StateExecutionAuthorized State = "ExecutionAuthorized"
	StateExecuting           State = "Executing"
	StateSucceeded           State = "Succeeded"
	StateFailed              State = "Failed"
	StatePartiallySucceeded  State = "PartiallySucceeded"
	StateOutcomeUnknown      State = "OutcomeUnknown"
	StateReconciled          State = "Reconciled"
	StateDenied              State = "Denied"
	StateExpired             State = "Expired"
	StateCancelled           State = "Cancelled"
	StateSupersededByPolicy  State = "SupersededByPolicy"
)

var allowedTransitions = map[State][]State{
	StateCreated:   {StateEvaluated},
	StateEvaluated: {StatePendingApproval, StateExecutionAuthorized, StateDenied},
	StatePendingApproval: {
		StateApproved, StateDenied, StateExpired, StateCancelled, StateSupersededByPolicy,
	},
	StateApproved:            {StateExecutionAuthorized, StateSupersededByPolicy},
	StateExecutionAuthorized: {StateExecuting, StateOutcomeUnknown},
	StateExecuting: {
		StateSucceeded, StateFailed, StatePartiallySucceeded, StateOutcomeUnknown,
	},
	StateOutcomeUnknown: {StateReconciled},
}

func CanTransition(from, to State) bool {
	for _, s := range allowedTransitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

func IsTerminal(s State) bool {
	return len(allowedTransitions[s]) == 0
}

type EventType string

const (
	EventActionCreated     EventType = "ActionCreated"
	EventPolicyEvaluated   EventType = "PolicyEvaluated"
	EventPolicyRevalidated EventType = "PolicyRevalidated"
	EventApprovalRequested EventType = "ApprovalRequested"
	EventApprovalGranted   EventType = "ApprovalGranted"
	EventApprovalDenied    EventType = "ApprovalDenied"
	EventApprovalExpired   EventType = "ApprovalExpired"
	// ActionDenied records the Evaluated→Denied auto-deny transition.
	// Added during implementation: the transition primitive writes exactly
	// one event per transition, and PolicyEvaluated already belongs to
	// Created→Evaluated — reusing it would duplicate the type in one action.
	EventActionDenied                EventType = "ActionDenied"
	EventActionCancelled             EventType = "ActionCancelled"
	EventActionSupersededByPolicy    EventType = "ActionSupersededByPolicy"
	EventExecutionAuthorized         EventType = "ExecutionAuthorized"
	EventExecutionStarted            EventType = "ExecutionStarted"
	EventExecutionSucceeded          EventType = "ExecutionSucceeded"
	EventExecutionFailed             EventType = "ExecutionFailed"
	EventExecutionPartiallySucceeded EventType = "ExecutionPartiallySucceeded"
	EventOutcomeUnknown              EventType = "OutcomeUnknown"
	EventOutcomeReconciled           EventType = "OutcomeReconciled"
	EventIdempotencyConflict         EventType = "IdempotencyConflict"
	EventInvalidTransitionAttempted  EventType = "InvalidTransitionAttempted"
)

const (
	AttestedByControlPlane = "control_plane"
	AttestedByOperator     = "operator" // suffix with :<operator_id>
	AttestedByGateway      = "gateway"  // suffix with :<gateway_id>
)
