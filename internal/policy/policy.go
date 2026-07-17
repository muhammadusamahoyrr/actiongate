// Package policy is the PolicyEngine (plan §3): a pure evaluator of
// ActionRequest facts against a compiled ConfigurationSnapshot. Rules are an
// explicit ordered list — first match wins — with cel-go evaluating each
// rule's condition (plan §20.1). CEL is deterministic, guaranteed to
// terminate, and sandboxed; composition, precedence, and explanation live in
// this package, not in the expression language.
//
// Fail-closed rules:
//   - Snapshots that fail to compile are rejected at load time, never
//     half-loaded.
//   - A rule condition that errors at evaluation time fails the whole
//     evaluation; the orchestrator rejects the action (plan §16). Errors are
//     never treated as "no match".
//   - No rule matched → the snapshot's default decision, which itself
//     defaults to deny.
package policy

import (
	"errors"
	"fmt"

	"github.com/google/cel-go/cel"

	"github.com/muhammadusamahoyrr/actiongate/internal/domain"
)

type DecisionKind string

const (
	Allow            DecisionKind = "allow"
	Deny             DecisionKind = "deny"
	RequiresApproval DecisionKind = "requires_approval"
)

const (
	DefaultRiskClassification = "standard"
	// DefaultRuleID marks a decision produced by the snapshot default, not a
	// rule. It is reserved: snapshots may not define a rule with this id.
	DefaultRuleID = "__default__"
)

var ErrNotBoolean = errors.New("rule condition does not evaluate to a boolean")

// Rule is one entry of the ordered rule list in a ConfigurationSnapshot.
type Rule struct {
	ID                 string       `json:"id"`
	Description        string       `json:"description,omitempty"`
	Condition          string       `json:"condition"`
	Decision           DecisionKind `json:"decision"`
	RiskClassification string       `json:"risk_classification,omitempty"`
}

// SnapshotConfig is the policy portion of a ConfigurationSnapshot's content.
type SnapshotConfig struct {
	DefaultDecision DecisionKind `json:"default_decision,omitempty"` // empty → deny
	Rules           []Rule       `json:"rules"`
}

// Input is the fact set a condition may inspect. It mirrors the immutable
// ActionRequest; conditions can never see or reach anything else.
type Input struct {
	AgentID     string
	ToolName    string
	Environment string
	Params      map[string]any
}

// RuleTrace records one evaluated rule for the explainability requirement
// (plan §22): a blocked developer must see exactly which rule fired.
type RuleTrace struct {
	RuleID    string `json:"rule_id"`
	Condition string `json:"condition"`
	Matched   bool   `json:"matched"`
}

// Decision is the engine's verdict, carried into PolicyDecision rows.
type Decision struct {
	Decision           DecisionKind
	RiskClassification string
	MatchedRuleID      string
	// Trace lists the rules evaluated, in order, up to and including the
	// match — an honest record of first-match semantics.
	Trace []RuleTrace
}

type Engine struct {
	env *cel.Env
}

func NewEngine() (*Engine, error) {
	env, err := cel.NewEnv(
		cel.Variable("agent_id", cel.StringType),
		cel.Variable("tool_name", cel.StringType),
		cel.Variable("environment", cel.StringType),
		cel.Variable("params", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, fmt.Errorf("cel environment: %w", err)
	}
	return &Engine{env: env}, nil
}

type compiledRule struct {
	rule    Rule
	program cel.Program
}

// CompiledSnapshot is an immutable, validated snapshot ready to evaluate.
// Compile everything at config-load time so a broken rule can never be
// discovered mid-request.
type CompiledSnapshot struct {
	defaultDecision DecisionKind
	rules           []compiledRule
}

func (e *Engine) Compile(cfg SnapshotConfig) (*CompiledSnapshot, error) {
	defaultDecision := cfg.DefaultDecision
	if defaultDecision == "" {
		defaultDecision = Deny
	}
	if err := validDecision(defaultDecision); err != nil {
		return nil, fmt.Errorf("default_decision: %w", err)
	}

	seen := make(map[string]bool, len(cfg.Rules))
	compiled := make([]compiledRule, 0, len(cfg.Rules))
	for i, r := range cfg.Rules {
		if r.ID == "" {
			return nil, fmt.Errorf("rule %d: missing id", i)
		}
		if r.ID == DefaultRuleID {
			return nil, fmt.Errorf("rule %q: reserved id", r.ID)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("rule %q: duplicate id", r.ID)
		}
		seen[r.ID] = true
		if err := validDecision(r.Decision); err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.ID, err)
		}
		if r.RiskClassification == "" {
			r.RiskClassification = DefaultRiskClassification
		}

		ast, issues := e.env.Compile(r.Condition)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("rule %q: compile: %w", r.ID, issues.Err())
		}
		if !ast.OutputType().IsExactType(cel.BoolType) {
			return nil, fmt.Errorf("rule %q: %w (got %s)", r.ID, ErrNotBoolean, ast.OutputType())
		}
		program, err := e.env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("rule %q: program: %w", r.ID, err)
		}
		compiled = append(compiled, compiledRule{rule: r, program: program})
	}
	return &CompiledSnapshot{defaultDecision: defaultDecision, rules: compiled}, nil
}

// Evaluate applies the ordered rules to the input. It is pure: no I/O, no
// clock, no state. A condition that errors (e.g. touches a missing params
// key) fails the evaluation — the orchestrator must then reject the action.
func (s *CompiledSnapshot) Evaluate(in Input) (Decision, error) {
	activation := map[string]any{
		"agent_id":    in.AgentID,
		"tool_name":   in.ToolName,
		"environment": in.Environment,
		"params":      in.Params,
	}
	if in.Params == nil {
		activation["params"] = map[string]any{}
	}

	trace := make([]RuleTrace, 0, len(s.rules))
	for _, cr := range s.rules {
		out, _, err := cr.program.Eval(activation)
		if err != nil {
			return Decision{}, fmt.Errorf("rule %q: eval: %w", cr.rule.ID, err)
		}
		matched, ok := out.Value().(bool)
		if !ok {
			return Decision{}, fmt.Errorf("rule %q: %w at runtime", cr.rule.ID, ErrNotBoolean)
		}
		trace = append(trace, RuleTrace{
			RuleID:    cr.rule.ID,
			Condition: cr.rule.Condition,
			Matched:   matched,
		})
		if matched {
			return Decision{
				Decision:           cr.rule.Decision,
				RiskClassification: cr.rule.RiskClassification,
				MatchedRuleID:      cr.rule.ID,
				Trace:              trace,
			}, nil
		}
	}
	return Decision{
		Decision:           s.defaultDecision,
		RiskClassification: DefaultRiskClassification,
		MatchedRuleID:      DefaultRuleID,
		Trace:              trace,
	}, nil
}

// ToState maps a decision to the state-machine transition target the
// orchestrator must apply (plan §7: Evaluated → …).
func (d Decision) ToState() domain.State {
	switch d.Decision {
	case Allow:
		return domain.StateExecutionAuthorized
	case RequiresApproval:
		return domain.StatePendingApproval
	default:
		return domain.StateDenied
	}
}

func validDecision(d DecisionKind) error {
	switch d {
	case Allow, Deny, RequiresApproval:
		return nil
	default:
		return fmt.Errorf("unknown decision %q", d)
	}
}
