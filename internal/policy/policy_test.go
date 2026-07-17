package policy

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"actiongate/internal/domain"
)

func engine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func compile(t *testing.T, cfg SnapshotConfig) *CompiledSnapshot {
	t.Helper()
	cs, err := engine(t).Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return cs
}

func codingAgentRules() SnapshotConfig {
	return SnapshotConfig{
		DefaultDecision: Allow,
		Rules: []Rule{
			{
				ID:                 "deny-prod-secrets",
				Condition:          `tool_name == "read_file" && params.path.contains(".env")`,
				Decision:           Deny,
				RiskClassification: "secrets",
			},
			{
				ID:                 "approve-destructive-shell",
				Condition:          `tool_name == "bash" && params.command.contains("rm -rf")`,
				Decision:           RequiresApproval,
				RiskClassification: "destructive",
			},
			{
				ID:        "approve-prod-deploys",
				Condition: `environment == "production" && tool_name == "deploy"`,
				Decision:  RequiresApproval,
			},
		},
	}
}

func TestFirstMatchWins(t *testing.T) {
	cs := compile(t, SnapshotConfig{
		Rules: []Rule{
			{ID: "first", Condition: `tool_name == "bash"`, Decision: Deny},
			{ID: "second", Condition: `tool_name == "bash"`, Decision: Allow},
		},
	})
	d, err := cs.Evaluate(Input{ToolName: "bash"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.MatchedRuleID != "first" || d.Decision != Deny {
		t.Fatalf("first-match violated: %+v", d)
	}
	if len(d.Trace) != 1 {
		t.Fatalf("trace should stop at the match, got %d entries", len(d.Trace))
	}
}

func TestDecisionsAndParams(t *testing.T) {
	cs := compile(t, codingAgentRules())

	cases := []struct {
		name     string
		in       Input
		decision DecisionKind
		rule     string
		risk     string
	}{
		{
			name:     "secrets read denied",
			in:       Input{ToolName: "read_file", Params: map[string]any{"path": "/app/.env"}},
			decision: Deny, rule: "deny-prod-secrets", risk: "secrets",
		},
		{
			name:     "destructive shell needs approval",
			in:       Input{ToolName: "bash", Params: map[string]any{"command": "rm -rf /tmp/x"}},
			decision: RequiresApproval, rule: "approve-destructive-shell", risk: "destructive",
		},
		{
			name:     "prod deploy needs approval, default risk",
			in:       Input{ToolName: "deploy", Environment: "production", Params: map[string]any{}},
			decision: RequiresApproval, rule: "approve-prod-deploys", risk: DefaultRiskClassification,
		},
		{
			name:     "harmless call falls through to default allow",
			in:       Input{ToolName: "bash", Params: map[string]any{"command": "ls"}},
			decision: Allow, rule: DefaultRuleID, risk: DefaultRiskClassification,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := cs.Evaluate(tc.in)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if d.Decision != tc.decision || d.MatchedRuleID != tc.rule || d.RiskClassification != tc.risk {
				t.Fatalf("got %+v, want (%s, %s, %s)", d, tc.decision, tc.rule, tc.risk)
			}
		})
	}
}

func TestDefaultDefaultIsDeny(t *testing.T) {
	cs := compile(t, SnapshotConfig{Rules: nil})
	d, err := cs.Evaluate(Input{ToolName: "anything"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Decision != Deny || d.MatchedRuleID != DefaultRuleID {
		t.Fatalf("empty snapshot must fail closed, got %+v", d)
	}
}

func TestRuntimeErrorFailsClosed(t *testing.T) {
	cs := compile(t, SnapshotConfig{
		Rules: []Rule{
			// Errors at runtime when the key is absent — must fail the
			// evaluation, never be skipped as "no match".
			{ID: "touchy", Condition: `params.command.contains("x")`, Decision: Allow},
			{ID: "catch-all", Condition: `true`, Decision: Allow},
		},
	})
	_, err := cs.Evaluate(Input{ToolName: "bash", Params: map[string]any{"other": 1}})
	if err == nil {
		t.Fatal("erroring rule was silently skipped — fail-closed violated")
	}
	if !strings.Contains(err.Error(), "touchy") {
		t.Fatalf("error does not name the failing rule: %v", err)
	}
}

func TestCompileRejections(t *testing.T) {
	e := engine(t)
	cases := []struct {
		name string
		cfg  SnapshotConfig
	}{
		{"syntax error", SnapshotConfig{Rules: []Rule{{ID: "r", Condition: `tool_name ==`, Decision: Deny}}}},
		{"non-boolean", SnapshotConfig{Rules: []Rule{{ID: "r", Condition: `tool_name`, Decision: Deny}}}},
		{"unknown variable", SnapshotConfig{Rules: []Rule{{ID: "r", Condition: `nonexistent == "x"`, Decision: Deny}}}},
		{"missing id", SnapshotConfig{Rules: []Rule{{Condition: `true`, Decision: Deny}}}},
		{"duplicate id", SnapshotConfig{Rules: []Rule{
			{ID: "r", Condition: `true`, Decision: Deny},
			{ID: "r", Condition: `false`, Decision: Deny},
		}}},
		{"reserved id", SnapshotConfig{Rules: []Rule{{ID: DefaultRuleID, Condition: `true`, Decision: Deny}}}},
		{"unknown decision", SnapshotConfig{Rules: []Rule{{ID: "r", Condition: `true`, Decision: "maybe"}}}},
		{"bad default", SnapshotConfig{DefaultDecision: "shrug"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := e.Compile(tc.cfg); err == nil {
				t.Fatal("invalid snapshot compiled — must be rejected at load time")
			}
		})
	}
}

func TestNonBooleanIsErrNotBoolean(t *testing.T) {
	_, err := engine(t).Compile(SnapshotConfig{
		Rules: []Rule{{ID: "r", Condition: `tool_name`, Decision: Deny}},
	})
	if !errors.Is(err, ErrNotBoolean) {
		t.Fatalf("want ErrNotBoolean, got %v", err)
	}
}

func TestTraceRecordsEvaluationPath(t *testing.T) {
	cs := compile(t, codingAgentRules())
	d, err := cs.Evaluate(Input{
		ToolName:    "deploy",
		Environment: "production",
		Params:      map[string]any{},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	var ids []string
	for _, tr := range d.Trace {
		ids = append(ids, tr.RuleID)
	}
	want := []string{"deny-prod-secrets", "approve-destructive-shell", "approve-prod-deploys"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("trace path = %v, want %v", ids, want)
	}
	if !d.Trace[2].Matched || d.Trace[0].Matched || d.Trace[1].Matched {
		t.Fatalf("trace matched flags wrong: %+v", d.Trace)
	}
}

func TestEvaluationIsDeterministic(t *testing.T) {
	cs := compile(t, codingAgentRules())
	in := Input{ToolName: "bash", Params: map[string]any{"command": "rm -rf /"}}
	first, err := cs.Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	for i := 0; i < 100; i++ {
		again, err := cs.Evaluate(in)
		if err != nil {
			t.Fatalf("Evaluate #%d: %v", i, err)
		}
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("evaluation diverged on run %d: %+v vs %+v", i, first, again)
		}
	}
}

func TestSnapshotConfigRoundTripsJSON(t *testing.T) {
	// The snapshot content is stored as jsonb in configuration_snapshots;
	// the JSON shape is part of the product contract.
	raw := []byte(`{
		"default_decision": "allow",
		"rules": [
			{"id": "r1", "condition": "tool_name == \"bash\"", "decision": "requires_approval", "risk_classification": "destructive"}
		]
	}`)
	var cfg SnapshotConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	cs := compile(t, cfg)
	d, err := cs.Evaluate(Input{ToolName: "bash"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Decision != RequiresApproval || d.MatchedRuleID != "r1" {
		t.Fatalf("round-tripped snapshot misbehaved: %+v", d)
	}
}

func TestToState(t *testing.T) {
	cases := map[DecisionKind]domain.State{
		Allow:            domain.StateExecutionAuthorized,
		RequiresApproval: domain.StatePendingApproval,
		Deny:             domain.StateDenied,
	}
	for kind, want := range cases {
		if got := (Decision{Decision: kind}).ToState(); got != want {
			t.Fatalf("ToState(%s) = %s, want %s", kind, got, want)
		}
	}
}
