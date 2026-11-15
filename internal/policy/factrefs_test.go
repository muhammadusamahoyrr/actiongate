package policy

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// Audit M10: an unknown fact name must be rejected when the policy is
// compiled (SetPolicy compiles before saving), not discovered by every
// evaluation failing closed.
func TestCompileRejectsUnknownFacts(t *testing.T) {
	e, err := NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	for _, cond := range []string{
		"facts.destrutive",                     // typo
		`facts["destrutive"]`,                  // index spelling
		"tool_name == 'Bash' && facts.no_such", // inside a larger condition
		`facts.opaque || facts["self_tampr"]`,  // second reference
		`[1].exists(x, facts.not_a_fact)`,      // inside a comprehension
	} {
		_, err := e.Compile(SnapshotConfig{Rules: []Rule{{ID: "r", Condition: cond, Decision: Deny}}})
		if !errors.Is(err, ErrUnknownFact) {
			t.Errorf("%s: err = %v, want ErrUnknownFact", cond, err)
		}
	}
}

func TestCompileAcceptsKnownAndSafeFactReads(t *testing.T) {
	e, err := NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	for _, cond := range []string{
		"facts.destructive",
		`facts["secret_access"] && facts.self_tamper`,
		"has(facts.future_fact)", // cannot fail at run time
		"facts.self_secret",
	} {
		if _, err := e.Compile(SnapshotConfig{Rules: []Rule{{ID: "r", Condition: cond, Decision: Deny}}}); err != nil {
			t.Errorf("%s: %v", cond, err)
		}
	}
	_, err = e.Compile(SnapshotConfig{Rules: []Rule{{ID: "r", Condition: `facts[tool_name]`, Decision: Deny}}})
	if err == nil || !strings.Contains(err.Error(), "literal") {
		t.Errorf("dynamic facts index: err = %v, want a literal-name error", err)
	}
}

func TestFactsUsed(t *testing.T) {
	e, err := NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.FactsUsed(SnapshotConfig{Rules: []Rule{
		{ID: "a", Condition: "facts.secret_access", Decision: Deny},
		{ID: "b", Condition: `facts["self_tamper"] || facts.secret_access`, Decision: Deny},
		{ID: "c", Condition: "has(facts.opaque)", Decision: Deny},
		{ID: "d", Condition: "tool_name == 'Bash'", Decision: Deny},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"secret_access", "self_tamper"}; !reflect.DeepEqual(got, want) {
		t.Errorf("FactsUsed = %v, want %v", got, want)
	}
}
