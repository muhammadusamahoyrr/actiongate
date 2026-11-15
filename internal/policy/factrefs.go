package policy

import (
	"errors"
	"fmt"
	"sort"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"

	"github.com/muhammadusamahoyrr/actiongate/internal/facts"
)

// ErrUnknownFact: a rule reads a fact this build does not derive. facts is
// a map in CEL, so without this check a typo (facts.destrutive) or a fact
// from a newer build compiles fine and then fails EVERY evaluation with
// "no such key" — every governed action blocked (audit M10).
var ErrUnknownFact = errors.New("unknown fact")

// factRefs returns the fact names a checked condition reads with
// facts.<name> or facts["<name>"]. Reads that cannot fail at run time —
// has(facts.x) and the optional facts[?"x"] — are not counted. A
// non-literal index (facts[some_var]) cannot be checked, so it is an error.
func factRefs(a *cel.Ast) ([]string, error) {
	seen := map[string]bool{}
	var err error
	celast.PreOrderVisit(celast.NavigateAST(a.NativeRep()), celast.NewExprVisitor(func(e celast.Expr) {
		if err != nil {
			return
		}
		switch e.Kind() {
		case celast.SelectKind:
			s := e.AsSelect()
			if isFactsIdent(s.Operand()) && !s.IsTestOnly() {
				seen[s.FieldName()] = true
			}
		case celast.CallKind:
			c := e.AsCall()
			args := c.Args()
			if c.FunctionName() != operators.Index || len(args) != 2 || !isFactsIdent(args[0]) {
				return
			}
			if args[1].Kind() == celast.LiteralKind {
				if name, ok := args[1].AsLiteral().Value().(string); ok {
					seen[name] = true
					return
				}
			}
			err = errors.New(`facts must be indexed with a literal name (facts["destructive"] or facts.destructive)`)
		}
	}))
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

func isFactsIdent(e celast.Expr) bool {
	return e.Kind() == celast.IdentKind && e.AsIdent() == "facts"
}

// checkFactRefs rejects a condition that reads a fact this build lacks.
func checkFactRefs(a *cel.Ast) error {
	refs, err := factRefs(a)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, k := range facts.Keys() {
		known[k] = true
	}
	for _, r := range refs {
		if !known[r] {
			return fmt.Errorf("%w facts.%s (this build knows: %v)", ErrUnknownFact, r, facts.Keys())
		}
	}
	return nil
}

// FactsUsed lists every fact name the snapshot's rules read. Tools that
// write a policy use it to check that the RUNNING control plane — possibly
// an older build — derives all of them before the policy goes live.
func (e *Engine) FactsUsed(cfg SnapshotConfig) ([]string, error) {
	seen := map[string]bool{}
	for _, r := range cfg.Rules {
		a, issues := e.env.Compile(r.Condition)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("rule %q: compile: %w", r.ID, issues.Err())
		}
		refs, err := factRefs(a)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.ID, err)
		}
		for _, n := range refs {
			seen[n] = true
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}
