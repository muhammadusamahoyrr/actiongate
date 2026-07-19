package upgrade

import (
	"errors"
	"reflect"
	"testing"
)

// TestUpgradeVerifyBeforeCommit: the phases run prepare→perform→verify→commit,
// and a failing verify aborts before commit (the cluster is never switched).
func TestUpgradeVerifyBeforeCommit(t *testing.T) {
	// Success path: strict order, commit reached.
	var order []string
	rec := func(name string) func() error {
		return func() error { order = append(order, name); return nil }
	}
	if err := run(steps{
		prepare: rec("prepare"),
		perform: rec("perform"),
		verify:  rec("verify"),
		commit:  rec("commit"),
	}); err != nil {
		t.Fatalf("run: %v", err)
	}
	want := []string{"prepare", "perform", "verify", "commit"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("order = %v, want %v", order, want)
	}

	// Failure path: verify fails → commit must NOT run.
	order = nil
	committed := false
	verifyErr := errors.New("checkpoint mismatch")
	err := run(steps{
		prepare: rec("prepare"),
		perform: rec("perform"),
		verify:  func() error { order = append(order, "verify"); return verifyErr },
		commit:  func() error { committed = true; return nil },
	})
	if !errors.Is(err, verifyErr) {
		t.Fatalf("expected verify error, got %v", err)
	}
	if committed {
		t.Fatal("commit ran despite a failed verify — must never switch on failure")
	}
	if got := []string{"prepare", "perform", "verify"}; !reflect.DeepEqual(order, got) {
		t.Fatalf("order = %v, want %v (no commit)", order, got)
	}
}

// TestRunRequiresAllPhases: Run rejects a nil phase rather than panicking.
func TestRunRequiresAllPhases(t *testing.T) {
	err := Run(Options{Prepare: func() error { return nil }})
	if err == nil {
		t.Fatal("expected an error when phases are missing")
	}
}
