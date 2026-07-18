package policies

import (
	"encoding/json"
	"testing"

	"github.com/muhammadusamahoyrr/actiongate/internal/policy"
)

// Every shipped pack must compile — a starter pack that fails at
// provisioning would be worse than no pack at all.
func TestAllPacksCompile(t *testing.T) {
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range Names() {
		raw, ok := Pack(name)
		if !ok {
			t.Fatalf("Pack(%q) not found despite being in Names()", name)
		}
		var cfg policy.SnapshotConfig
		if err := json.Unmarshal(raw, &cfg); err != nil {
			t.Errorf("pack %q: invalid JSON: %v", name, err)
			continue
		}
		if _, err := engine.Compile(cfg); err != nil {
			t.Errorf("pack %q rejected by the compiler: %v", name, err)
		}
	}
	if _, ok := Pack("no-such-pack"); ok {
		t.Error("unknown pack name unexpectedly resolved")
	}
}

// The packs must guard every params access with has() — an unguarded
// access errors the evaluation and fails ALL tools closed (the v1-policy
// lesson: it broke unrelated tools like Glob).
func TestPacksGuardParamsAccess(t *testing.T) {
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range Names() {
		raw, _ := Pack(name)
		var cfg policy.SnapshotConfig
		if err := json.Unmarshal(raw, &cfg); err != nil {
			t.Fatal(err)
		}
		compiled, err := engine.Compile(cfg)
		if err != nil {
			t.Fatal(err)
		}
		// A tool the pack never mentions must evaluate cleanly.
		decision, err := compiled.Evaluate(policy.Input{
			ToolName: "Glob",
			AgentID:  "test",
			Params:   map[string]any{"pattern": "*.go"},
		})
		if err != nil {
			t.Errorf("pack %q: evaluation errored on an unrelated tool: %v", name, err)
			continue
		}
		if decision.Decision != policy.Allow {
			t.Errorf("pack %q: unrelated tool Glob got %q, want allow", name, decision.Decision)
		}
	}
}
