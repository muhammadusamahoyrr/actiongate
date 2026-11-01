package policies

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/muhammadusamahoyrr/actiongate/internal/policy"
)

// The default pack must decide every action in the development benchmark
// exactly as labelled. bench/heldout.jsonl is deliberately NOT tested here:
// it measures generalisation and must never become a tuning target.
func TestClaudeCodePackOnBenchmark(t *testing.T) {
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	var cfg policy.SnapshotConfig
	if err := json.Unmarshal(ClaudeCode, &cfg); err != nil {
		t.Fatal(err)
	}
	pack, err := engine.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open("../bench/actions.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		var a struct {
			ID     string         `json:"id"`
			Tool   string         `json:"tool"`
			Params map[string]any `json:"params"`
			Expect string         `json:"expect"`
		}
		if err := json.Unmarshal(sc.Bytes(), &a); err != nil {
			t.Fatal(err)
		}
		n++
		d, err := pack.Evaluate(policy.Input{AgentID: "test", ToolName: a.Tool, Params: a.Params})
		if err != nil {
			t.Errorf("%s: %v", a.ID, err)
			continue
		}
		if string(d.Decision) != a.Expect {
			t.Errorf("%s (%s %v): got %s by %s, want %s", a.ID, a.Tool, a.Params, d.Decision, d.MatchedRuleID, a.Expect)
		}
	}
	if n < 200 {
		t.Fatalf("benchmark has %d actions, expected at least 200", n)
	}
}

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

// BenchmarkPackOnHeldOutB times one evaluation of each held-out B action
// (parsing included), per pack: ns/op is the mean over all 150 actions.
//
//	go test ./policies -run '^$' -bench PackOnHeldOutB -benchtime 20000x
func BenchmarkPackOnHeldOutB(b *testing.B) {
	type act struct {
		Tool   string         `json:"tool"`
		Params map[string]any `json:"params"`
	}
	raw, err := os.ReadFile("../bench/heldout-b.jsonl")
	if err != nil {
		b.Fatal(err)
	}
	var acts []act
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var a act
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			b.Fatal(err)
		}
		acts = append(acts, a)
	}
	engine, err := policy.NewEngine()
	if err != nil {
		b.Fatal(err)
	}
	for _, p := range []struct{ name, path string }{
		{"v1", "../bench/baseline/claude-code-v1.json"},
		{"regex", "../bench/baseline/regex-strong.json"},
		{"vocab", "../bench/baseline/regex-matched.json"},
		{"facts", "claude-code.json"},
	} {
		raw, err := os.ReadFile(p.path)
		if err != nil {
			b.Fatal(err)
		}
		var cfg policy.SnapshotConfig
		if err := json.Unmarshal(raw, &cfg); err != nil {
			b.Fatal(err)
		}
		snap, err := engine.Compile(cfg)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(p.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				a := acts[i%len(acts)]
				_, _ = snap.Evaluate(policy.Input{ToolName: a.Tool, Params: a.Params})
			}
		})
	}
}
