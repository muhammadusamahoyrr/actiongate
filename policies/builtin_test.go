package policies

import (
	"encoding/json"
	"testing"

	"github.com/muhammadusamahoyrr/actiongate/internal/policy"
)

func compilePack(t *testing.T, name string) *policy.CompiledSnapshot {
	t.Helper()
	raw, ok := Pack(name)
	if !ok {
		t.Fatalf("no pack %q", name)
	}
	var cfg policy.SnapshotConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	s, err := engine.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Audit C1/C2: reading actiongate's own secrets is denied by the engine
// whatever pack is active — including relaxed and paranoid, whose own
// secret rules are substring matches that never knew about these files.
func TestBuiltinDeniesActiongateSecretsInEveryPack(t *testing.T) {
	reads := []policy.Input{
		{ToolName: "Read", Params: map[string]any{"file_path": `C:\Users\x\AppData\Roaming\actiongate\dev.json`}},
		{ToolName: "Read", Params: map[string]any{"file_path": "/home/x/.config/actiongate/gateway.json"}},
		{ToolName: "Grep", Params: map[string]any{"path": `C:\Users\x\AppData\Roaming\actiongate`, "pattern": "seed"}},
		{ToolName: "Bash", Params: map[string]any{"command": "cat ~/.config/actiongate/dev.json"}},
		{ToolName: "Bash", Params: map[string]any{"command": `cat "$APPDATA/actiongate/gateway.json"`}},
		{ToolName: "Bash", Params: map[string]any{"command": "cp ~/.config/actiongate/dev.json /tmp/x"}},
		{ToolName: "Bash", Params: map[string]any{"command": "tar czf /tmp/db.tgz ~/.config/actiongate/pgdata"}},
		{ToolName: "PowerShell", Params: map[string]any{"command": `Get-Content $env:APPDATA\actiongate\dev.json`}},
		{ToolName: "mcp__fs__read_text_file", Params: map[string]any{"path": "/home/x/.config/actiongate/dev.json"}},
	}
	for _, name := range Names() {
		pack := compilePack(t, name)
		for _, in := range reads {
			d, err := pack.Evaluate(in)
			if err != nil {
				t.Errorf("%s %s %v: %v", name, in.ToolName, in.Params, err)
				continue
			}
			if d.Decision != policy.Deny || d.MatchedRuleID != policy.BuiltinSecretsRuleID {
				t.Errorf("pack %s: %s %v = %s by %s, want deny by the built-in", name, in.ToolName, in.Params, d.Decision, d.MatchedRuleID)
			}
		}
	}
}

// Look-alikes stay out of the built-in: listing the directory, the repo
// checkout that happens to be named actiongate, a project's own dev.json.
func TestBuiltinSecretsLeaveOrdinaryWorkAlone(t *testing.T) {
	pack := compilePack(t, "claude-code")
	for _, in := range []policy.Input{
		{ToolName: "Bash", Params: map[string]any{"command": "ls ~/.config/actiongate"}},
		{ToolName: "Read", Params: map[string]any{"file_path": "/home/x/src/actiongate/README.md"}},
		{ToolName: "Read", Params: map[string]any{"file_path": "/home/x/app/config/dev.json"}},
		{ToolName: "Bash", Params: map[string]any{"command": "cat ~/src/actiongate/go.mod"}},
	} {
		d, err := pack.Evaluate(in)
		if err != nil {
			t.Fatal(err)
		}
		if d.MatchedRuleID == policy.BuiltinSecretsRuleID {
			t.Errorf("%s %v hit the built-in secrets rule", in.ToolName, in.Params)
		}
	}
}

// Audit C3: a pack without a self_tamper rule still cannot allow it; a pack
// may be stricter (paranoid denies) but never looser.
func TestBuiltinSelfTamperFloor(t *testing.T) {
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	allowAll, err := engine.Compile(policy.SnapshotConfig{DefaultDecision: policy.Allow})
	if err != nil {
		t.Fatal(err)
	}
	edit := policy.Input{ToolName: "Edit", Params: map[string]any{"file_path": "/repo/.claude/settings.local.json"}}
	d, err := allowAll.Evaluate(edit)
	if err != nil {
		t.Fatal(err)
	}
	if d.Decision != policy.RequiresApproval || d.MatchedRuleID != policy.BuiltinTamperRuleID {
		t.Errorf("allow-all pack: self-tamper = %s by %s, want requires_approval by the built-in floor", d.Decision, d.MatchedRuleID)
	}
	if d, _ := compilePack(t, "paranoid").Evaluate(edit); d.Decision != policy.Deny {
		t.Errorf("paranoid: self-tamper = %s, want its stricter deny kept", d.Decision)
	}
	plain := policy.Input{ToolName: "Edit", Params: map[string]any{"file_path": "/repo/main.go"}}
	if d, _ := allowAll.Evaluate(plain); d.Decision != policy.Allow {
		t.Errorf("allow-all pack: ordinary edit = %s, want allow", d.Decision)
	}
}

// Audit H10: the agent must not approve its own held action, through the
// local CLI or the callback endpoint, whatever pack is active.
func TestBuiltinDeniesSelfApprovalInEveryPack(t *testing.T) {
	attempts := []policy.Input{
		{ToolName: "Bash", Params: map[string]any{"command": "actiongate approvals approve 019f2c"}},
		{ToolName: "Bash", Params: map[string]any{"command": `"C:/bin/actiongate.exe" approvals deny 019f2c`}},
		{ToolName: "Bash", Params: map[string]any{"command": `curl -X POST http://127.0.0.1:8091/approval/callback -d '{"token":"x"}'`}},
		{ToolName: "PowerShell", Params: map[string]any{"command": `Invoke-RestMethod -Method Post http://localhost:8091/approval/callback -Body $b`}},
		{ToolName: "Bash", Params: map[string]any{"command": `python3 -c "import urllib.request as u; u.urlopen('http://localhost:8091/approval/callback')"`}},
		{ToolName: "mcp__http__fetch", Params: map[string]any{"url": "http://localhost:8091/approval/callback", "method": "POST"}},
	}
	for _, name := range Names() {
		pack := compilePack(t, name)
		for _, in := range attempts {
			d, err := pack.Evaluate(in)
			if err != nil {
				t.Fatal(err)
			}
			if d.Decision != policy.Deny || d.MatchedRuleID != policy.BuiltinApprovalRuleID {
				t.Errorf("pack %s: %s %v = %s by %s, want deny by the built-in", name, in.ToolName, in.Params, d.Decision, d.MatchedRuleID)
			}
		}
	}
	// Writing a document that mentions the endpoint is not approving.
	if d, _ := compilePack(t, "claude-code").Evaluate(policy.Input{ToolName: "Write",
		Params: map[string]any{"file_path": "/repo/docs/GUIDE.md", "content": "POST /approval/callback with the token"}}); d.MatchedRuleID == policy.BuiltinApprovalRuleID {
		t.Error("writing docs that mention /approval/callback hit the self-approval rule")
	}
	// Listing what is pending is fine.
	d, err := compilePack(t, "claude-code").Evaluate(policy.Input{ToolName: "Bash", Params: map[string]any{"command": "actiongate approvals list"}})
	if err != nil || d.MatchedRuleID == policy.BuiltinApprovalRuleID {
		t.Errorf("approvals list hit the self-approval rule: %v %s", err, d.MatchedRuleID)
	}
}

func TestBuiltinRuleIDsAreReserved(t *testing.T) {
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{policy.BuiltinSecretsRuleID, policy.BuiltinTamperRuleID, policy.BuiltinApprovalRuleID, policy.DefaultRuleID} {
		_, err := engine.Compile(policy.SnapshotConfig{Rules: []policy.Rule{{ID: id, Condition: "true", Decision: policy.Allow}}})
		if err == nil {
			t.Errorf("rule id %q should be reserved", id)
		}
	}
}
