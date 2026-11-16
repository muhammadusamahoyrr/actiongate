package policies

import (
	"testing"

	"github.com/muhammadusamahoyrr/actiongate/internal/policy"
)

// Audit H4: every pack must block secrets and gate destructive actions
// however they are spelled — relaxed and paranoid used substring rules
// (relaxed never looked at Bash, so `cat .env` passed; paranoid did not
// gate PowerShell, MultiEdit or other tools).
func TestEveryPackBlocksSecretsAnySpelling(t *testing.T) {
	secrets := []policy.Input{
		{ToolName: "Read", Params: map[string]any{"file_path": "/repo/.env"}},
		{ToolName: "Bash", Params: map[string]any{"command": "cat .env"}},
		{ToolName: "Bash", Params: map[string]any{"command": "cat .e*"}},
		{ToolName: "Bash", Params: map[string]any{"command": "cp -t /tmp/out .env"}},
		{ToolName: "Bash", Params: map[string]any{"command": "cat ~/.kube/config"}},
		{ToolName: "PowerShell", Params: map[string]any{"command": "Get-Content .env"}},
		{ToolName: "Grep", Params: map[string]any{"path": "/repo/.env", "pattern": "KEY"}},
	}
	for _, name := range Names() {
		pack := compilePack(t, name)
		for _, in := range secrets {
			d, err := pack.Evaluate(in)
			if err != nil {
				t.Fatal(err)
			}
			if d.Decision != policy.Deny {
				t.Errorf("pack %s: %s %v = %s (rule %s), want deny", name, in.ToolName, in.Params, d.Decision, d.MatchedRuleID)
			}
		}
	}
}

func TestEveryPackGatesDestructiveActions(t *testing.T) {
	destructive := []policy.Input{
		{ToolName: "Bash", Params: map[string]any{"command": "rm --rec -f ~"}},
		{ToolName: "Bash", Params: map[string]any{"command": "git push --forc origin main"}},
		{ToolName: "Bash", Params: map[string]any{"command": `psql -c "UPDATE users SET pw=null"`}},
		{ToolName: "Bash", Params: map[string]any{"command": "docker compose down -v"}},
		{ToolName: "PowerShell", Params: map[string]any{"command": "Remove-Item -Recurse -Force C:\\data"}},
	}
	for _, name := range Names() {
		pack := compilePack(t, name)
		for _, in := range destructive {
			d, err := pack.Evaluate(in)
			if err != nil {
				t.Fatal(err)
			}
			if d.Decision == policy.Allow {
				t.Errorf("pack %s: %s %v allowed, want gated", name, in.ToolName, in.Params)
			}
		}
	}
}

// What each pack is FOR: relaxed lets ordinary and uninspectable work run;
// paranoid lets only reads run and holds everything else, including
// PowerShell, MultiEdit and tools it has never heard of.
func TestPackCharacter(t *testing.T) {
	relaxed, paranoid := compilePack(t, "relaxed"), compilePack(t, "paranoid")
	for _, in := range []policy.Input{
		{ToolName: "Bash", Params: map[string]any{"command": "go test ./..."}},
		{ToolName: "Bash", Params: map[string]any{"command": `python3 -c "exec(input())"`}}, // opaque: relaxed runs it
		{ToolName: "Edit", Params: map[string]any{"file_path": "/repo/main.go"}},
		{ToolName: "Read", Params: map[string]any{"file_path": "/repo/.env.example"}}, // template, not a secret
	} {
		if d, _ := relaxed.Evaluate(in); d.Decision != policy.Allow {
			t.Errorf("relaxed: %s %v = %s, want allow", in.ToolName, in.Params, d.Decision)
		}
	}
	for _, in := range []policy.Input{
		{ToolName: "Read", Params: map[string]any{"file_path": "/repo/main.go"}},
		{ToolName: "Grep", Params: map[string]any{"path": "/repo", "pattern": "TODO"}},
		{ToolName: "Read", Params: map[string]any{"file_path": "/repo/.env.example"}},
	} {
		if d, _ := paranoid.Evaluate(in); d.Decision != policy.Allow {
			t.Errorf("paranoid: read %v = %s, want allow", in.Params, d.Decision)
		}
	}
	for _, in := range []policy.Input{
		{ToolName: "Bash", Params: map[string]any{"command": "ls"}},
		{ToolName: "PowerShell", Params: map[string]any{"command": "Get-ChildItem"}},
		{ToolName: "MultiEdit", Params: map[string]any{"file_path": "/repo/main.go"}},
		{ToolName: "Write", Params: map[string]any{"file_path": "/repo/new.go"}},
		{ToolName: "mcp__github__create_issue", Params: map[string]any{"title": "x"}},
	} {
		if d, _ := paranoid.Evaluate(in); d.Decision != policy.RequiresApproval {
			t.Errorf("paranoid: %s %v = %s, want requires_approval", in.ToolName, in.Params, d.Decision)
		}
	}
}
