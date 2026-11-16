package facts

import "testing"

// A recursive search rooted at actiongate's config directory or any
// ancestor of it reads dev.json: Grep on %APPDATA% used to be allowed with
// no fact at all.
func TestSearchOverConfigRootIsSelfSecret(t *testing.T) {
	for _, p := range []string{
		`C:\Users\x\AppData\Roaming`, `C:\Users\x\AppData`, `%APPDATA%`, `$env:APPDATA`,
		"~/.config", "/home/x/.config", "/home/x", `C:\Users\x`, "/Users/x/Library", "~", "$HOME", "/", `C:\`,
	} {
		if f := Derive("Grep", map[string]any{"pattern": "token_secret", "path": p, "output_mode": "content"}); !f.SelfSecret {
			t.Errorf("Grep path %q: self_secret not set (%v)", p, f.Reasons)
		}
	}
	for _, cmd := range []string{
		"grep -r token_secret ~/.config",
		"grep -R x /",
		"rg token_secret /c/Users/x/AppData/Roaming",
		"egrep --recursive secret /home/x",
	} {
		if f := Derive("Bash", map[string]any{"command": cmd}); !f.SelfSecret {
			t.Errorf("%q: self_secret not set (%v)", cmd, f.Reasons)
		}
	}
}

func TestOrdinarySearchesStayClean(t *testing.T) {
	for _, p := range []string{`C:\Users\x\src\proj`, "./internal", "", "/home/x/src/app", "docs"} {
		if f := Derive("Grep", map[string]any{"pattern": "TODO", "path": p}); f.SelfSecret || f.SecretAccess {
			t.Errorf("Grep path %q flagged: %v", p, f.Reasons)
		}
	}
	for _, cmd := range []string{
		"grep -r TODO ./internal",
		"rg TODO src",
		"grep -rn foo /home/x/src",
		"grep foo ~/notes.txt", // not recursive
	} {
		if f := Derive("Bash", map[string]any{"command": cmd}); f.SelfSecret {
			t.Errorf("%q flagged self_secret: %v", cmd, f.Reasons)
		}
	}
}

// A root named only by a variable may be home: not provably a secret read,
// but not clean either.
func TestSearchOverVariableRootIsOpaque(t *testing.T) {
	for _, cmd := range []string{`grep -rn token_secret "$HOME"`, "rg secret $DIR", `grep -r x "${XDG_CONFIG_HOME}/"`} {
		if f := Derive("Bash", map[string]any{"command": cmd}); !f.Opaque && !f.SelfSecret {
			t.Errorf("%q: neither opaque nor self_secret (%v)", cmd, f.Reasons)
		}
	}
}

// Quote splitting used to slip past the self-approval check: the shell
// joins the pieces back into the endpoint path.
func TestSelfApprovalSeesThroughQuoteSplitting(t *testing.T) {
	for _, cmd := range []string{
		`curl -X POST http://localhost:8091/approval/call""back -d @b.json`,
		`curl -X POST 'http://localhost:8091/approval/'"callback" -d @b.json`,
		`curl http://127.0.0.1:8091/slack/inter\action`,
		`curl http://127.0.0.1:8091/approval/call^back`,
	} {
		if f := Derive("Bash", map[string]any{"command": cmd}); !f.SelfApproval {
			t.Errorf("%q: self_approval not set (%v)", cmd, f.Reasons)
		}
	}
}

// go run x.go runs that file: it is attached and judged like the other
// interpreters' scripts. A package path is a directory and is not read.
func TestGoRunFileIsAScript(t *testing.T) {
	got := ScriptsRun("Bash", map[string]any{"command": "go run approver.go -v"})
	if len(got) != 1 || got[0].Path != "approver.go" || got[0].Via != "go" {
		t.Errorf("go run approver.go: scripts = %+v", got)
	}
	for _, cmd := range []string{"go run ./cmd/actiongate", "go run .", "go test ./...", "go build ./..."} {
		if got := ScriptsRun("Bash", map[string]any{"command": cmd}); len(got) != 0 {
			t.Errorf("%q: scripts = %+v, want none", cmd, got)
		}
	}
	src := "package main\n\nimport \"net/http\"\n\nfunc main() { http.Post(\"http://127.0.0.1:8091/approval/callback\", \"application/json\", nil) }\n"
	f := Derive("Bash", map[string]any{"command": "go run approver.go", ScriptsKey: []any{
		map[string]any{"path": "approver.go", "via": "go", "content": src},
	}})
	if !f.SelfApproval {
		t.Errorf("go run of a file posting to /approval/callback: self_approval not set (%v)", f.Reasons)
	}
}

// Follow-ups from the automated security review: other spellings of
// recursion, root's home, and roots that climb out of the project.
func TestSearchRecursionSpellingsAndClimbs(t *testing.T) {
	for _, cmd := range []string{
		"grep -d recurse token_secret ~/.config",
		"grep -drecurse token_secret ~/.config",
		"grep --directories=recurse token_secret ~/.config",
		"grep --dir=recurse token_secret ~/.config",
		"grep -r token_secret /root",
		"grep -r token_secret /var/root",
	} {
		if f := Derive("Bash", map[string]any{"command": cmd}); !f.SelfSecret {
			t.Errorf("%q: self_secret not set (%v)", cmd, f.Reasons)
		}
	}
	for _, cmd := range []string{"grep -r token_secret ../..", "rg token_secret .."} {
		if f := Derive("Bash", map[string]any{"command": cmd}); !f.Opaque && !f.SelfSecret {
			t.Errorf("%q: neither opaque nor self_secret (%v)", cmd, f.Reasons)
		}
	}
	if f := Derive("Grep", map[string]any{"pattern": "x", "path": "../.."}); !f.Opaque {
		t.Errorf("Grep path ../..: not opaque (%v)", f.Reasons)
	}
	for _, cmd := range []string{"grep -r TODO .", "grep -r TODO ../sibling/src", "grep -d skip x *"} {
		if f := Derive("Bash", map[string]any{"command": cmd}); f.Opaque || f.SelfSecret {
			t.Errorf("%q flagged: %v", cmd, f.Reasons)
		}
	}
}

// Second round of spellings from the automated review.
func TestSearchSpellingsRoundTwo(t *testing.T) {
	for _, cmd := range []string{
		"grep --directories recurse token_secret ~/.config",
		"grep -nd recurse token_secret ~/.config",
		"grep -ndrecurse token_secret ~/.config",
		"grep -r token_secret ~bob",
		"grep -r token_secret ~root/",
		"grep -r token_secret /private/var/root",
	} {
		if f := Derive("Bash", map[string]any{"command": cmd}); !f.SelfSecret {
			t.Errorf("%q: self_secret not set (%v)", cmd, f.Reasons)
		}
	}
	for _, cmd := range []string{"grep -r token_secret ../.", "grep -r token_secret ./..", "rg token_secret ../../."} {
		if f := Derive("Bash", map[string]any{"command": cmd}); !f.Opaque && !f.SelfSecret {
			t.Errorf("%q: neither opaque nor self_secret (%v)", cmd, f.Reasons)
		}
	}
	// -ed is -e with pattern "d": not a directories option.
	if f := Derive("Bash", map[string]any{"command": "grep -ed recurse ~/.config"}); f.SelfSecret {
		t.Errorf("grep -ed (pattern d) treated as recursive: %v", f.Reasons)
	}
}

// Third round: grep's abbreviated option values, unreadable values, and an
// option hidden behind a "--" that is really a pattern.
func TestSearchSpellingsRoundThree(t *testing.T) {
	for _, cmd := range []string{
		"grep -d rec token_secret ~/.config",
		"grep --dir=recu token_secret ~/.config",
		"grep -d $MODE token_secret ~/.config",
		"grep -e -- -r ~/.config",
		"grep -nr token_secret ~/.config",
	} {
		if f := Derive("Bash", map[string]any{"command": cmd}); !f.SelfSecret {
			t.Errorf("%q: self_secret not set (%v)", cmd, f.Reasons)
		}
	}
	for _, cmd := range []string{
		"grep -d read token_secret ~/.config/app.conf", // not recursive
		"grep -d skip x ~/.config",
		"grep -erx ~/notes", // -e takes "rx" as the pattern
	} {
		if f := Derive("Bash", map[string]any{"command": cmd}); f.SelfSecret {
			t.Errorf("%q flagged self_secret: %v", cmd, f.Reasons)
		}
	}
}

// Fourth round: unknown -d values and option words from variables fail
// closed; read and skip stay clean.
func TestSearchSpellingsRoundFour(t *testing.T) {
	for _, cmd := range []string{
		"grep -d RECURSE token_secret ~/.config",
		"grep $FLAGS token_secret ~/.config",
		"grep -n$X token_secret ~/.config",
	} {
		if f := Derive("Bash", map[string]any{"command": cmd}); !f.SelfSecret {
			t.Errorf("%q: self_secret not set (%v)", cmd, f.Reasons)
		}
	}
	for _, cmd := range []string{"grep -d sk x ~/.config", "grep --directories=rea x ~/.config", "grep -n token ~/notes.txt"} {
		if f := Derive("Bash", map[string]any{"command": cmd}); f.SelfSecret {
			t.Errorf("%q flagged self_secret: %v", cmd, f.Reasons)
		}
	}
}
