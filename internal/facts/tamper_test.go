package facts

import "testing"

func TestIsControlPath(t *testing.T) {
	for p, want := range map[string]bool{
		".claude/settings.local.json":                    true,
		`C:\repo\.claude\settings.json`:                  true,
		"/c/Users/x/.claude/settings.json":               true,
		"bin/ag-hook.exe":                                true,
		"/home/x/.config/actiongate/gateway.json":        true,
		`C:\Users\x\AppData\Roaming\actiongate\dev.json`: true,
		"settings.json":                                  false, // not under .claude
		"web/.vscode/settings.json":                      false,
		"app/dev.json":                                   false,
		".claude/commands/review.md":                     false,
		"docs/gateway.json.md":                           false,
	} {
		if got := IsControlPath(p); got != want {
			t.Errorf("IsControlPath(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestSelfTamper(t *testing.T) {
	cases := []struct {
		tool   string
		params map[string]any
		want   bool
	}{
		// File tools: changing is tamper, reading is not.
		{"Edit", map[string]any{"file_path": ".claude/settings.local.json"}, true},
		{"Write", map[string]any{"file_path": `C:\p\.claude\settings.json`}, true},
		{"Write", map[string]any{"file_path": "bin/ag-hook.exe"}, true},
		{"Read", map[string]any{"file_path": ".claude/settings.local.json"}, false},
		{"Edit", map[string]any{"file_path": "src/settings.json"}, false},

		// Shell: writers, movers, deleters, redirects, in-place editors.
		{"Bash", map[string]any{"command": "rm .claude/settings.local.json"}, true},
		{"Bash", map[string]any{"command": `echo '{}' > .claude/settings.local.json`}, true},
		{"Bash", map[string]any{"command": "jq 'del(.hooks)' s.json >> ~/.claude/settings.json"}, true},
		{"Bash", map[string]any{"command": "sed -i 's/ag-hook//' .claude/settings.json"}, true},
		{"Bash", map[string]any{"command": "cp /tmp/noop bin/ag-hook.exe"}, true},
		{"Bash", map[string]any{"command": "mv bin/ag-hook.exe bin/off"}, true},
		{"Bash", map[string]any{"command": "echo x | tee gateway.json"}, true},
		{"Bash", map[string]any{"command": `bash -c "rm -f .claude/settings.local.json"`}, true},
		{"Bash", map[string]any{"command": `python -c "open('.claude/settings.json','w').write('{}')"`}, true},
		{"Bash", map[string]any{"command": "cat .claude/settings.local.json"}, false},
		{"Bash", map[string]any{"command": "cp .claude/settings.local.json /tmp/backup.json"}, false},
		{"Bash", map[string]any{"command": "grep ag-hook .claude/settings.json"}, false},
		{"Bash", map[string]any{"command": "sed -n 1p .claude/settings.json"}, false},

		// PowerShell.
		{"PowerShell", map[string]any{"command": `Set-Content .claude\settings.local.json '{}'`}, true},
		{"PowerShell", map[string]any{"command": `Remove-Item C:\bin\ag-hook.exe`}, true},
		{"PowerShell", map[string]any{"command": `'{}' > .claude\settings.json`}, true},
		{"PowerShell", map[string]any{"command": `Get-Content .claude\settings.json`}, false},
		{"PowerShell", map[string]any{"command": `Copy-Item .claude\settings.json backup.json`}, true}, // conservative: PS copy operands not split
	}
	for _, c := range cases {
		f := Derive(c.tool, c.params)
		if f.SelfTamper != c.want {
			t.Errorf("%s %v: self_tamper = %v, want %v (reasons %v)", c.tool, c.params, f.SelfTamper, c.want, f.Reasons)
		}
		if f.Map()["self_tamper"] != f.SelfTamper {
			t.Errorf("%s %v: Map() disagrees with SelfTamper", c.tool, c.params)
		}
	}
}
