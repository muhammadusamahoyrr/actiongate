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
		".claude/*":                                      true, // glob can expand to the settings files
		"docs/gateway.json.md":                           false,
	} {
		if got := IsControlPath(p); got != want {
			t.Errorf("IsControlPath(%q) = %v, want %v", p, got, want)
		}
	}
}

// deepNest returns n levels of nested maps around a harmless string.
func deepNest(n int) any {
	var v any = "src/main.go"
	for range n {
		v = map[string]any{"x": v}
	}
	return v
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

		// Bypasses found in review of #9 — each one must stay caught.
		{"MultiEdit", map[string]any{"file_path": "/p/.claude/settings.local.json"}, true},
		{"Bash", map[string]any{"command": "sed -ni 's/x/y/' .claude/settings.local.json"}, true},
		{"Bash", map[string]any{"command": "sed -Ei 's/x/y/' .claude/settings.local.json"}, true},
		{"Bash", map[string]any{"command": "perl -pi.bak -e 's/x//' .claude/settings.json"}, true},
		{"Bash", map[string]any{"command": "cd .claude && echo {} > settings.local.json"}, true},
		{"Bash", map[string]any{"command": "cd /repo/.claude; rm settings.json"}, true},
		{"Bash", map[string]any{"command": `cd "$D" && echo {} > settings.local.json`}, true}, // unknown dir: control name counts
		{"Bash", map[string]any{"command": "mv .claude /tmp/old"}, true},
		{"Bash", map[string]any{"command": "rm -rf .claude"}, true},
		{"Bash", map[string]any{"command": "rm -rf ~/.config/actiongate"}, true},
		{"Bash", map[string]any{"command": "rm .claude/*"}, true},
		{"Bash", map[string]any{"command": "chmod 000 .claude"}, true},
		{"Bash", map[string]any{"command": "cp /tmp/settings.local.json .claude/"}, true},
		{"PowerShell", map[string]any{"command": `Set-Content -Path:.claude\settings.local.json -Value '{}'`}, true},
		{"PowerShell", map[string]any{"command": `[IO.File]::WriteAllText('.claude\settings.local.json','{}')`}, true},
		{"PowerShell", map[string]any{"command": `[System.IO.File]::Delete("C:\bin\ag-hook.exe")`}, true},
		{"PowerShell", map[string]any{"command": `Remove-Item -Recurse -Force .claude`}, true},
		{"PowerShell", map[string]any{"command": `Set-Location .claude; Set-Content settings.json '{}'`}, true},
		{"mcp__fs__write_file", map[string]any{"path": "/p/.claude/settings.json"}, true}, // unknown tool: assume writer

		// Second review round.
		{"mcp__fs__edit", map[string]any{"edits": []any{map[string]any{"file": ".claude/settings.json", "old": "a", "new": "b"}}}, true},
		{"PowerShell", map[string]any{"command": `Remove-Item -Recurse $env:APPDATA\actiongate`}, true},
		{"Bash", map[string]any{"command": "rm -rf .config/actiongate"}, true},
		{"Bash", map[string]any{"command": "rm -rf .cla*"}, true},
		{"Bash", map[string]any{"command": "echo {} > .clau?e/settings.*"}, true},
		{"Write", map[string]any{"file_path": `C:\p\.claude\settings.json.`}, true},
		{"Write", map[string]any{"file_path": `C:\p\.claude\settings.json::$DATA`}, true},
		{"Bash", map[string]any{"command": "cp -r /tmp/evil/. .claude/"}, true},
		{"Bash", map[string]any{"command": "cp -t .claude /tmp/settings.local.json"}, true},
		{"PowerShell", map[string]any{"command": `Get-Item .claude\settings.json | Remove-Item`}, true},
		{"PowerShell", map[string]any{"command": `Get-ChildItem .claude | Remove-Item -Recurse`}, true},

		// Third review round.
		{"Bash", map[string]any{"command": "rsync -t /tmp/settings.json .claude/settings.json"}, true}, // rsync -t = times, not target
		{"Bash", map[string]any{"command": "cp -rt .claude /tmp/evil"}, true},
		{"Bash", map[string]any{"command": "cp -t.claude /tmp/settings.json"}, true},
		{"Bash", map[string]any{"command": "cp --target .claude /tmp/settings.json"}, true},
		{"Bash", map[string]any{"command": "cp --target-dir=.claude /tmp/settings.json"}, true},
		{"Bash", map[string]any{"command": `echo {} > "$CONF/actiongate/dev.json"`}, true},
		{"Bash", map[string]any{"command": `rm -rf "$CONF/actiongate"`}, true},
		{"PowerShell", map[string]any{"command": `Get-Item .claude\settings.json | Set-Content -Value '{}'`}, true},
		{"PowerShell", map[string]any{"command": `Get-Item .claude\settings.json | Out-File -Encoding utf8`}, true},
		{"mcp__deep", map[string]any{"a": deepNest(12)}, true}, // too deep to inspect: fail closed

		// ...without flagging ordinary work.
		{"Bash", map[string]any{"command": "rm -rf ~/src/actiongate/build"}, false}, // a checkout named actiongate
		{"Bash", map[string]any{"command": "rsync -avt src/ /backup/src/"}, false},
		{"Bash", map[string]any{"command": "cp -t /tmp .claude/settings.json"}, false}, // copies the control file away: read only
		{"PowerShell", map[string]any{"command": `Get-Item .claude\settings.json | Set-Content -Path backup.json`}, false},
		{"mcp__shallow", map[string]any{"a": deepNest(3)}, false},
		{"Bash", map[string]any{"command": "cp notes.md .claude/commands/"}, false},
		{"PowerShell", map[string]any{"command": `Get-Content .claude\settings.json | Set-Content backup.json`}, false}, // reads the control file only
		{"PowerShell", map[string]any{"command": `Get-Item .claude | Move-Item -Destination C:\tmp\x`}, true},
		{"mcp__fs__list", map[string]any{"path": "src"}, false},
		{"Bash", map[string]any{"command": "sed -e 's/i/I/' .claude/settings.json"}, false}, // -e takes the script; no -i
		{"Bash", map[string]any{"command": "sed -n '/hooks/p' .claude/settings.json"}, false},
		{"Bash", map[string]any{"command": "cd src && echo x > settings.json"}, false},
		{"Bash", map[string]any{"command": "ls .claude && cat .claude/settings.json"}, false},
		{"Bash", map[string]any{"command": "cp .claude/settings.json /tmp/"}, false},
		{"Bash", map[string]any{"command": "rm -rf node_modules/.cache"}, false},
		{"PowerShell", map[string]any{"command": `Set-Location src; Set-Content settings.json '{}'`}, false},
		{"PowerShell", map[string]any{"command": `[IO.File]::ReadAllText('.claude\settings.json')`}, false},
		{"Glob", map[string]any{"path": ".claude", "pattern": "*.json"}, false},
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
