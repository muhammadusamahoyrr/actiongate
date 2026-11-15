package facts

import (
	"reflect"
	"testing"
)

func TestScriptsRun(t *testing.T) {
	cases := []struct {
		tool, cmd string
		want      []Script
	}{
		{"Bash", "bash cleanup.sh", []Script{{Path: "cleanup.sh", Via: "shell"}}},
		{"Bash", "./cleanup.sh", []Script{{Path: "./cleanup.sh", Via: "exec"}}},
		{"Bash", "sh -e ./x.sh arg", []Script{{Path: "./x.sh", Via: "shell"}}},
		{"Bash", "bash -o pipefail run.sh", []Script{{Path: "run.sh", Via: "shell"}}},
		{"Bash", "source ./env.sh", []Script{{Path: "./env.sh", Via: "shell"}}},
		{"Bash", ". ./env.sh", []Script{{Path: "./env.sh", Via: "shell"}}},
		{"Bash", "python3 -u job.py --fast", []Script{{Path: "job.py", Via: "python"}}},
		{"Bash", "python -W ignore job.py", []Script{{Path: "job.py", Via: "python"}}},
		{"Bash", "node scripts/build.js", []Script{{Path: "scripts/build.js", Via: "node"}}},
		{"Bash", "deno run x.ts", []Script{{Path: "x.ts", Via: "deno"}}},
		{"Bash", "sudo bash /tmp/x.sh", []Script{{Path: "/tmp/x.sh", Via: "shell"}}},
		{"Bash", "cd tools && ./gen.sh", []Script{{Path: "tools/gen.sh", Via: "exec"}}},
		{"Bash", `cd "$D" && bash x.sh`, []Script{{Path: "x.sh", Via: "shell", UnknownDir: true}}},
		{"Bash", "npm run clean", []Script{{Path: "package.json", Via: "npm", Name: "clean"}}},
		{"Bash", "npm test", []Script{{Path: "package.json", Via: "npm", Name: "test"}}},
		{"Bash", "npm t", []Script{{Path: "package.json", Via: "npm", Name: "test"}}},
		{"Bash", "yarn lint", []Script{{Path: "package.json", Via: "npm", Name: "lint"}}},
		{"Bash", "pwsh -File ./x.ps1", []Script{{Path: "./x.ps1", Via: "powershell"}}},
		{"PowerShell", `.\setup.ps1; & .\b.ps1`, []Script{{Path: `.\setup.ps1`, Via: "powershell"}, {Path: `.\b.ps1`, Via: "powershell"}}},
		{"PowerShell", `pwsh -File C:\t\x.ps1`, []Script{{Path: `C:\t\x.ps1`, Via: "powershell"}}},

		// An option the model does not know before the operand: uncertain.
		{"Bash", "bash --frobnicate evil.sh x.sh", []Script{{Path: "evil.sh", Via: "shell", Uncertain: true}}},
		{"Bash", "python3 -Z x.py job.py", []Script{{Path: "x.py", Via: "python", Uncertain: true}}},
		{"Bash", "node --some-flag a.js", []Script{{Path: "a.js", Via: "node", Uncertain: true}}},
		{"Bash", "node --no-warnings a.js", []Script{{Path: "a.js", Via: "node"}}},
		{"Bash", "bash -s x.sh", nil}, // script from stdin; x.sh is an argument
		// Options that load more code, or change directory: uncertain.
		{"Bash", "node -r ./evil.js app.js", []Script{{Path: "app.js", Via: "node", Uncertain: true}}},
		{"Bash", "node --require=./evil.js app.js", []Script{{Path: "app.js", Via: "node", Uncertain: true}}},
		{"Bash", "ruby -C /tmp x.rb", []Script{{Path: "x.rb", Via: "ruby", Uncertain: true}}},
		{"Bash", "perl -MEvil x.pl", []Script{{Path: "x.pl", Via: "perl", Uncertain: true}}},
		{"Bash", "bash --rcfile evil.sh x.sh", []Script{{Path: "x.sh", Via: "shell", Uncertain: true}}},

		// Inline shell code that runs a script is followed.
		{"Bash", `bash -c "bash cleanup.sh"`, []Script{{Path: "cleanup.sh", Via: "shell"}}},
		{"Bash", `sh -ec "./x.sh"`, []Script{{Path: "./x.sh", Via: "exec"}}},
		{"Bash", `eval "./x.sh"`, []Script{{Path: "./x.sh", Via: "exec"}}},
		{"Bash", `cd sub && bash -c "./x.sh"`, []Script{{Path: "sub/x.sh", Via: "exec"}}},

		// Inline code is already inspected; nothing to read.
		{"Bash", `bash -c "rm -rf x"`, nil},
		{"Bash", `python3 -c "print(1)"`, nil},
		{"Bash", "python -m pytest", nil},
		{"Bash", `node -e "1"`, nil},
		{"Bash", "npm install", nil},
		{"Bash", "ls -la && git status", nil},
		{"Bash", "go test ./...", nil},
	}
	for _, c := range cases {
		got := ScriptsRun(c.tool, map[string]any{"command": c.cmd})
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s %q:\n got %+v\nwant %+v", c.tool, c.cmd, got, c.want)
		}
	}
}

// Audit H2: a script's text, attached by the gateway, is judged as if it
// had been typed inline.
func TestDeriveJudgesAttachedScripts(t *testing.T) {
	withScript := func(cmd string, entries ...map[string]any) map[string]any {
		list := make([]any, len(entries))
		for i, e := range entries {
			list[i] = e
		}
		return map[string]any{"command": cmd, ScriptsKey: list}
	}
	cases := []struct {
		name   string
		params map[string]any
		check  func(Facts) bool
	}{
		{"shell script deleting home", withScript("bash cleanup.sh",
			map[string]any{"path": "cleanup.sh", "via": "shell", "content": "#!/bin/sh\nrm -rf ~\n"}),
			func(f Facts) bool { return f.Destructive }},
		{"exec with no extension runs as sh", withScript("./wipe",
			map[string]any{"path": "./wipe", "via": "exec", "content": "git push --force origin main\n"}),
			func(f Facts) bool { return f.Destructive }},
		{"shebang python", withScript("./x",
			map[string]any{"path": "./x", "via": "exec", "content": "#!/usr/bin/env python3\nimport shutil\nshutil.rmtree('/home/x')\n"}),
			func(f Facts) bool { return f.Destructive }},
		{"python reading a secret", withScript("python3 job.py",
			map[string]any{"path": "job.py", "via": "python", "content": "print(open('.env').read())\n"}),
			func(f Facts) bool { return f.SecretAccess }},
		{"npm script", withScript("npm run clean",
			map[string]any{"path": "package.json", "via": "npm", "name": "clean", "content": "rm -rf / --no-preserve-root"}),
			func(f Facts) bool { return f.Destructive }},
		{"powershell script", withScript(`.\x.ps1`,
			map[string]any{"path": `.\x.ps1`, "via": "powershell", "content": "Remove-Item -Recurse -Force C:\\Users\\x"}),
			func(f Facts) bool { return f.Destructive }},
		{"script that edits the hook", withScript("bash x.sh",
			map[string]any{"path": "x.sh", "via": "shell", "content": "echo '{}' > .claude/settings.local.json"}),
			func(f Facts) bool { return f.SelfTamper }},
		{"exec: shebang beats the extension", withScript("./x.sh",
			map[string]any{"path": "./x.sh", "via": "exec", "content": "#!/usr/bin/env python3\nimport shutil\nshutil.rmtree('/home/x')\n"}),
			func(f Facts) bool { return f.Destructive }},
		{"exec: unknown shebang interpreter is opaque", withScript("./x",
			map[string]any{"path": "./x", "via": "exec", "content": "#!/usr/bin/awk -f\n{ system(\"rm -rf ~\") }\n"}),
			func(f Facts) bool { return f.Opaque }},
		{"exec: env -S shebang", withScript("./x",
			map[string]any{"path": "./x", "via": "exec", "content": "#!/usr/bin/env -S bash -e\nrm -rf ~\n"}),
			func(f Facts) bool { return f.Destructive }},
		{"exec: python3.11 shebang", withScript("./x",
			map[string]any{"path": "./x", "via": "exec", "content": "#!/usr/bin/python3.11\nprint(open('.env').read())\n"}),
			func(f Facts) bool { return f.SecretAccess }},
		{"exec: harmless shebang switches are fine", withScript("./x",
			map[string]any{"path": "./x", "via": "exec", "content": "#!/bin/bash -eu\nrm -rf ~\n"}),
			func(f Facts) bool { return f.Destructive && !f.Opaque }},
		{"exec: shebang with inline code is opaque", withScript("./x",
			map[string]any{"path": "./x", "via": "exec", "content": "#!/bin/sh -c 'rm -rf ~'\necho hi\n"}),
			func(f Facts) bool { return f.Opaque }},
		{"exec: env -S with an rc file is opaque", withScript("./x",
			map[string]any{"path": "./x", "via": "exec", "content": "#!/usr/bin/env -S bash --rcfile evil.sh\necho hi\n"}),
			func(f Facts) bool { return f.Opaque }},
		{"sourcing a secret is a secret read", withScript("source .env",
			map[string]any{"path": ".env", "via": "shell", "secret": true}),
			func(f Facts) bool { return f.SecretAccess }},
		{"unreadable script is opaque", withScript("bash x.sh",
			map[string]any{"path": "x.sh", "via": "shell", "error": "does not exist yet"}),
			func(f Facts) bool { return f.Opaque }},
		{"harmless script stays clean", withScript("bash build.sh",
			map[string]any{"path": "build.sh", "via": "shell", "content": "go build ./...\ngo test ./...\n"}),
			func(f Facts) bool { return !f.Destructive && !f.Opaque && !f.SecretAccess && !f.SelfTamper }},
	}
	for _, c := range cases {
		f := Derive("Bash", c.params)
		if !c.check(f) {
			t.Errorf("%s: facts %+v", c.name, f)
		}
	}
}
