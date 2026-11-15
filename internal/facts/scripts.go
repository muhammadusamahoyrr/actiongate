package facts

import (
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Write-then-run (audit H2): the agent writes cleanup.sh containing
// `rm -rf ~` and runs `bash cleanup.sh`. The command line alone shows
// nothing, so every fact the analyzer derives from a command would miss
// it. The fix needs the script's text, which only the local gateway can
// read (the control plane may not share the agent's filesystem):
//
//  1. ScriptsRun (pure) lists the local files a command would execute.
//  2. The gateway reads them, bounded, and attaches them to the params
//     under ScriptsKey, always overwriting whatever the caller sent.
//  3. Derive analyzes each attached script as if it had been typed inline
//     (deriveScripts). A script the gateway could not read in full is
//     opaque: fail closed.

// ScriptsKey is the reserved params key the gateway attaches script
// contents under. Its value is a list of {path, via, content, error}.
const ScriptsKey = "_actiongate_scripts"

// Script is one local file a command executes, and how.
type Script struct {
	// Path as written (relative to the hook's working directory unless
	// absolute), already joined with any cd inside the command. For an
	// npm-style run it is "package.json" and Name is the script name.
	Path string `json:"path"`
	// Via is how it runs: "shell", "powershell", an interpreter name
	// ("python3", "node", ...), "exec" (./x: shebang decides) or "npm".
	Via  string `json:"via"`
	Name string `json:"name,omitempty"`
	// UnknownDir: a cd inside the command went somewhere the analyzer
	// cannot resolve, so Path cannot be located. The gateway reports it
	// unreadable, which is opaque.
	UnknownDir bool `json:"unknown_dir,omitempty"`
}

// ScriptsRun lists the local scripts a Bash or PowerShell command would
// execute. It never reads files.
func ScriptsRun(tool string, params map[string]any) []Script {
	cmd, _ := params["command"].(string)
	if strings.TrimSpace(cmd) == "" {
		return nil
	}
	switch tool {
	case "Bash", "bash":
		return shellScripts(cmd)
	case "PowerShell":
		return psScripts(cmd)
	}
	return nil
}

func shellScripts(cmd string) []Script { return shellScriptsDepth(cmd, 0) }

func shellScriptsDepth(cmd string, depth int) (out []Script) {
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(cmd), "")
	if err != nil {
		return nil // unparseable: the analyzer already reports it opaque
	}
	a := &shellAnalyzer{depth: depth, stdin: map[*syntax.Stmt]stdinSource{}, vars: map[string]string{}, collect: true}
	syntax.Walk(file, a.visit)
	return a.scripts
}

// scriptValueFlags take a value as the next word (bash -o pipefail x.sh).
var scriptValueFlags = map[string]string{
	"shell":   "oO",
	"python":  "WXQ",
	"node":    "r",
	"perl":    "IM",
	"ruby":    "IrE",
	"php":     "dc",
	"default": "",
}

// collectScript records the script a command runs, if any. It mirrors how
// each runner picks its script operand: the first operand that is not an
// option (or an option's value), unless code is given inline (-c, -e),
// which the analyzer already inspects.
func (a *shellAnalyzer) collectScript(args []arg) {
	if len(args) == 0 || !args[0].lit {
		return
	}
	cmd0 := args[0].text
	name := cmdName(cmd0)
	rest := args[1:]
	add := func(p, via, scriptName string) {
		if p == "" {
			return
		}
		s := Script{Path: p, Via: via, Name: scriptName}
		if !isAbsPath(p) {
			switch a.cwd.dir {
			case "":
			case unknownDir:
				s.UnknownDir = true
			default:
				s.Path = path.Join(a.cwd.dir, slash(p))
			}
		}
		a.scripts = append(a.scripts, s)
	}

	// A command named by a path (./cleanup.sh, scripts/run, /tmp/x) runs
	// that file directly.
	if strings.ContainsAny(cmd0, `/\`) && !shells[name] && !interpreters[name] {
		add(cmd0, "exec", "")
		return
	}
	// Inline shell code can itself run a script: bash -c "bash x.sh",
	// eval "./x.sh". Follow it, bounded by the analyzer's depth limit.
	nested := func(code string) {
		if a.depth >= maxDepth {
			return
		}
		for _, s := range shellScriptsDepth(code, a.depth+1) {
			if !isAbsPath(s.Path) && s.Via != "npm" && a.cwd.dir != "" {
				if a.cwd.dir == unknownDir {
					s.UnknownDir = true
				} else {
					s.Path = path.Join(a.cwd.dir, slash(s.Path))
				}
			}
			a.scripts = append(a.scripts, s)
		}
	}
	switch {
	case name == "eval":
		if code, ok := joinLiteral(rest); ok {
			nested(code)
		}
	case shells[name]:
		for i, x := range rest {
			if (x.text == "-c" || isShortCluster(x.text) && strings.Contains(x.text, "c")) && i+1 < len(rest) {
				if rest[i+1].lit {
					nested(rest[i+1].text)
				}
				return
			}
		}
		if p, ok := scriptOperand(rest, scriptValueFlags["shell"], set("-c")); ok {
			add(p, "shell", "")
		}
	case name == "source" || name == ".":
		if len(rest) > 0 {
			add(rest[0].text, "shell", "")
		}
	case interpreters[name]:
		inline := set("-c", "-e", "-E", "-r", "--eval", "-p", "--print", "-m", "-")
		kind := name
		flags := scriptValueFlags["default"]
		switch {
		case strings.HasPrefix(name, "python"):
			flags, kind = scriptValueFlags["python"], "python"
			inline = set("-c", "-m", "-")
		case name == "node" || name == "nodejs":
			flags, kind = scriptValueFlags["node"], "node"
		case name == "perl" || name == "ruby" || name == "php":
			flags = scriptValueFlags[name]
		case name == "deno" || name == "bun":
			// deno run x.ts / bun run x.ts / bun x.ts
			if len(rest) > 0 && (rest[0].text == "run" || rest[0].text == "x") {
				rest = rest[1:]
			}
		}
		if p, ok := scriptOperand(rest, flags, inline); ok {
			add(p, kind, "")
		}
	case name == "npm" || name == "pnpm" || name == "yarn" || name == "bun":
		if s, ok := npmScriptName(name, rest); ok {
			add("package.json", "npm", s)
		}
	case name == "pwsh" || name == "powershell":
		for i, x := range rest {
			if strings.EqualFold(x.text, "-file") || strings.EqualFold(x.text, "-f") {
				if i+1 < len(rest) {
					add(rest[i+1].text, "powershell", "")
				}
				return
			}
		}
	}
}

// scriptOperand finds the script operand: the first word that is not an
// option, skipping the values of options in valueFlags. ok is false when
// inline code (an inline flag) comes first, or there is no operand.
func scriptOperand(rest []arg, valueFlags string, inline map[string]bool) (string, bool) {
	for i := 0; i < len(rest); i++ {
		t := rest[i].text
		if inline[t] {
			return "", false
		}
		if t == "--" {
			if i+1 < len(rest) {
				return rest[i+1].text, true
			}
			return "", false
		}
		if strings.HasPrefix(t, "-") && len(t) > 1 {
			// -o pipefail / -W ignore: the next word is the option's value.
			if len(t) == 2 && strings.ContainsRune(valueFlags, rune(t[1])) {
				i++
			}
			// Inline code in a cluster (bash -ec '...', python -Bc '...').
			if !strings.HasPrefix(t, "--") && strings.ContainsAny(t[1:], "ce") && inlineInCluster(t, inline) {
				return "", false
			}
			continue
		}
		return t, true
	}
	return "", false
}

func inlineInCluster(t string, inline map[string]bool) bool {
	for _, r := range t[1:] {
		if inline["-"+string(r)] {
			return true
		}
	}
	return false
}

// npmScriptName is the package.json script an npm/pnpm/yarn/bun command
// runs: `npm run x`, `npm test`/`start`/`stop`/`restart`, `yarn x`,
// `pnpm x`. Built-in commands (install, ci, ...) run no script by name
// (their lifecycle hooks are a known gap).
func npmScriptName(tool string, rest []arg) (string, bool) {
	var words []string
	for _, x := range rest {
		if !strings.HasPrefix(x.text, "-") {
			words = append(words, x.text)
		}
	}
	if len(words) == 0 {
		return "", false
	}
	switch words[0] {
	case "run", "run-script", "rum", "urn":
		if len(words) > 1 {
			return words[1], true
		}
		return "", false
	case "test", "t", "tst":
		return "test", true
	case "start", "stop", "restart":
		return words[0], true
	}
	if tool == "yarn" || tool == "pnpm" || tool == "bun" {
		builtins := set("add", "install", "i", "remove", "rm", "up", "upgrade", "update", "init", "create", "dlx", "exec", "x", "link", "unlink", "why", "info", "list", "ls", "outdated", "publish", "pack", "config", "cache", "audit", "global", "import", "patch", "set", "version", "workspaces", "workspace", "plugin", "build")
		if !builtins[words[0]] {
			return words[0], true
		}
	}
	return "", false
}

// psScripts finds .ps1 files a PowerShell command runs (.\x.ps1, & .\x.ps1,
// x.ps1 by path) and pwsh -File targets.
func psScripts(cmd string) []Script {
	var out []Script
	for _, stmt := range strings.FieldsFunc(cmd, func(r rune) bool { return r == ';' || r == '\n' }) {
		toks := psTokens(stmt)
		for i, t := range toks {
			u := strings.Trim(t, `"'`)
			first := i == 0 || psSeparator(toks[i-1]) || toks[i-1] == "&" || toks[i-1] == "."
			if first && strings.HasSuffix(strings.ToLower(u), ".ps1") {
				out = append(out, Script{Path: u, Via: "powershell"})
			}
			if (strings.EqualFold(u, "-file") || strings.EqualFold(u, "-f")) && i > 0 && i+1 < len(toks) {
				if n := cmdName(strings.Trim(toks[0], `"'`)); n == "pwsh" || n == "powershell" {
					out = append(out, Script{Path: strings.Trim(toks[i+1], `"'`), Via: "powershell"})
				}
			}
		}
	}
	return out
}

// deriveScripts analyzes the scripts the gateway attached (ScriptsKey) as
// if their text had been typed inline.
func deriveScripts(params map[string]any, o Options) Facts {
	var f Facts
	list, _ := params[ScriptsKey].([]any)
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			f.opaque("attached script entry is malformed")
			continue
		}
		p, _ := m["path"].(string)
		via, _ := m["via"].(string)
		content, _ := m["content"].(string)
		name, _ := m["name"].(string)
		label := p
		if name != "" {
			label = p + "#" + name
		}
		if e, _ := m["error"].(string); e != "" {
			f.opaque("runs a script that could not be inspected (" + label + ": " + e + ")")
			continue
		}
		var sf Facts
		switch scriptKind(p, via, content) {
		case "shell":
			sf = shellDepth(content, 1, o)
		case "powershell":
			sf = powerShellDepth(content, 1)
		case "code":
			sf = inspectCode(content, 1, o)
		default:
			sf.opaque("runs a script of a kind the analyzer cannot inspect (" + label + ")")
		}
		if sf.Destructive || sf.SecretAccess || sf.Opaque || sf.SelfTamper || sf.SelfSecret || sf.InlineDynamic {
			f.add("runs script " + label + ", which:")
		}
		f.merge(sf)
	}
	return f
}

// scriptKind decides how to read a script: by how it is run, then by
// extension, then by shebang.
func scriptKind(p, via, content string) string {
	switch via {
	case "shell", "npm":
		return "shell"
	case "powershell":
		return "powershell"
	case "python", "node", "perl", "ruby", "php", "deno", "bun":
		return "code"
	}
	switch strings.ToLower(path.Ext(slash(p))) {
	case ".sh", ".bash", ".zsh", ".ksh", ".command":
		return "shell"
	case ".ps1":
		return "powershell"
	case ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".php":
		return "code"
	}
	if first, _, _ := strings.Cut(content, "\n"); strings.HasPrefix(first, "#!") {
		switch {
		case strings.Contains(first, "pwsh") || strings.Contains(first, "powershell"):
			return "powershell"
		case strings.Contains(first, "python") || strings.Contains(first, "node") || strings.Contains(first, "perl") ||
			strings.Contains(first, "ruby") || strings.Contains(first, "php") || strings.Contains(first, "deno") || strings.Contains(first, "bun"):
			return "code"
		case strings.Contains(first, "sh"):
			return "shell"
		}
	}
	// No extension, no shebang: the kernel would run it as /bin/sh.
	return "shell"
}
