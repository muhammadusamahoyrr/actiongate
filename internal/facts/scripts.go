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
	// Uncertain: an option the analyzer does not model came before the
	// operand, so Path may be that option's value and the real script
	// another word. Reported opaque rather than guessed.
	Uncertain bool `json:"uncertain,omitempty"`
}

// markUncertain flags the script just recorded.
func (a *shellAnalyzer) markUncertain(unsure bool) {
	if unsure && len(a.scripts) > 0 {
		a.scripts[len(a.scripts)-1].Uncertain = true
	}
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

// runnerOpts models a runner's options well enough to find its script
// operand. An option it does not list makes the operand UNCERTAIN (it may
// take the next word as its value: bash --rcfile evil.sh x.sh), which is
// reported opaque rather than guessed.
type runnerOpts struct {
	noValue, value         string          // short options
	longNoValue, longValue map[string]bool // long options (--x=y is always self-contained)
	inline                 map[string]bool // code given inline / from stdin: no script operand
	// unsure lists options (short "-r" or long "--require") whose value is
	// code that also gets loaded, or that change directory: the analyzer
	// does not read that code, so the operand is uncertain (opaque).
	unsure map[string]bool
}

var runners = map[string]runnerOpts{
	"shell": {
		noValue: "abefhkmnptuvxBCEHPTilr", value: "oO",
		longNoValue: set("--norc", "--noprofile", "--login", "--posix", "--verbose", "--noediting", "--restricted", "--debugger", "--help", "--version"),
		longValue:   set("--rcfile", "--init-file"),
		inline:      set("-c", "-s"),
		// -i/-l/--login source ~/.bashrc / profile files, which the agent
		// can write; --rcfile/--init-file name one.
		unsure: set("--rcfile", "--init-file", "-i", "-l", "--login"),
	},
	"python": {
		noValue: "bBdEhiIOPqsSuvVxR", value: "WXQ",
		longNoValue: set("--help", "--version"), longValue: set("--check-hash-based-pycs"),
		inline: set("-c", "-m", "-"),
	},
	"node": {
		noValue: "vhic", value: "r",
		longNoValue: set("--no-warnings", "--trace-warnings", "--enable-source-maps", "--inspect", "--inspect-brk",
			"--watch", "--test", "--expose-gc", "--no-deprecation", "--trace-deprecation", "--preserve-symlinks",
			"--abort-on-uncaught-exception", "--trace-uncaught", "--help", "--version"),
		longValue: set("--require", "--import", "--loader", "--experimental-loader", "--env-file", "--env-file-if-exists", "--max-old-space-size"),
		inline:    set("-e", "-p", "--eval", "--print", "-"),
		// --env-file can set NODE_OPTIONS, which loads code.
		unsure: set("-r", "--require", "--import", "--loader", "--experimental-loader", "--env-file", "--env-file-if-exists"),
	},
	"perl": {noValue: "wWXtTcnpasluU0", value: "IMm", inline: set("-e", "-E", "-"), unsure: set("-M", "-m", "-I")},
	"ruby": {noValue: "wWvcdynpalhs", value: "IrEC", inline: set("-e", "-"), unsure: set("-r", "-C", "-I")},
	// -d auto_prepend_file=..., -c custom php.ini: both can load code.
	"php":   {noValue: "hvqsnailw", value: "dcz", inline: set("-r", "-"), unsure: set("-z", "-d", "-c")},
	"deno":  {inline: set("--eval", "-")},
	"bun":   {inline: set("-e", "--eval", "-")},
	"other": {inline: set("-c", "-e", "-")},
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
		if p, ok, unsure := scriptOperand(rest, runners["shell"]); ok {
			add(p, "shell", "")
			a.markUncertain(unsure)
		}
	case name == "source" || name == ".":
		if len(rest) > 0 {
			add(rest[0].text, "shell", "")
		}
	case interpreters[name]:
		kind, ro := name, runners["other"]
		switch {
		case strings.HasPrefix(name, "python"):
			kind, ro = "python", runners["python"]
		case name == "node" || name == "nodejs":
			kind, ro = "node", runners["node"]
		case name == "perl" || name == "ruby" || name == "php":
			ro = runners[name]
		case name == "deno" || name == "bun":
			ro = runners[name]
			// deno run x.ts / bun run x.ts / bun x.ts
			if len(rest) > 0 && (rest[0].text == "run" || rest[0].text == "x") {
				rest = rest[1:]
			}
		}
		if p, ok, unsure := scriptOperand(rest, ro); ok {
			add(p, kind, "")
			a.markUncertain(unsure)
		}
	case name == "go" && len(rest) > 1 && rest[0].text == "run":
		// go run x.go [y.go]: the named files are the program. A package
		// path (go run ./cmd/x, go run .) is a directory and is not read.
		for _, x := range rest[1:] {
			if x.text == "--" {
				break
			}
			if !strings.HasPrefix(x.text, "-") && strings.HasSuffix(strings.ToLower(x.text), ".go") {
				add(x.text, "go", "")
			}
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
// option or an option's value. ok is false when inline code comes first or
// there is no operand. uncertain is true when an option the runner model
// does not know came first, so the operand may really be its value.
func scriptOperand(rest []arg, ro runnerOpts) (op string, ok, uncertain bool) {
	for i := 0; i < len(rest); i++ {
		t := rest[i].text
		if ro.inline[t] {
			return "", false, false
		}
		switch {
		case t == "--":
			if i+1 < len(rest) {
				return rest[i+1].text, true, uncertain
			}
			return "", false, false
		case strings.HasPrefix(t, "--"):
			name, _, hasVal := strings.Cut(t, "=")
			if ro.unsure[name] {
				uncertain = true
			}
			switch {
			case hasVal || ro.longNoValue[name]:
			case ro.longValue[name]:
				i++
			default:
				uncertain = true
			}
		case strings.HasPrefix(t, "-") && len(t) > 1:
			// A short cluster: options until one takes a value, whose value
			// is the rest of the word or the next word.
			for j, r := range t[1:] {
				o := "-" + string(r)
				if ro.inline[o] {
					return "", false, false // bash -ec '...', python -Bc '...'
				}
				if ro.unsure[o] {
					uncertain = true // node -r x, ruby -C dir, perl -MFoo
				}
				if strings.ContainsRune(ro.value, r) {
					if j == len(t)-2 {
						i++ // value is the next word
					}
					break
				}
				if !strings.ContainsRune(ro.noValue, r) {
					uncertain = true
				}
			}
		default:
			return t, true, uncertain
		}
	}
	return "", false, false
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
		if secret, _ := m["secret"].(bool); secret {
			// The gateway does not copy secrets: sourcing or running one is
			// reading it.
			f.secretPath(p, "runs or sources secret file "+label)
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

// scriptKind decides how to read a script. An explicit runner (bash x,
// python x) decides. A file run directly (./x) is run the way the kernel
// runs it: by its shebang interpreter, matched by exact name, or, with no
// shebang, by /bin/sh — the extension plays no part. An interpreter the
// analyzer does not know is "unknown", which is opaque.
func scriptKind(p, via, content string) string {
	switch via {
	case "shell", "npm":
		return "shell"
	case "powershell":
		return "powershell"
	case "python", "node", "perl", "ruby", "php", "deno", "bun", "go":
		return "code"
	}
	if via == "exec" && strings.EqualFold(path.Ext(slash(p)), ".ps1") {
		return "powershell" // PowerShell runs .ps1 by extension
	}
	first, _, _ := strings.Cut(content, "\n")
	if !strings.HasPrefix(first, "#!") {
		return "shell" // ENOEXEC: the shell runs it
	}
	return shebangKind(first)
}

// shebangKind maps a "#!" line to how its interpreter reads the file.
func shebangKind(line string) string {
	fields := strings.Fields(strings.TrimPrefix(line, "#!"))
	if len(fields) == 0 {
		return "shell"
	}
	interp, args := cmdName(fields[0]), fields[1:]
	if interp == "env" {
		interp, args = "", nil
		for i, f := range fields[1:] {
			if strings.HasPrefix(f, "-") || strings.Contains(f, "=") {
				continue // env -S, env FOO=bar
			}
			interp, args = cmdName(f), fields[i+2:]
			break
		}
	}
	kind, ro := "unknown", runnerOpts{}
	switch {
	case shells[interp] && interp != "fish", interp == "ash", interp == "mksh":
		kind, ro = "shell", runners["shell"]
	case interp == "pwsh" || interp == "powershell":
		return "unknown" // pwsh shebang options are not modelled
	case strings.HasPrefix(interp, "python"):
		kind, ro = "code", runners["python"]
	case interp == "node" || interp == "nodejs":
		kind, ro = "code", runners["node"]
	case interpreters[interp]:
		kind, ro = "code", runners[interp]
	}
	if kind == "unknown" {
		return kind
	}
	// Interpreter arguments must be harmless switches (#!/bin/bash -eu,
	// #!/usr/bin/python3 -u). Anything else — inline code, an rc file, a
	// module to load, an option not modelled — changes what runs: opaque.
	for _, a := range args {
		if !harmlessSwitch(a, ro) {
			return "unknown"
		}
	}
	return kind
}

// harmlessSwitch: a, a single word, is only no-value options the runner
// model lists.
func harmlessSwitch(a string, ro runnerOpts) bool {
	if strings.HasPrefix(a, "--") {
		return ro.longNoValue[a]
	}
	if !strings.HasPrefix(a, "-") || len(a) < 2 {
		return false
	}
	for _, r := range a[1:] {
		if !strings.ContainsRune(ro.noValue, r) || ro.inline["-"+string(r)] || ro.unsure["-"+string(r)] {
			return false
		}
	}
	return true
}
