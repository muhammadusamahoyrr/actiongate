package facts

import "strings"

// PowerShell has no Go parser, so this is a token-level analysis: statements
// split on ; and newlines, pipelines kept together. It recognises the
// cmdlets and aliases agents actually use; unusual syntax is a known gap
// (see docs/research/EVALUATION.md) rather than a silent allow-by-design.

var psRemove = set("remove-item", "rm", "ri", "del", "erase", "rmdir", "rd")
var psDisk = set("format-volume", "clear-disk", "remove-partition", "initialize-disk")
var psMetadata = set("test-path", "get-childitem", "gci", "ls", "dir", "get-item", "gi", "resolve-path", "split-path", "join-path", "new-item", "ni", "set-content", "sc", "out-file", "add-content", "ac")
var psCopy = set("copy-item", "copy", "cp", "cpi", "move-item", "move", "mv", "mi")

func PowerShell(cmd string) Facts { return powerShellDepth(cmd, 0) }

func powerShellDepth(cmd string, depth int) Facts {
	var f Facts
	if depth > maxDepth {
		f.opaque("nested code deeper than the analyzer follows")
		return f
	}
	for _, stmt := range strings.FieldsFunc(cmd, func(r rune) bool { return r == ';' || r == '\n' }) {
		f.merge(psStatement(stmt, depth))
	}
	return f
}

func psStatement(stmt string, depth int) Facts {
	var f Facts
	lower := strings.ToLower(stmt)
	if strings.Contains(lower, "[scriptblock]::create") {
		f.opaque("PowerShell script block built at run time")
	}
	toks := psTokens(stmt)
	recurse := false
	for _, t := range toks {
		l := strings.ToLower(t)
		if len(l) >= 2 && strings.HasPrefix("-recurse", l) || l == "/s" {
			recurse = true
		}
	}
	for i := 0; i < len(toks); i++ {
		if i > 0 && !psSeparator(toks[i-1]) {
			continue // only command positions name a command
		}
		name := cmdName(strings.Trim(toks[i], `"'`))
		args := psArgs(toks[i+1:])
		switch {
		case psRemove[name] && recurse:
			f.destructive("recursive delete (" + name + ")")
		case psDisk[name]:
			f.destructive(name + " destroys a disk or volume")
		case name == "git":
			if r := gitDestructive(args); r != "" {
				f.destructive(r)
			}
		case name == "iex" || name == "invoke-expression":
			f.opaque("Invoke-Expression runs text as code")
		case name == "&" || name == ".":
			if len(args) > 0 && strings.HasPrefix(args[0], "$") {
				f.opaque("calls a command held in a variable")
			}
		case name == "powershell" || name == "pwsh":
			for j, a := range args {
				l := strings.ToLower(a)
				if strings.HasPrefix(l, "-e") && strings.HasPrefix("-encodedcommand", l) {
					f.opaque("PowerShell encoded command")
				}
				if (l == "-c" || l == "-command") && j+1 < len(args) {
					f.merge(powerShellDepth(strings.Join(args[j+1:], " "), depth+1))
					break
				}
			}
		case name == "cmd":
			for j, a := range args {
				if strings.EqualFold(a, "/c") || strings.EqualFold(a, "/k") {
					f.merge(powerShellDepth(strings.Join(args[j+1:], " "), depth+1))
					break
				}
			}
		case name == "bash" || name == "sh" || name == "wsl":
			f.merge(Shell(strings.Join(args, " ")))
		}
		if psMetadata[name] {
			continue
		}
		cands := args
		if psCopy[name] {
			cands = dropLastOperand(args)
		}
		for _, a := range cands {
			if IsSecretPath(a) || isSecretDir(a) && psCopy[name] || strings.ContainsAny(a, "*?") && globMatchesSecret(a) {
				f.secret(name + " reads secret file " + a)
				break
			}
		}
	}
	return f
}

// psTokens splits on whitespace and makes |, (, ), {, } separate tokens.
// Quoted strings stay whole so cmd /c "rd /s /q x" can be re-analyzed.
func psTokens(s string) []string {
	var toks []string
	var cur strings.Builder
	var quote rune
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote = r
		case r == ' ' || r == '\t' || r == '\r':
			flush()
		case strings.ContainsRune("|(){}", r):
			flush()
			toks = append(toks, string(r))
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return toks
}

func psSeparator(t string) bool { return t == "|" || t == "(" || t == "{" || t == "&&" || t == "||" }

// psArgs returns the arguments up to the end of this pipeline element.
func psArgs(toks []string) []string {
	var out []string
	for _, t := range toks {
		if t == "|" || t == ")" || t == "}" {
			break
		}
		out = append(out, t)
	}
	return out
}

func dropLastOperand(args []string) []string {
	last := -1
	for i, a := range args {
		if !strings.HasPrefix(a, "-") {
			last = i
		}
	}
	if last < 0 {
		return args
	}
	return append(append([]string{}, args[:last]...), args[last+1:]...)
}
