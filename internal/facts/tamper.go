package facts

import (
	"path"
	"strings"
)

// Self-tamper: the agent being governed rewrites the thing governing it.
//
// actiongate reaches Claude Code through a PreToolUse hook declared in
// .claude/settings*.json and carried out by ag-hook, with the gateway's
// state in gateway.json and the dev install's seeds in
// %APPDATA%\actiongate\dev.json. All of those are ordinary files owned by the
// same user the agent runs as, so with a default-allow pack an agent could
// Edit its own hook out of settings.local.json, replace ag-hook, or rewrite
// the gateway's receipts — and every later call would go ungoverned. Reading
// them is harmless; changing them is exactly the event a firewall must not
// wave through.

// IsControlPath reports whether a path names a file actiongate's own
// enforcement depends on.
func IsControlPath(p string) bool {
	p = strings.Trim(strings.TrimSpace(p), `"'`)
	if p == "" {
		return false
	}
	p = strings.ToLower(slash(p))
	base := path.Base(p)
	dir := path.Base(path.Dir(p))
	switch base {
	case "ag-hook", "ag-hook.exe", "gateway.json", "gateway.json.lock":
		return true
	case "settings.json", "settings.local.json":
		// Claude Code's hook configuration, project or user level.
		return dir == ".claude"
	case "dev.json":
		return dir == "actiongate"
	}
	return false
}

// shellMutators change or remove every file operand they are given.
var shellMutators = set("rm", "unlink", "mv", "truncate", "chmod", "chown", "chattr", "tee", "touch", "shred")

// tamperArgs flags a shell command that writes, moves or deletes a control
// file. Copy-like commands only write their destination; in-place editors
// (sed -i, perl -i) write their operands.
func (a *shellAnalyzer) tamperArgs(name string, rest []arg) {
	var targets []arg
	switch {
	case shellMutators[name]:
		targets = rest
	case copyLike[name]:
		if name == "mv" {
			targets = rest
			break
		}
		for i := len(rest) - 1; i >= 0; i-- {
			if !strings.HasPrefix(rest[i].text, "-") {
				targets = rest[i : i+1]
				break
			}
		}
	case name == "sed" || name == "perl":
		for _, x := range rest {
			if x.text == "-i" || strings.HasPrefix(x.text, "-i") || x.text == "--in-place" || strings.HasPrefix(x.text, "--in-place=") || name == "perl" && strings.HasPrefix(x.text, "-pi") {
				targets = rest
				break
			}
		}
	case name == "dd":
		for _, x := range rest {
			if strings.HasPrefix(x.text, "of=") {
				targets = append(targets, arg{text: strings.TrimPrefix(x.text, "of="), lit: x.lit})
			}
		}
	}
	for _, x := range targets {
		for _, c := range pathCandidates(x.text) {
			if IsControlPath(c) {
				a.f.selfTamper(name + " modifies actiongate control file " + path.Base(slash(c)))
				return
			}
		}
	}
}

// psWriters change or remove the files they name.
var psWriters = set("set-content", "sc", "add-content", "ac", "clear-content", "clc", "out-file",
	"new-item", "ni", "remove-item", "rm", "ri", "del", "erase", "rename-item", "ren", "rni",
	"move-item", "move", "mv", "mi", "copy-item", "copy", "cp", "cpi", "set-itemproperty", "sp")

// psTamper flags a PowerShell statement that writes a control file, through
// a writer cmdlet or a > / >> redirection.
func psTamper(toks []string) (string, bool) {
	writer := ""
	for i, t := range toks {
		if i == 0 || psSeparator(toks[i-1]) {
			writer = ""
			if n := cmdName(strings.Trim(t, `"'`)); psWriters[n] {
				writer = n
			}
			continue
		}
		u := strings.Trim(t, `"'`)
		if (t == ">" || t == ">>") && i+1 < len(toks) && IsControlPath(toks[i+1]) {
			return "redirects output into actiongate control file " + path.Base(slash(strings.Trim(toks[i+1], `"'`))), true
		}
		if s, ok := strings.CutPrefix(u, ">>"); ok && IsControlPath(s) || strings.HasPrefix(u, ">") && IsControlPath(u[1:]) {
			return "redirects output into actiongate control file", true
		}
		if writer != "" && IsControlPath(u) {
			return writer + " modifies actiongate control file " + path.Base(slash(u)), true
		}
	}
	return "", false
}

func (f *Facts) selfTamper(reason string) {
	f.SelfTamper = true
	f.add(reason)
}
