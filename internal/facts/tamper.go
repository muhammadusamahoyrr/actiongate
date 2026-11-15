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
//
// This is pattern analysis, so it narrows the gap rather than closing it:
// code the analyzer cannot see through is the opaque fact's job.

// IsControlPath reports whether a path names a file actiongate's own
// enforcement depends on. A glob directly inside .claude (".claude/*")
// counts: it can expand to the settings files.
func IsControlPath(p string) bool {
	p = normPath(p)
	if p == "" {
		return false
	}
	base := path.Base(p)
	dir := path.Dir(p)
	parent := path.Base(dir)
	if matchName(base, "ag-hook", "ag-hook.exe", "gateway.json", "gateway.json.lock") {
		return true
	}
	if matchName(parent, ".claude") {
		// Claude Code's hook configuration, project or user level. Any
		// glob inside .claude counts too: it can expand to the settings.
		return matchName(base, "settings.json", "settings.local.json") || strings.ContainsAny(base, "*?[")
	}
	return matchName(base, "dev.json") && isActiongateConfigDir(dir)
}

// matchName reports whether one path component is, or as a glob could
// expand to, one of names.
func matchName(component string, names ...string) bool {
	glob := strings.ContainsAny(component, "*?[")
	for _, n := range names {
		if component == n {
			return true
		}
		if ok, _ := path.Match(component, n); glob && ok {
			return true
		}
	}
	return false
}

// IsControlDir reports whether a path names a directory that holds control
// files: a .claude directory, or actiongate's per-user config directory.
// Deleting, moving or re-permissioning one switches enforcement off as
// surely as editing the file inside it.
func IsControlDir(p string) bool {
	p = normPath(p)
	if p == "" {
		return false
	}
	return matchName(path.Base(p), ".claude") || isActiongateConfigDir(p)
}

// isActiongateConfigDir: an "actiongate" directory under a user config
// root, spelled literally or through a variable ($env:APPDATA,
// %APPDATA%, $XDG_CONFIG_HOME). A parent the analyzer cannot read (a
// glob) counts. A bare "actiongate" (e.g. the source checkout) does not.
func isActiongateConfigDir(p string) bool {
	if !matchName(path.Base(p), "actiongate") {
		return false
	}
	parent := path.Base(path.Dir(p))
	switch parent {
	case "roaming", ".config", "application support", "$env:appdata", "%appdata%", "$appdata",
		"$xdg_config_home", "${xdg_config_home}", "$env:xdg_config_home":
		return true
	}
	return strings.ContainsAny(parent, "*?[")
}

// controlBaseName reports whether a bare file name is one a control file
// could have. Used when the working directory is unknown.
func controlBaseName(p string) bool {
	switch path.Base(normPath(p)) {
	case "ag-hook", "ag-hook.exe", "gateway.json", "gateway.json.lock", "settings.json", "settings.local.json", "dev.json":
		return true
	}
	return false
}

// normPath lower-cases and slashes p and undoes the spellings Windows
// treats as the same file: trailing dots and spaces on a component
// ("settings.json." is settings.json) and an NTFS stream suffix
// ("settings.json::$DATA", "x.json:alt").
func normPath(p string) string {
	p = strings.Trim(strings.TrimSpace(p), `"'`)
	p = strings.ToLower(slash(p))
	parts := strings.Split(p, "/")
	for i, c := range parts {
		if i == 0 && len(c) == 2 && c[1] == ':' {
			continue // drive letter
		}
		if j := strings.Index(c, ":"); j > 0 && !strings.HasPrefix(c, "$") {
			c = c[:j] // not $env:NAME, which is a variable, not a stream
		}
		if t := strings.TrimRight(c, ". "); t != "" && t != c && c != "." && c != ".." {
			c = t
		}
		parts[i] = c
	}
	p = strings.Join(parts, "/")
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
	}
	return p
}

func isAbsPath(p string) bool {
	p = slash(p)
	return strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") || len(p) >= 2 && p[1] == ':'
}

// unknownDir marks a working directory the analyzer cannot resolve (cd to
// a variable, a command substitution, or "cd -").
const unknownDir = "\x00?"

// cwdTracker follows cd / pushd / Set-Location within one command line, so
// "cd .claude && echo {} > settings.local.json" is judged on the path the
// write really hits. Scoping (subshells, popd) is ignored: a cd is assumed
// to stick, which can only over-report.
type cwdTracker struct{ dir string }

func (c *cwdTracker) cd(target string, literal bool) {
	switch {
	case !literal || target == "" || target == "-":
		c.dir = unknownDir
	case isAbsPath(target) || c.dir == "":
		c.dir = slash(target)
	case c.dir != unknownDir:
		c.dir = path.Join(c.dir, slash(target))
	}
}

// resolve returns the paths a possibly-relative path may stand for.
func (c *cwdTracker) resolve(p string) []string {
	if c.dir == "" || c.dir == unknownDir || isAbsPath(p) {
		return []string{p}
	}
	return []string{p, path.Join(c.dir, slash(p))}
}

// file reports whether p, written from the current directory, is a control
// file. With an unknown directory any control file name counts.
func (c *cwdTracker) file(p string) bool {
	if c.dir == unknownDir && !isAbsPath(p) && controlBaseName(p) {
		return true
	}
	for _, r := range c.resolve(p) {
		if IsControlPath(r) {
			return true
		}
	}
	return false
}

// target is file plus control directories, for commands that delete, move
// or re-permission their operands.
func (c *cwdTracker) target(p string) bool {
	if c.file(p) {
		return true
	}
	for _, r := range c.resolve(p) {
		if IsControlDir(r) {
			return true
		}
	}
	return false
}

// shellMutators change or remove every file operand they are given.
var shellMutators = set("rm", "rmdir", "unlink", "mv", "truncate", "chmod", "chown", "chattr", "tee", "touch", "shred")

// tamperArgs flags a shell command that writes, moves or deletes a control
// file or directory, and follows cd/pushd. Copy-like commands only write
// their destination; in-place editors (sed -i, perl -i) write their
// operands.
func (a *shellAnalyzer) tamperArgs(name string, rest []arg) {
	if name == "cd" || name == "pushd" {
		target, literal := "", true
		for _, x := range rest {
			if !strings.HasPrefix(x.text, "-") || x.text == "-" {
				target, literal = x.text, x.lit
				break
			}
		}
		a.cwd.cd(target, literal)
		return
	}
	hit := func(why string) { a.f.selfTamper(name + " " + why) }
	switch {
	case shellMutators[name]:
		for _, x := range rest {
			for _, c := range pathCandidates(x.text) {
				if a.cwd.target(c) {
					hit("modifies actiongate control path " + path.Base(slash(c)))
					return
				}
			}
		}
	case copyLike[name]:
		var ops []arg
		dest, recursive := "", false
		for i := 0; i < len(rest); i++ {
			t := rest[i].text
			switch {
			case t == "-t" || t == "--target-directory":
				if i+1 < len(rest) {
					dest = rest[i+1].text
					i++
				}
			case strings.HasPrefix(t, "--target-directory="):
				dest = strings.TrimPrefix(t, "--target-directory=")
			case t == "--recursive" || t == "--archive":
				recursive = true
			case strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--"):
				recursive = recursive || strings.ContainsAny(t, "rRa")
			case !strings.HasPrefix(t, "-"):
				ops = append(ops, rest[i])
			}
		}
		srcs := ops
		if dest == "" {
			if len(ops) == 0 {
				return
			}
			dest, srcs = ops[len(ops)-1].text, ops[:len(ops)-1]
		}
		if a.cwd.file(dest) {
			hit("overwrites actiongate control file " + path.Base(slash(dest)))
			return
		}
		// Copying INTO a control directory overwrites the real file when
		// a source is named like one, or is a tree that may contain one.
		if a.cwd.target(dest) {
			for _, src := range srcs {
				if recursive || controlBaseName(src.text) || strings.ContainsAny(src.text, "*?[") {
					hit("writes into actiongate control directory " + path.Base(slash(dest)))
					return
				}
			}
		}
	case name == "sed" || name == "perl":
		if inPlace(name, rest) {
			for _, x := range rest {
				if a.cwd.file(x.text) {
					hit("edits actiongate control file in place " + path.Base(slash(x.text)))
					return
				}
			}
		}
	case name == "dd":
		for _, x := range rest {
			if of, ok := strings.CutPrefix(x.text, "of="); ok && a.cwd.file(of) {
				hit("writes actiongate control file " + path.Base(slash(of)))
				return
			}
		}
	}
}

// inPlace reports whether sed/perl was asked to edit files in place: an i
// anywhere in a short-option cluster (sed -ni, sed -Ei, perl -pi.bak), up
// to an option whose argument follows (-e, -f), or --in-place.
func inPlace(name string, rest []arg) bool {
	for _, x := range rest {
		t := x.text
		if t == "--in-place" || strings.HasPrefix(t, "--in-place=") {
			return true
		}
		if len(t) < 2 || t[0] != '-' || t[1] == '-' {
			continue
		}
		for _, r := range t[1:] {
			if r == 'i' {
				return true
			}
			if r == 'e' || r == 'f' || (name == "perl" && (r == 'E' || r == 'M' || r == 'I')) {
				break
			}
		}
	}
	return false
}

// psWriters change or remove the files they name.
var psWriters = set("set-content", "sc", "add-content", "ac", "clear-content", "clc", "out-file",
	"new-item", "ni", "remove-item", "rm", "ri", "del", "erase", "rmdir", "rd", "rename-item", "ren", "rni",
	"move-item", "move", "mv", "mi", "copy-item", "copy", "cp", "cpi", "set-itemproperty", "sp",
	"set-acl", "tee-object", "tee")

// psPipeTargets act on the items piped into them (delete, move, rename,
// clear, re-permission). Content writers (Set-Content backup.json) write
// their own path, so piping a control file into one only reads it.
var psPipeTargets = set("remove-item", "rm", "ri", "del", "erase", "rmdir", "rd", "rename-item", "ren", "rni",
	"move-item", "move", "mv", "mi", "clear-content", "clc", "set-itemproperty", "sp", "set-acl")

// psLocation are the cmdlets and aliases that change directory.
var psLocation = set("set-location", "sl", "cd", "chdir", "push-location", "pushd")

// psNetWriters are .NET file APIs that write, move or delete: a statement
// calling one is judged on every path it mentions.
var psNetWriters = []string{"writealltext", "writeallbytes", "writealllines", "appendalltext", "appendalllines",
	"::delete", "::move", "::copy", "::replace", "::create", "openwrite", "streamwriter", "setaccesscontrol"}

// psTamperState carries the working directory across the statements of one
// PowerShell command.
type psTamperState struct{ cwd cwdTracker }

// psCandidates turns one token into the paths it may hold: a -Name:value
// parameter loses its prefix (a bare -Name holds no path), and
// comma-separated lists (method arguments, -Path a,b) are split.
func psCandidates(t string) []string {
	u := strings.Trim(t, `"'`)
	if strings.HasPrefix(u, "-") {
		i := strings.Index(u, ":")
		if i < 0 {
			return nil
		}
		u = u[i+1:]
	}
	var out []string
	for _, part := range strings.Split(u, ",") {
		if part = strings.Trim(strings.TrimSpace(part), `"'`); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// statement flags a PowerShell statement that writes a control file or
// directory, through a writer cmdlet, a .NET file API or a > / >>
// redirection, and follows Set-Location.
func (st *psTamperState) statement(toks []string) (string, bool) {
	lowerAll := strings.ToLower(strings.Join(toks, " "))
	netWrite := false
	for _, m := range psNetWriters {
		if strings.Contains(lowerAll, m) {
			netWrite = true
			break
		}
	}
	writer, location := "", false
	// upstream: a control path named earlier in this statement. A writer
	// later in the pipeline (Get-Item .claude\settings.json | Remove-Item)
	// takes its target from there, with no path of its own.
	upstream := ""
	for i, t := range toks {
		if i == 0 || psSeparator(toks[i-1]) {
			writer, location = "", false
			switch n := cmdName(strings.Trim(t, `"'`)); {
			case psWriters[n]:
				writer = n
				if i > 0 && toks[i-1] == "|" && upstream != "" && psPipeTargets[n] {
					return n + " modifies piped actiongate control path " + path.Base(slash(upstream)), true
				}
				continue
			case psLocation[n]:
				location = true
				continue
			}
		}
		u := strings.Trim(t, `"'`)
		if location {
			if c := psCandidates(t); len(c) > 0 {
				st.cwd.cd(c[0], !strings.ContainsAny(c[0], "$("))
				location = false
			}
			continue
		}
		if (t == ">" || t == ">>") && i+1 < len(toks) && st.cwd.file(strings.Trim(toks[i+1], `"'`)) {
			return "redirects output into actiongate control file " + path.Base(slash(strings.Trim(toks[i+1], `"'`))), true
		}
		if s, ok := strings.CutPrefix(u, ">>"); ok && st.cwd.file(s) || strings.HasPrefix(u, ">") && len(u) > 1 && st.cwd.file(u[1:]) {
			return "redirects output into actiongate control file", true
		}
		if writer == "" && !netWrite {
			for _, c := range psCandidates(t) {
				if st.cwd.target(c) {
					upstream = c
				}
			}
			continue
		}
		for _, c := range psCandidates(t) {
			if st.cwd.target(c) {
				via := writer
				if via == "" {
					via = ".NET file API"
				}
				return via + " modifies actiongate control path " + path.Base(slash(c)), true
			}
		}
	}
	return "", false
}

func (f *Facts) selfTamper(reason string) {
	f.SelfTamper = true
	f.add(reason)
}
