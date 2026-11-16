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
	// dev.json under ANY directory named actiongate: its parent may be a
	// variable or expression the analyzer cannot resolve, so do not
	// narrow this to the known config roots.
	return matchName(base, "dev.json") && matchName(parent, "actiongate")
}

// matchName reports whether one path component is, or could stand for, one
// of names: as a glob that could expand to it, or as a Windows 8.3 short
// name that could alias it (ACTION~1 for actiongate, SETTIN~1.JSO).
func matchName(component string, names ...string) bool {
	glob := strings.ContainsAny(component, "*?[")
	for _, n := range names {
		if component == n {
			return true
		}
		if ok, _ := path.Match(component, n); glob && ok {
			return true
		}
		if shortNameMatch(component, n) {
			return true
		}
	}
	return false
}

// shortNameMatch reports whether component is an 8.3 short name that could
// belong to name: up to six leading characters of the name's stem, ~N, and
// optionally up to three leading characters of its extension. Which ~N a
// file gets is not knowable statically, so any N matches (fail closed).
func shortNameMatch(component, name string) bool {
	stem, ext, _ := strings.Cut(component, ".")
	pre, num, ok := strings.Cut(stem, "~")
	if !ok || pre == "" || len(pre) > 6 || num == "" || len(ext) > 3 {
		return false
	}
	for _, r := range num {
		if r < '0' || r > '9' {
			return false
		}
	}
	// Short names drop dots and spaces from the long stem.
	nStem, nExt := name, ""
	if i := strings.LastIndex(name, "."); i > 0 {
		nStem, nExt = name[:i], name[i+1:]
	}
	nStem = strings.NewReplacer(".", "", " ", "").Replace(nStem)
	return strings.HasPrefix(nStem, pre) && strings.HasPrefix(nExt, ext)
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
	case "roaming", ".config", "application support":
		return true
	}
	// A parent the analyzer cannot read (a variable — the shell analyzer
	// renders an unresolved one as \x00 — an expression, a glob) may be
	// the config root: fail closed.
	return strings.ContainsAny(parent, "*?[$%(\x00")
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
	if p == "" {
		return ""
	}
	// Resolve . and .. lexically: ~/.config/x/../actiongate/pgdata is the
	// config dir, whatever the spelling.
	return path.Clean(p)
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
		// cwdSecret is never cleared within one command line: popd, cd -
		// and subshells can return to the config directory, and the
		// analyzer cannot scope them. Over-reporting is the safe side.
		// Entering actiongate's config directory — by any spelling,
		// including an unreadable variable ($APPDATA/actiongate) — makes
		// relative reads after it reads of its secrets.
		for _, r := range []string{target, a.cwd.dir} {
			if r != "" && r != unknownDir && IsActiongateSecretPath(r) {
				a.cwdSecret, a.cwdSecretDir = true, slash(r)
			}
		}
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
		ops, dest, recursive := copyOperands(name, rest)
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
		// With -t the last operand is a source — unless the option parse
		// was wrong. A control file there fails closed either way.
		if len(ops) > 0 && a.cwd.file(ops[len(ops)-1].text) {
			hit("may overwrite actiongate control file " + path.Base(slash(ops[len(ops)-1].text)))
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

// targetDirCmds are the copy-like commands with GNU's -t/--target-directory
// (rsync -t preserves times and scp has no -t, so they keep the last
// operand as destination).
var targetDirCmds = set("cp", "mv", "install", "ln")

// copyValueOpts are the short options that take a value, per command.
var copyValueOpts = map[string]string{"cp": "S", "mv": "S", "ln": "S", "install": "Sgom", "rsync": "efT", "scp": "cFiJlPoS"}

// copyOperands splits a copy-like command into its operands, an explicit
// target directory (-t DIR, -tDIR, -rt DIR, --target-directory=DIR, or any
// unambiguous prefix such as --target DIR) and whether it copies trees.
func copyOperands(name string, rest []arg) (ops []arg, dest string, recursive bool) {
	takesT := targetDirCmds[name]
	for i := 0; i < len(rest); i++ {
		t := rest[i].text
		switch {
		case t == "--":
			ops = append(ops, rest[i+1:]...)
			return ops, dest, recursive
		case strings.HasPrefix(t, "--"):
			opt, val, hasVal := strings.Cut(t, "=")
			switch {
			case takesT && len(opt) >= 4 && strings.HasPrefix("--target-directory", opt):
				if !hasVal && i+1 < len(rest) {
					val = rest[i+1].text
					i++
				}
				dest = val
			case strings.HasPrefix("--recursive", opt) && len(opt) >= 5, strings.HasPrefix("--archive", opt) && len(opt) >= 4:
				recursive = true
			}
		case len(t) > 1 && t[0] == '-':
			cluster := t[1:]
			for j, r := range cluster {
				if r == 'r' || r == 'R' || r == 'a' {
					recursive = true
				}
				// An option that takes a value ends the cluster: the rest
				// is its value (cp -S.tx is suffix ".tx", not -t x).
				if strings.ContainsRune(copyValueOpts[name], r) {
					if cluster[j+1:] == "" {
						i++ // value is the next word
					}
					break
				}
				if r == 't' && takesT {
					if v := cluster[j+1:]; v != "" {
						dest = v
					} else if i+1 < len(rest) {
						dest = rest[i+1].text
						i++
					}
					break
				}
			}
		default:
			ops = append(ops, rest[i])
		}
	}
	return ops, dest, recursive
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

// psExplicitPath reports whether a writer's arguments (up to the end of its
// pipeline element) name its own path: -Path / -LiteralPath / -FilePath,
// or a positional path straight after the cmdlet. Anything else (e.g.
// "Set-Content -Encoding utf8 x") is treated as binding from the pipe.
func psExplicitPath(args []string) bool {
	for i, t := range args {
		if psSeparator(t) || t == ")" || t == "}" {
			return false
		}
		l := strings.ToLower(t)
		for _, p := range []string{"-path", "-literalpath", "-filepath", "-pspath", "-lp"} {
			if l == p || strings.HasPrefix(l, p+":") {
				return true
			}
		}
		if i == 0 && !strings.HasPrefix(t, "-") {
			return true
		}
	}
	return false
}

// psLocation are the cmdlets and aliases that change directory.
var psLocation = set("set-location", "sl", "cd", "chdir", "push-location", "pushd")

// psNetWriters are .NET file APIs that write, move or delete: a statement
// calling one is judged on every path it mentions.
var psNetWriters = []string{"writealltext", "writeallbytes", "writealllines", "appendalltext", "appendalllines",
	"::delete", "::move", "::copy", "::replace", "::create", "openwrite", "streamwriter", "setaccesscontrol"}

// psTamperState carries the working directory across the statements of one
// PowerShell command. cwdSecret: a Set-Location entered actiongate's
// config directory (cwdSecretDir), so relative reads after it are reads
// of its secrets.
type psTamperState struct {
	cwd          cwdTracker
	cwdSecret    bool
	cwdSecretDir string
}

// secretOperand is the PowerShell twin of shellAnalyzer.secretOperand: an
// operand is judged on the path it names after Set-Location.
func (st *psTamperState) secretOperand(a string, copying bool) (string, bool) {
	for _, r := range st.cwd.resolve(a) {
		if IsSecretPath(r) || isSecretDir(r) && copying || strings.ContainsAny(r, "*?") && globMatchesSecret(r) {
			return r, true
		}
	}
	// A variable or expression operand ($PWD\dev.json, (Get-Location)\x)
	// may name the current directory: fail closed.
	if st.cwdSecret && a != "" && !isAbsPath(a) && !strings.HasPrefix(a, "-") {
		return st.cwdSecretDir + "/" + slash(a), true
	}
	return "", false
}

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
				// A content writer (Set-Content, Out-File, ...) binds its
				// Path from the pipe unless it names its own; only then is
				// the upstream control file merely read.
				if i > 0 && toks[i-1] == "|" && upstream != "" && (psPipeTargets[n] || !psExplicitPath(toks[i+1:])) {
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
				literal := !strings.ContainsAny(c[0], "$(")
				st.cwd.cd(c[0], literal) // cwdSecret is never cleared (see tamperArgs)
				for _, r := range []string{c[0], st.cwd.dir} {
					if r != "" && r != unknownDir && IsActiongateSecretPath(r) {
						st.cwdSecret, st.cwdSecretDir = true, slash(r)
					}
				}
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

// IsActiongateSecretPath reports whether a path lies in actiongate's own
// per-user config directory, or is that directory: dev.json (DB password,
// token secret, signing seeds, Slack secret), gateway.json (the gateway's
// bearer credential and Ed25519 seed), pgdata (the database files),
// postgres.log. dev.json and gateway.json count under any directory named
// actiongate, since its parent may be a variable the analyzer cannot read.
// Nothing in it is something an agent needs to read.
func IsActiongateSecretPath(p string) bool {
	p = normPath(p)
	if p == "" {
		return false
	}
	if matchName(path.Base(p), "dev.json", "gateway.json", "gateway.json.lock") && matchName(path.Base(path.Dir(p)), "actiongate") {
		return true
	}
	for q := p; ; q = path.Dir(q) {
		if isActiongateConfigDir(q) {
			return true
		}
		if parent := path.Dir(q); parent == q || parent == "." {
			return false
		}
	}
}

// mentionsActiongateSecret reports whether any string in params, or any
// word of one (a shell command), names an actiongate secret path.
func mentionsActiongateSecret(params map[string]any) bool {
	_, ok := findString(params, 0, func(s string) bool {
		if IsActiongateSecretPath(s) {
			return true
		}
		for _, w := range strings.FieldsFunc(s, func(r rune) bool {
			return strings.ContainsRune(" \t\r\n'\"`;|&<>()=,{}", r)
		}) {
			if IsActiongateSecretPath(w) {
				return true
			}
		}
		return false
	})
	return ok
}

func (f *Facts) selfTamper(reason string) {
	f.SelfTamper = true
	f.add(reason)
}

// ReachesActiongateConfig reports whether a recursive search rooted at p
// could descend into actiongate's config directory, and so print its
// secrets: p is the directory's root (Roaming, ~/.config, Application
// Support), an ancestor of it (AppData, Library, a home directory, users,
// a drive or filesystem root), or a variable naming one of those. Grep on
// %APPDATA% used to read dev.json with no fact raised, because only the
// file itself and its directory were recognised.
func ReachesActiongateConfig(p string) bool {
	raw := strings.ToLower(strings.Trim(strings.TrimSpace(p), `"'`))
	if raw == "" {
		return false
	}
	switch strings.TrimRight(raw, `/\`) {
	case "~", "$home", "${home}", "$env:home", "$env:userprofile", "%userprofile%", "%homepath%",
		"$env:appdata", "%appdata%", "$xdg_config_home", "${xdg_config_home}", "$env:localappdata":
		return true
	}
	np := strings.TrimRight(normPath(p), "/")
	if np == "" || len(np) == 2 && np[1] == ':' {
		return true // "/" or a drive root
	}
	switch path.Base(np) {
	case "roaming", "appdata", ".config", "application support", "library", "users", "home":
		return true
	}
	switch path.Base(path.Dir(np)) {
	case "users", "home": // a home directory: c:/users/x, /home/x, /Users/x
		return true
	}
	switch np {
	case "/root", "/var/root", "/private/var/root": // root's home on Linux and macOS
		return true
	}
	// ~name is that user's home directory.
	if t := strings.TrimRight(raw, `/\`); strings.HasPrefix(t, "~") && !strings.ContainsAny(t, `/\`) {
		return true
	}
	return false
}

// climbsOnly reports whether p is made only of ".." steps (.., ../..):
// relative to an unknown working directory, it can reach a home directory
// and from there the config directory.
func climbsOnly(p string) bool {
	raw := slash(strings.Trim(strings.TrimSpace(p), `"'`))
	if raw == "" {
		return false
	}
	np := path.Clean(raw) // ../. and ./.. are ..; ../../. is ../..
	for _, part := range strings.Split(np, "/") {
		if part != ".." {
			return false
		}
	}
	return true
}

// selfSecretSearch flags a recursive search that can reach actiongate's
// config directory.
func (f *Facts) selfSecretSearch(reason string) {
	f.secret(reason)
	f.SelfSecret = true
	f.add("could read actiongate's own secrets (searches its config directory)")
}

// recursiveSearch reports whether a reader command searches directories
// recursively: rg/ag/ack always do, grep only with -r/-R/--recursive.
func recursiveSearch(name string, rest []arg) bool {
	switch name {
	case "rg", "ag", "ack":
		return true
	case "grep", "egrep", "fgrep":
		if hasShortOrLong(rest, "rR", "--recursive") || hasShortOrLong(rest, "", "--dereference-recursive") {
			return true
		}
		// -d ACTION / --directories=ACTION with ACTION "recurse" recurses
		// too, in every spelling: -d recurse, -drecurse, -nd recurse,
		// --directories recurse, --dir=recurse.
		for i, x := range rest {
			if grepDirectoriesValue(rest, i) == "recurse" {
				return true
			}
			if x.text == "--" {
				break
			}
		}
	}
	return false
}

// grepDirectoriesValue returns the value given to grep's -d/--directories
// option at rest[i], or "" when rest[i] does not set it.
func grepDirectoriesValue(rest []arg, i int) string {
	t := rest[i].text
	next := func() string {
		if i+1 < len(rest) {
			return rest[i+1].text
		}
		return ""
	}
	if strings.HasPrefix(t, "--") {
		name, value, hasValue := strings.Cut(t, "=")
		if len(name) < 4 || !isLongPrefix(name, "--directories") && name != "--directories" {
			return ""
		}
		if hasValue {
			return value
		}
		return next()
	}
	if !isShortCluster(t) {
		return ""
	}
	// Walk the cluster: a letter that takes a value swallows the rest of
	// the word, so -ed is -e with pattern "d", not -d.
	for j := 1; j < len(t); j++ {
		switch t[j] {
		case 'd':
			if j+1 < len(t) {
				return t[j+1:]
			}
			return next()
		case 'A', 'B', 'C', 'D', 'e', 'f', 'm':
			return ""
		}
	}
	return ""
}
