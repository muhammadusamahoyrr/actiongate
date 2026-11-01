package facts

import (
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// tokenShell is the Options.Tokenize analysis: no syntax tree, only
// quote-aware splitting into simple commands and words, feeding the same
// per-command semantics as the full analyzer.
func tokenShell(cmd string, depth int, o Options) Facts {
	a := &shellAnalyzer{depth: depth, opts: o, stdin: map[*syntax.Stmt]stdinSource{}, vars: map[string]string{}}
	if !o.TokenizePlus {
		for _, seg := range splitSegments(cmd) {
			args := tokenWords(seg.text)
			for _, x := range args {
				a.texts = append(a.texts, x.text)
			}
			a.command(args, stdinSource{piped: seg.piped})
		}
	} else {
		// TokenizePlus: here-documents are cut out of the command line and
		// handed to the command that reads them, and variables assigned a
		// static value are substituted, as the full analyzer does, but
		// still without a syntax tree.
		for _, line := range splitHeredocs(cmd) {
			segs := splitSegments(line.text)
			for i, seg := range segs {
				text := substituteVars(seg.text, a.vars)
				if name, value, ok := staticAssignment(text); ok {
					a.vars[name] = value
					continue
				}
				args := tokenWords(text)
				for _, x := range args {
					a.texts = append(a.texts, x.text)
				}
				in := stdinSource{piped: seg.piped}
				if line.hasBody && i == line.bodySeg(segs) {
					in = stdinSource{code: line.body, hasCode: true}
					a.texts = append(a.texts, line.body)
				}
				a.command(stripHeredocMarker(args), in)
			}
		}
	}
	f := a.f
	if a.sawDB {
		for _, t := range a.texts {
			if destructiveSQL.MatchString(t) {
				f.destructive("destructive SQL sent to a database client")
				break
			}
		}
	}
	return f
}

type segment struct {
	text  string
	piped bool // the segment's stdin is the previous segment's output
}

// splitSegments cuts a command line at ;, newline, &&, ||, | and & outside
// quotes.
func splitSegments(cmd string) []segment {
	var segs []segment
	var cur strings.Builder
	var quote byte
	piped := false
	flush := func(nextPiped bool) {
		if strings.TrimSpace(cur.String()) != "" {
			segs = append(segs, segment{text: cur.String(), piped: piped})
		}
		cur.Reset()
		piped = nextPiped
	}
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '"' && i+1 < len(cmd) {
				cur.WriteByte(c)
				i++
				cur.WriteByte(cmd[i])
				continue
			}
			if c == quote {
				quote = 0
			}
			cur.WriteByte(c)
		case c == '\\' && i+1 < len(cmd):
			cur.WriteByte(c)
			i++
			cur.WriteByte(cmd[i])
		case c == '\'' || c == '"':
			quote = c
			cur.WriteByte(c)
		case c == ';' || c == '\n':
			flush(false)
		case c == '|' || c == '&':
			if i+1 < len(cmd) && cmd[i+1] == c {
				i++
				flush(false) // && or ||
			} else {
				flush(c == '|')
			}
		default:
			cur.WriteByte(c)
		}
	}
	flush(false)
	return segs
}

// tokenWords splits a segment into words at white space outside quotes and
// removes the quotes. A word that contains $ or a backquote outside single
// quotes is not static.
func tokenWords(seg string) []arg {
	var out []arg
	var cur strings.Builder
	var quote byte
	inWord, static := false, true
	flush := func() {
		if inWord {
			out = append(out, arg{text: cur.String(), lit: static})
		}
		cur.Reset()
		inWord, static = false, true
	}
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case quote == '"':
			switch {
			case c == '"':
				quote = 0
			case c == '\\' && i+1 < len(seg):
				i++
				cur.WriteByte(seg[i])
			default:
				if c == '$' || c == '`' {
					static = false
				}
				cur.WriteByte(c)
			}
		case c == ' ' || c == '\t' || c == '\r':
			flush()
		case c == '\'' || c == '"':
			quote = c
			inWord = true
		case c == '\\' && i+1 < len(seg):
			i++
			cur.WriteByte(seg[i])
			inWord = true
		default:
			if c == '$' || c == '`' {
				static = false
			}
			cur.WriteByte(c)
			inWord = true
		}
	}
	flush()
	return out
}

// mentionedSecret is the Options.NoReaders rule: any argument of any
// command that names a credential file counts as secret access.
func (a *shellAnalyzer) mentionedSecret(name string, rest []arg) {
	for _, x := range rest {
		for _, c := range pathCandidates(x.text) {
			if IsSecretPath(c) || isSecretDir(c) || strings.ContainsAny(c, "*?[") && globMatchesSecret(strings.ReplaceAll(c, `\`, "")) {
				a.f.secret(name + " mentions secret file " + c)
				return
			}
		}
	}
}

// regenerableDirs are directory names that build tools, package managers and
// test runners recreate on demand. The list is generic, not fitted to any
// corpus; a real project directory that happens to carry one of these names
// (or a symlink pointing elsewhere) would be exempted too.
var regenerableDirs = set("build", "dist", "out", "target", "bin", "obj", ".next", ".nuxt", ".svelte-kit",
	".turbo", ".parcel-cache", "node_modules", "coverage", ".nyc_output", ".cache", "cache", "__pycache__",
	".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".gradle", "tmp", "temp", ".tmp")

// allRegenerable reports whether every operand of an rm is static and names a
// regenerable directory or something inside a temporary directory.
func allRegenerable(rest []arg) bool {
	n := 0
	for _, x := range rest {
		if x.text == "--" || strings.HasPrefix(x.text, "-") {
			continue
		}
		if !x.lit || !regenerablePath(x.text) {
			return false
		}
		n++
	}
	return n > 0
}

func regenerablePath(p string) bool {
	p = strings.ToLower(strings.TrimRight(slash(p), "/"))
	if p == "" || p == "." || p == ".." || p == "/" || p == "~" {
		return false
	}
	if strings.HasPrefix(p, "/tmp/") || strings.Contains(p, "/appdata/local/temp/") {
		return true
	}
	base := p
	if i := strings.LastIndex(p, "/"); i >= 0 {
		base = p[i+1:]
	}
	return regenerableDirs[base]
}

// heredocLine is one logical line of a command with the body of a
// here-document it opens, if any.
type heredocLine struct {
	text    string
	body    string
	hasBody bool
}

// bodySeg returns the index of the segment that contains the << marker.
func (l heredocLine) bodySeg(segs []segment) int {
	for i, s := range segs {
		if strings.Contains(s.text, "<<") {
			return i
		}
	}
	return len(segs) - 1
}

var heredocMarker = regexp.MustCompile(`<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)(['"]?)`)

// splitHeredocs cuts here-document bodies out of a command line. A body
// whose delimiter is quoted is static code; an unquoted body that contains
// $ or a backquote is treated as built at run time.
func splitHeredocs(cmd string) []heredocLine {
	lines := strings.Split(cmd, "\n")
	var out []heredocLine
	for i := 0; i < len(lines); i++ {
		l := heredocLine{text: lines[i]}
		if m := heredocMarker.FindStringSubmatch(lines[i]); m != nil && !strings.Contains(lines[i], "<<<") {
			quoted := m[1] != ""
			var body []string
			j := i + 1
			for ; j < len(lines); j++ {
				if strings.TrimSpace(lines[j]) == m[2] {
					break
				}
				body = append(body, lines[j])
			}
			l.body = strings.Join(body, "\n")
			l.hasBody = quoted || !strings.ContainsAny(l.body, "$`")
			i = j
		}
		out = append(out, l)
	}
	return out
}

var assignment = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)

// staticAssignment recognises a segment that only assigns a static value.
func staticAssignment(seg string) (string, string, bool) {
	m := assignment.FindStringSubmatch(seg)
	if m == nil {
		return "", "", false
	}
	words := tokenWords(m[2])
	if len(words) != 1 || !words[0].lit {
		return "", "", false
	}
	return m[1], words[0].text, true
}

var varRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// substituteVars replaces $NAME and ${NAME} with known static values.
func substituteVars(seg string, vars map[string]string) string {
	if len(vars) == 0 {
		return seg
	}
	return varRef.ReplaceAllStringFunc(seg, func(ref string) string {
		m := varRef.FindStringSubmatch(ref)
		name := m[1]
		if name == "" {
			name = m[2]
		}
		if v, ok := vars[name]; ok {
			return v
		}
		return ref
	})
}

// stripHeredocMarker drops the <<DELIM word from a command's arguments.
func stripHeredocMarker(args []arg) []arg {
	out := args[:0:0]
	for _, x := range args {
		if strings.HasPrefix(x.text, "<<") {
			continue
		}
		out = append(out, x)
	}
	return out
}
