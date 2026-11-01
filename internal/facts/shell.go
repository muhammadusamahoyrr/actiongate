package facts

import (
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// maxDepth bounds re-parsing of nested code (bash -c '...', eval, python -c
// "os.system('...')"). Deeper nesting is itself a reason for a human to look.
const maxDepth = 4

var destructiveMongo = regexp.MustCompile(`(?i)\.(drop|dropDatabase|deleteMany|remove)\s*\(`)

// dynamicCode spots inline code that evaluates computed code (exec(b64...),
// eval(x), new Function(x)): a literal string argument is the only safe form.
var dynamicCode = regexp.MustCompile(`\b(exec|eval|Function)\s*\(\s*[^'"\s)]`)

// inlineDynamic spots string or name construction inside interpreter code:
// 'rmt'+'ree', getattr(m, x), __import__(x), ”.join(...), chr(...),
// String.fromCharCode, obj['a'+'b'], bytes.fromhex, codecs.decode.
var inlineDynamic = regexp.MustCompile(`['"]\s*\+|\+\s*['"]|\bgetattr\s*\(|__import__\s*\(|\.join\s*\(|\bchr\s*\(|fromCharCode|\bbytes\.fromhex|\bcodecs\.decode|\bimportlib\.`)

var destructiveSQL = regexp.MustCompile(`(?i)\b(drop\s+(table|database|schema|view|index)\b|truncate\s+(table\s+)?[\w."]+|delete\s+from\s+[\w."]+\s*(;|$))`)

var shells = set("sh", "bash", "zsh", "dash", "ksh", "fish")
var interpreters = set("python", "python2", "python3", "node", "nodejs", "perl", "ruby", "php", "deno", "bun")
var dbClients = set("psql", "mysql", "mariadb", "sqlite3", "sqlcmd", "mongo", "mongosh", "cockroach", "clickhouse-client", "duckdb")

// readers are commands that put a file's contents where the agent can see
// them or send them elsewhere. Only these count as secret access: a program
// that is merely handed a secret path (docker --env-file, a dev server's
// --env-overlay) loads it without exposing it. The cost is a known miss: a
// custom script that prints the file it is given is not detected.
var readers = set("cat", "tac", "less", "more", "head", "tail", "nl", "grep", "egrep", "fgrep", "rg", "ag", "ack",
	"sed", "awk", "gawk", "cut", "sort", "uniq", "paste", "tr", "strings", "xxd", "od", "hexdump", "base64", "base32",
	"openssl", "gpg", "diff", "cmp", "comm", "jq", "yq", "source", ".", "cp", "mv", "scp", "rsync", "curl", "wget",
	"nc", "ncat", "socat", "tar", "zip", "gzip", "bzip2", "xz", "7z", "zcat", "bat", "dd", "iconv", "split", "column")

// patternFirst are readers whose first operand is a pattern or program, not
// a file, unless the pattern is given by flag (grep -e, sed -e, awk -f).
var patternFirst = map[string]map[string]bool{
	"grep": set("-e", "-f", "--regexp", "--file"), "egrep": set("-e", "-f"), "fgrep": set("-e", "-f"),
	"rg": set("-e", "-f", "--regexp", "--file"), "ag": {}, "ack": {},
	"sed": set("-e", "-f", "--expression", "--file"), "awk": set("-f"), "gawk": set("-f"), "jq": {}, "yq": {},
}

// gitReaders print file contents from the repository or its history.
var gitReaders = set("show", "diff", "cat-file", "blame", "log")

// copyLike commands take sources then one destination; only sources are read.
var copyLike = set("cp", "mv", "rsync", "scp", "install", "ln")

// Shell analyzes a bash command line.
func Shell(cmd string) Facts { return shellDepth(cmd, 0, Options{}) }

// ShellWith analyzes a bash command line with some analysis switched off or
// refined; see Options.
func ShellWith(cmd string, o Options) Facts { return shellDepth(cmd, 0, o) }

func shellDepth(cmd string, depth int, o Options) Facts {
	var f Facts
	if strings.TrimSpace(cmd) == "" {
		return f
	}
	if depth > maxDepth {
		f.opaque("nested code deeper than the analyzer follows")
		return f
	}
	if o.Tokenize || o.TokenizePlus {
		return tokenShell(cmd, depth, o)
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(cmd), "")
	if err != nil {
		f.opaque("command does not parse as shell")
		return f
	}
	a := &shellAnalyzer{depth: depth, opts: o, stdin: map[*syntax.Stmt]stdinSource{}, vars: map[string]string{}}
	syntax.Walk(file, a.visit)
	f.merge(a.f)
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

type shellAnalyzer struct {
	f     Facts
	depth int
	opts  Options
	// stdin records where a statement's input comes from, so an interpreter
	// reading its program from stdin can be judged on that program.
	stdin map[*syntax.Stmt]stdinSource
	// vars holds variables assigned a static value earlier in the same
	// command line (PY=/usr/bin/python3; "$PY" ...). A non-static
	// assignment removes the entry, so lookups never guess.
	vars  map[string]string
	sawDB bool
	texts []string
}

// stdinSource: piped means content the analyzer cannot see (a pipe);
// code is a static here-doc or here-string it can inspect.
type stdinSource struct {
	piped   bool
	code    string
	hasCode bool
}

func (a *shellAnalyzer) visit(node syntax.Node) bool {
	switch n := node.(type) {
	case *syntax.BinaryCmd:
		if n.Op == syntax.Pipe || n.Op == syntax.PipeAll {
			a.stdin[n.Y] = stdinSource{piped: true}
		}
	case *syntax.Stmt:
		for _, r := range n.Redirs {
			if r.Op == syntax.RdrIn || r.Op == syntax.RdrInOut {
				if t := a.approx(r.Word); IsSecretPath(t) {
					a.f.secret("redirects a secret file into a command")
				}
			}
			var body *syntax.Word
			switch {
			case r.Hdoc != nil:
				body = r.Hdoc
			case r.Op == syntax.WordHdoc:
				body = r.Word
			}
			if body != nil {
				code, ok := a.literal(body)
				if ok {
					a.stdin[n] = stdinSource{code: code, hasCode: true}
				} else {
					code = a.approx(body)
					a.stdin[n] = stdinSource{piped: true}
				}
				a.texts = append(a.texts, code)
			}
		}
		switch c := n.Cmd.(type) {
		case *syntax.CallExpr:
			if len(c.Args) == 0 {
				a.assign(c.Assigns)
			} else {
				a.call(c, a.stdin[n])
			}
		case *syntax.DeclClause:
			a.assign(c.Args)
		}
	case *syntax.FuncDecl:
		if forkBomb(n) {
			a.f.destructive("self-recursive background function (fork bomb)")
		}
	}
	return true
}

// arg is one expanded word: its text and whether it is fully static.
type arg struct {
	text string
	lit  bool
	// proc: the word is a process substitution, <(cmd); as a script
	// argument it runs whatever cmd prints.
	proc bool
}

func (a *shellAnalyzer) assign(assigns []*syntax.Assign) {
	if a.opts.NoVarResolve {
		return
	}
	for _, as := range assigns {
		if as.Name == nil {
			continue
		}
		if as.Value != nil && !as.Append && as.Array == nil {
			if v, ok := a.literal(as.Value); ok {
				a.vars[as.Name.Value] = v
				continue
			}
		}
		delete(a.vars, as.Name.Value)
	}
}

func (a *shellAnalyzer) call(c *syntax.CallExpr, in stdinSource) {
	var args []arg
	for _, w := range c.Args {
		// Split a copy: Walk is still traversing w and cannot visit BraceExp.
		cw := &syntax.Word{Parts: append([]syntax.WordPart(nil), w.Parts...)}
		syntax.SplitBraces(cw)
		for _, bw := range expand.Braces(cw) {
			s, ok := a.literal(bw)
			if !ok {
				s = a.approx(bw)
			}
			proc := false
			for _, part := range bw.Parts {
				if _, isProc := part.(*syntax.ProcSubst); isProc {
					proc = true
				}
			}
			args = append(args, arg{s, ok, proc})
			a.texts = append(a.texts, s)
		}
	}
	a.command(args, in)
}

// command classifies one simple command after wrappers are stripped.
func (a *shellAnalyzer) command(args []arg, in stdinSource) {
	args = unwrap(args)
	if len(args) == 0 {
		return
	}
	if !args[0].lit {
		a.f.opaque("command name is computed at run time")
		return
	}
	name := cmdName(args[0].text)
	rest := args[1:]

	switch {
	case name == "rm":
		if hasShortOrLong(rest, "rR", "--recursive") && (!a.opts.ExemptRegenerable || !allRegenerable(rest)) {
			a.f.destructive("recursive delete (rm)")
		}
	case name == "find":
		for i, x := range rest {
			if x.text == "-delete" {
				a.f.destructive("find -delete")
			}
			if (x.text == "-exec" || x.text == "-execdir" || x.text == "-ok") && i+1 < len(rest) {
				if set("rm", "shred", "unlink")[cmdName(rest[i+1].text)] {
					a.f.destructive("find -exec deletes every match")
				}
			}
		}
	case name == "git":
		if r := gitDestructive(texts(rest)); r != "" {
			a.f.destructive(r)
		}
		if sub := gitSubcommand(texts(rest)); gitReaders[sub] {
			a.secretArgs(name, rest)
		}
	case name == "dd":
		for _, x := range rest {
			if strings.HasPrefix(x.text, "of=/dev/") {
				a.f.destructive("dd writes to a raw device")
			}
		}
	case strings.HasPrefix(name, "mkfs") || name == "wipefs" || name == "shred":
		a.f.destructive(name + " destroys data")
	case name == "rimraf":
		a.f.destructive("recursive delete (rimraf)")
	case name == "docker" || name == "podman":
		t := texts(rest)
		if contains(t, "prune") && (contains(t, "volume") || contains(t, "system")) || contains(t, "volume") && contains(t, "rm") {
			a.f.destructive("deletes container volumes")
		}
	case name == "kubectl" || name == "oc":
		if len(rest) > 0 && rest[0].text == "delete" {
			a.f.destructive("kubectl delete")
		}
	case name == "terraform" || name == "tofu":
		t := texts(rest)
		if contains(t, "destroy") || contains(t, "-destroy") {
			a.f.destructive("terraform destroy")
		}
	case name == "aws":
		t := texts(rest)
		if contains(t, "s3") && (contains(t, "rm") && contains(t, "--recursive") || contains(t, "rb") && contains(t, "--force")) {
			a.f.destructive("bulk S3 delete")
		}
	case dbClients[name]:
		a.sawDB = true
		if name == "mongo" || name == "mongosh" {
			for _, x := range rest {
				if destructiveMongo.MatchString(x.text) {
					a.f.destructive("destructive MongoDB operation")
				}
			}
		}
	case name == "redis-cli":
		for _, x := range rest {
			if u := strings.ToUpper(x.text); u == "FLUSHALL" || u == "FLUSHDB" {
				a.f.destructive("redis " + u + " deletes every key")
			}
		}
	case name == "dropdb":
		a.f.destructive("dropdb deletes a database")
	case name == "rsync":
		for _, x := range rest {
			if strings.HasPrefix(x.text, "--delete") || x.text == "--remove-source-files" {
				a.f.destructive("rsync " + x.text + " deletes files at the destination")
			}
		}
	case name == "gcloud" || name == "az" || name == "helm":
		t := texts(rest)
		if contains(t, "delete") || contains(t, "uninstall") {
			a.f.destructive(name + " deletes cloud resources")
		}
	case shells[name]:
		a.nestedShell(rest, in)
	case name == "eval":
		code, ok := joinLiteral(rest)
		if !ok {
			a.f.opaque("eval of text built at run time")
		} else {
			a.f.merge(shellDepth(code, a.depth+1, a.opts))
		}
	case interpreters[name]:
		a.interpreter(name, rest, in)
	case name == "pwsh" || name == "powershell":
		for i, x := range rest {
			l := strings.ToLower(x.text)
			if strings.HasPrefix(l, "-e") && strings.HasPrefix("-encodedcommand", l) {
				a.f.opaque("PowerShell encoded command")
			}
			if (l == "-c" || l == "-command") && i+1 < len(rest) {
				code, ok := joinLiteral(rest[i+1:])
				if !ok {
					a.f.opaque("PowerShell code built at run time")
				} else {
					a.f.merge(PowerShell(code))
				}
				break
			}
		}
	}

	switch {
	case a.opts.NoReaders:
		// Ablation: every mention of a credential file counts as a read.
		a.mentionedSecret(name, rest)
	case readers[name]:
		a.secretArgs(name, operands(name, rest))
	}
}

// fromStdin judges a program an interpreter reads from stdin: a static
// here-doc is inspected like inline code; a pipe is opaque.
func (a *shellAnalyzer) fromStdin(who string, in stdinSource, inspect func(string, int, Options) Facts) {
	switch {
	case in.hasCode:
		a.f.merge(inspect(in.code, a.depth+1, a.opts))
	case in.piped:
		a.f.opaque(who + " reads its program from a pipe")
	}
}

func (a *shellAnalyzer) nestedShell(rest []arg, in stdinSource) {
	for i, x := range rest {
		if x.text == "-c" || isShortCluster(x.text) && strings.Contains(x.text, "c") {
			if i+1 >= len(rest) {
				return
			}
			if !rest[i+1].lit {
				a.f.opaque("shell -c with code built at run time")
				return
			}
			a.f.merge(shellDepth(rest[i+1].text, a.depth+1, a.opts))
			return
		}
		if !strings.HasPrefix(x.text, "-") {
			if x.proc {
				a.f.opaque("shell runs the output of a process substitution")
			}
			return // runs a script file
		}
	}
	a.fromStdin("shell", in, shellDepth)
}

func (a *shellAnalyzer) interpreter(name string, rest []arg, in stdinSource) {
	codeFlags := set("-c", "-e", "-E", "-r", "--eval", "-p", "--print")
	if name == "python" || name == "python2" || name == "python3" {
		codeFlags = set("-c")
	}
	for i, x := range rest {
		switch {
		case codeFlags[x.text]:
			if i+1 >= len(rest) {
				return
			}
			if !rest[i+1].lit {
				a.f.opaque(name + " runs code built at run time")
				return
			}
			a.f.merge(inspectCode(rest[i+1].text, a.depth+1, a.opts))
			return
		case x.text == "-m":
			return
		case x.text == "-":
			a.fromStdin(name, in, inspectCode)
			return
		case !strings.HasPrefix(x.text, "-"):
			if x.proc {
				a.f.opaque(name + " runs the output of a process substitution")
			}
			return // runs a script file
		}
	}
	a.fromStdin(name, in, inspectCode)
}

func (a *shellAnalyzer) secretArgs(name string, rest []arg) {
	candidates := rest
	if copyLike[name] {
		// The last operand is the destination: writing a secret is not reading one.
		last := -1
		for i, x := range rest {
			if !strings.HasPrefix(x.text, "-") {
				last = i
			}
		}
		if last >= 0 {
			candidates = append(append([]arg{}, rest[:last]...), rest[last+1:]...)
		}
	}
	for i, x := range candidates {
		if i > 0 && candidates[i-1].text == "--env-file" || strings.HasPrefix(x.text, "--env-file=") {
			continue // hands the file to a container; the agent never sees it
		}
		for _, c := range pathCandidates(x.text) {
			if IsSecretPath(c) || isSecretDir(c) || strings.ContainsAny(c, "*?[") && globMatchesSecret(strings.ReplaceAll(c, `\`, "")) {
				a.f.secret(name + " reads secret file " + c)
				return
			}
		}
	}
}

// operands drops a reader's leading pattern or program (grep PATTERN FILE,
// sed SCRIPT FILE, awk PROG FILE) so it is not mistaken for a file.
func operands(name string, rest []arg) []arg {
	byFlag, ok := patternFirst[name]
	if !ok {
		return rest
	}
	for _, x := range rest {
		if byFlag[x.text] {
			return rest
		}
	}
	for i, x := range rest {
		if !strings.HasPrefix(x.text, "-") || x.text == "-" {
			return append(append([]arg{}, rest[:i]...), rest[i+1:]...)
		}
	}
	return rest
}

func gitSubcommand(args []string) string {
	for i := 0; i < len(args); i++ {
		t := args[i]
		if t == "-C" || t == "-c" || t == "--git-dir" || t == "--work-tree" || t == "--namespace" {
			i++
			continue
		}
		if !strings.HasPrefix(t, "-") {
			return t
		}
	}
	return ""
}

// inspectCode looks inside inline interpreter code (python -c, node -e) for
// bulk deletion, secret file names and embedded shell commands.
func inspectCode(code string, depth int, o Options) Facts {
	var f Facts
	if dynamicCode.MatchString(code) {
		f.opaque("inline code evaluates code built at run time")
	}
	if inlineDynamic.MatchString(code) {
		f.inlineDynamic("inline code builds strings or names at run time")
	}
	l := strings.ToLower(code)
	for _, m := range []string{"rmtree", "rmsync", "rimraf", "remove_dir_all", "rm_rf", "fileutils.rm_r"} {
		if strings.Contains(l, m) {
			f.destructive("inline code deletes recursively (" + m + ")")
		}
	}
	if strings.Contains(l, "rmdir") && strings.Contains(l, "recursive") {
		f.destructive("inline code deletes recursively (rmdir recursive)")
	}
	for _, s := range stringLiterals(code) {
		if IsSecretPath(s) {
			f.secret("inline code opens secret file " + s)
		}
		if strings.Contains(s, " ") && depth <= maxDepth {
			inner := shellDepth(s, depth+1, o)
			if inner.Destructive {
				f.destructive("inline code runs a destructive shell command")
			}
			if inner.SecretAccess {
				f.secret("inline code runs a shell command that reads secrets")
			}
		}
	}
	return f
}

var stringLit = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'`)

func stringLiterals(code string) []string {
	var out []string
	for _, m := range stringLit.FindAllStringSubmatch(code, -1) {
		s := m[1]
		if s == "" {
			s = m[2]
		}
		out = append(out, s)
	}
	return out
}

// unwrap strips commands that only run another command: sudo, env, xargs,
// nohup, timeout, npx, ... so "sudo -u x rm -rf /" is judged as rm.
func unwrap(args []arg) []arg {
	valueFlags := map[string]map[string]bool{
		"sudo":    set("-u", "-g", "-p", "-C", "-D", "-h", "-r", "-t", "-U"),
		"doas":    set("-u", "-C"),
		"nice":    set("-n"),
		"xargs":   set("-n", "-I", "-L", "-P", "-d", "-E", "-s", "-a"),
		"timeout": set("-s", "-k", "--signal", "--kill-after"),
		"stdbuf":  {},
		"env":     set("-u", "-C", "-S"),
		"npx":     set("-p", "--package"),
	}
	for len(args) > 0 && args[0].lit {
		name := cmdName(args[0].text)
		switch name {
		case "sudo", "doas", "env", "command", "builtin", "exec", "nohup", "time", "nice",
			"stdbuf", "xargs", "timeout", "npx", "pnpx", "bunx", "unbuffer", "chronic":
		default:
			return args
		}
		i := 1
		for i < len(args) {
			t := args[i].text
			if valueFlags[name][t] {
				i += 2
				continue
			}
			if strings.HasPrefix(t, "-") || name == "env" && strings.Contains(t, "=") {
				i++
				continue
			}
			break
		}
		if name == "timeout" && i < len(args) {
			i++ // the duration
		}
		args = args[i:]
	}
	return args
}

// gitDestructive returns why a git invocation is destructive, or "".
func gitDestructive(args []string) string {
	i := 0
	for i < len(args) {
		t := args[i]
		if t == "-C" || t == "-c" || t == "--git-dir" || t == "--work-tree" || t == "--namespace" {
			i += 2
			continue
		}
		if strings.HasPrefix(t, "-") {
			i++
			continue
		}
		break
	}
	if i >= len(args) {
		return ""
	}
	sub, rest := args[i], args[i+1:]
	switch sub {
	case "push":
		for _, t := range rest {
			switch {
			case t == "--force" || t == "--mirror" || t == "--delete" || strings.HasPrefix(t, "--force-with-lease") || t == "--force-if-includes":
				return "git push rewrites or deletes remote history"
			case isShortCluster(t) && strings.ContainsAny(t, "fd"):
				return "git push rewrites or deletes remote history"
			case strings.HasPrefix(t, "+"):
				return "git push with a forced refspec"
			case strings.HasPrefix(t, ":") && len(t) > 1:
				return "git push deletes a remote branch"
			}
		}
	case "reset":
		if contains(rest, "--hard") {
			return "git reset --hard discards work"
		}
	case "clean":
		for _, t := range rest {
			if t == "--force" || isShortCluster(t) && strings.Contains(t, "f") {
				return "git clean deletes untracked files"
			}
		}
	case "branch":
		if contains(rest, "-D") || contains(rest, "--delete") && contains(rest, "--force") {
			return "git branch -D deletes unmerged work"
		}
	case "checkout":
		if contains(rest, ".") {
			return "git checkout . discards uncommitted changes"
		}
	case "restore":
		if contains(rest, ".") && !contains(rest, "--staged") && !contains(rest, "-S") {
			return "git restore . discards uncommitted changes"
		}
	case "filter-branch", "filter-repo":
		return "git " + sub + " rewrites history"
	case "stash":
		if contains(rest, "clear") {
			return "git stash clear deletes stashes"
		}
	}
	return ""
}

func forkBomb(fn *syntax.FuncDecl) bool {
	if fn.Name == nil {
		return false
	}
	recursive := false
	syntax.Walk(fn.Body, func(n syntax.Node) bool {
		if c, ok := n.(*syntax.CallExpr); ok && len(c.Args) > 0 {
			if s, ok := literal(c.Args[0]); ok && s == fn.Name.Value {
				recursive = true
			}
		}
		return !recursive
	})
	return recursive
}

// literal resolves a word to its static value, honouring quotes and
// backslashes. ok is false if any part is expanded at run time.
func literal(w *syntax.Word) (string, bool) { return resolve(w, nil, false) }

// literal, plus variables given a static value earlier in the command line.
func (a *shellAnalyzer) literal(w *syntax.Word) (string, bool) { return resolve(w, a.vars, false) }

// approx is literal with unknown parts replaced by a placeholder, which still
// exposes static suffixes such as "$HOME/.ssh/id_rsa".
func (a *shellAnalyzer) approx(w *syntax.Word) string {
	if w == nil {
		return ""
	}
	s, _ := resolve(w, a.vars, true)
	return s
}

// resolve renders a word. Without placeholder it stops at the first unknown
// part and reports ok=false; with placeholder it writes "\x00" there and
// carries on.
func resolve(w *syntax.Word, vars map[string]string, placeholder bool) (string, bool) {
	var b strings.Builder
	static := true
	unknown := func() bool {
		static = false
		b.WriteString("\x00")
		return placeholder
	}
	param := func(p *syntax.ParamExp) bool {
		if p.Param != nil && p.Exp == nil && p.Repl == nil && p.Index == nil && p.Slice == nil &&
			!p.Excl && !p.Length && !p.Width && p.Names == 0 {
			if v, ok := vars[p.Param.Value]; ok {
				b.WriteString(v)
				return true
			}
		}
		return unknown()
	}
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(unescape(p.Value, false))
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.ParamExp:
			if !param(p) {
				return "", false
			}
		case *syntax.DblQuoted:
			for _, dp := range p.Parts {
				switch q := dp.(type) {
				case *syntax.Lit:
					b.WriteString(unescape(q.Value, true))
				case *syntax.ParamExp:
					if !param(q) {
						return "", false
					}
				default:
					if !unknown() {
						return "", false
					}
				}
			}
		default:
			if !unknown() {
				return "", false
			}
		}
	}
	return b.String(), static
}

func unescape(s string, inDouble bool) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			next := s[i+1]
			if !inDouble || strings.IndexByte("$`\"\\\n", next) >= 0 {
				if next != '\n' {
					b.WriteByte(next)
				}
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// pathCandidates yields the argument plus the parts after "=" or "@", so
// "-d @.env", "file=@.env" and "--data=.env" all expose ".env".
func pathCandidates(s string) []string {
	out := []string{s}
	if i := strings.LastIndexAny(s, "=@"); i >= 0 && i+1 < len(s) {
		out = append(out, s[i+1:])
	}
	return out
}

func cmdName(s string) string {
	s = slash(s)
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	return strings.TrimSuffix(strings.ToLower(s), ".exe")
}

func hasShortOrLong(args []arg, shortLetters, long string) bool {
	for _, x := range args {
		if x.text == "--" {
			return false
		}
		if x.text == long {
			return true
		}
		if isShortCluster(x.text) && strings.ContainsAny(x.text, shortLetters) {
			return true
		}
	}
	return false
}

func isShortCluster(t string) bool {
	return len(t) > 1 && t[0] == '-' && t[1] != '-'
}

func joinLiteral(args []arg) (string, bool) {
	parts := make([]string, 0, len(args))
	for _, x := range args {
		if !x.lit {
			return "", false
		}
		parts = append(parts, x.text)
	}
	return strings.Join(parts, " "), true
}

func texts(args []arg) []string {
	out := make([]string, len(args))
	for i, x := range args {
		out[i] = x.text
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, i := range items {
		m[i] = true
	}
	return m
}
