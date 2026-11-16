package facts

import (
	"path"
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
			if destructiveSQL.MatchString(t) || destructiveSQLStatement(t) {
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
	// cwd follows cd/pushd so relative writes are judged on the path they
	// really hit (see tamper.go).
	cwd cwdTracker
	// cwdSecret: a cd/pushd entered actiongate's config directory
	// (cwdSecretDir), so relative reads after it are its secrets.
	cwdSecret    bool
	cwdSecretDir string
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
				if t, ok := a.secretOperand(a.approx(r.Word)); ok {
					a.f.secretPath(t, "redirects a secret file into a command")
				}
			}
			switch r.Op {
			case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
				if t := a.approx(r.Word); a.cwd.file(t) {
					a.f.selfTamper("redirects output into actiongate control file " + path.Base(slash(t)))
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
	// env -S 'rm -rf ~' splits its value into a whole command line.
	if len(args) > 1 && args[0].lit && cmdName(args[0].text) == "env" {
		for i := 1; i < len(args); i++ {
			t := args[i].text
			v, hasV := "", false
			switch {
			case t == "-S" || t == "--split-string":
				if i+1 < len(args) {
					v, hasV, i = args[i+1].text, true, i+1
				}
			case strings.HasPrefix(t, "-S") && len(t) > 2:
				v, hasV = t[2:], true
			case strings.HasPrefix(t, "--split-string="):
				v, hasV = strings.TrimPrefix(t, "--split-string="), true
			}
			if hasV {
				code := v
				if tail, ok := joinLiteral(args[i+1:]); ok {
					code += " " + tail
				}
				a.f.merge(shellDepth(code, a.depth+1, a.opts))
				return
			}
			if !strings.HasPrefix(t, "-") && !strings.Contains(t, "=") {
				break
			}
		}
	}
	args = unwrap(args)
	if len(args) == 0 {
		return
	}
	if !args[0].lit {
		a.f.opaque("command name is computed at run time")
		return
	}
	// A glob as the command name (/bin/r? -rf ~) runs whatever it expands
	// to; the analyzer cannot know which command that is. ([ and [[ are the
	// test builtins.)
	if t := args[0].text; t != "[" && t != "[[" && strings.ContainsAny(t, "*?[") {
		a.f.opaque("command name is a glob: " + t)
		return
	}
	name := cmdName(args[0].text)
	rest := args[1:]
	a.tamperArgs(name, rest)
	// A dangerous command whose arguments are computed at run time
	// (rm $(echo -rf) ~, rm "$X" ~) may receive flags the analyzer never
	// sees: fail closed. git counts only for its history-rewriting
	// subcommands, so `git commit -m "$(...)"` stays clean.
	if computedArgsMatter(name, rest) {
		for _, x := range rest {
			if !x.lit {
				a.f.opaque(name + " receives arguments computed at run time")
				break
			}
		}
	}

	switch {
	case name == "rm":
		if hasShortOrLong(rest, "rR", "--recursive") && (!a.opts.ExemptRegenerable || !allRegenerable(rest)) {
			a.f.destructive("recursive delete (rm)")
		}
		// rm * / rm -f dir/*: every file in a directory at once.
		for _, x := range rest {
			if t := x.text; t == "*" || t == ".*" || strings.HasSuffix(t, "/*") || strings.HasSuffix(t, "/.*") {
				a.f.destructive("rm deletes every file in a directory (" + t + ")")
				break
			}
		}
	case name == "chmod" || name == "chown" || name == "chgrp":
		if r := permDestructive(name, rest); r != "" {
			a.f.destructive(r)
		}
	case name == "find":
		for i := 0; i < len(rest); i++ {
			x := rest[i]
			if x.text == "-delete" {
				a.f.destructive("find -delete")
			}
			if x.text == "-exec" || x.text == "-execdir" || x.text == "-ok" || x.text == "-okdir" {
				// The words up to ; or + are a command run on every match:
				// judge it as one (find . -exec sh -c 'rm -rf "$1"' _ {} \;,
				// find . -exec sudo rm -rf {} +).
				j := i + 1
				for j < len(rest) && rest[j].text != ";" && rest[j].text != "+" {
					j++
				}
				sub := unwrap(rest[i+1 : j])
				if len(sub) > 0 && set("rm", "shred", "unlink")[cmdName(sub[0].text)] {
					a.f.destructive("find -exec deletes every match")
				}
				if len(sub) > 0 {
					a.command(rest[i+1:j], stdinSource{})
				}
				i = j
			}
		}
	case name == "su" || name == "runuser":
		// su -c 'cmd' [user]: a shell runs cmd.
		for i, x := range rest {
			if (x.text == "-c" || x.text == "--command") && i+1 < len(rest) {
				if !rest[i+1].lit {
					a.f.opaque(name + " -c with code built at run time")
				} else {
					a.f.merge(shellDepth(rest[i+1].text, a.depth+1, a.opts))
				}
				break
			}
		}
	case name == "ssh":
		a.remoteCommand(rest)
	case name == "awk" || name == "gawk" || name == "mawk" || name == "nawk":
		a.awk(rest)
	case name == "sed" || name == "gsed":
		a.sedExec(rest)
	case name == "git":
		if r := gitDestructive(texts(rest)); r != "" {
			a.f.destructive(r)
		}
		// Aliases run whatever they define: git -c alias.p='push --force' p,
		// git config alias.x '!rm -rf ~'. The analyzer cannot follow them.
		t := texts(rest)
		for i, w := range t {
			if w == "-c" && i+1 < len(t) && strings.HasPrefix(strings.ToLower(t[i+1]), "alias.") {
				a.f.opaque("git runs an alias defined inline (-c alias.*)")
			}
		}
		if gitSubcommand(t) == "config" {
			for _, w := range t {
				if strings.HasPrefix(strings.ToLower(w), "alias.") {
					a.f.opaque("git config defines an alias, which can run any command later")
				}
			}
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
	case name == "docker" || name == "podman" || name == "docker-compose" || name == "podman-compose":
		t := texts(rest)
		if contains(t, "prune") && (contains(t, "volume") || contains(t, "system")) || contains(t, "volume") && contains(t, "rm") {
			a.f.destructive("deletes container volumes")
		}
		// docker compose down -v / --volumes / --rmi all: deletes the
		// project's named volumes (its data).
		if (contains(t, "compose") || strings.HasSuffix(name, "compose")) && contains(t, "down") &&
			(contains(t, "-v") || contains(t, "--volumes") || contains(t, "--rmi")) {
			a.f.destructive("compose down deletes the project's volumes")
		}
	case name == "kubectl" || name == "oc":
		// The verb is the first positional word, after options that take a
		// value (kubectl -n prod delete ns app).
		if kubeVerb(rest) == "delete" {
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
		// Every service names destruction delete-*/terminate-*/remove-*
		// (ec2 terminate-instances, rds delete-db-cluster, cloudformation
		// delete-stack, dynamodb delete-table, ...).
		for _, w := range t {
			if strings.HasPrefix(w, "delete-") || strings.HasPrefix(w, "terminate-") || strings.HasPrefix(w, "remove-") || w == "deregister-image" {
				a.f.destructive("aws " + w + " destroys cloud resources")
				break
			}
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
	for i := 0; i < len(rest); i++ {
		x := rest[i]
		// Options whose value is the next word: bash -o pipefail -c '...'.
		switch x.text {
		case "-o", "+o", "-O", "+O", "--rcfile", "--init-file":
			i++
			continue
		}
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

// interpreterOpts: which short option letters take inline code as their
// value, and which take some other value as the next word.
var interpreterOpts = map[string]struct{ codeLetters, valueLetters string }{
	"python": {codeLetters: "c", valueLetters: "WXQ"},
	"node":   {codeLetters: "ep", valueLetters: "r"},
	"perl":   {codeLetters: "eE", valueLetters: "IMmx"},
	"ruby":   {codeLetters: "e", valueLetters: "IrECxF"},
	"php":    {codeLetters: "r", valueLetters: "dcz"},
	"other":  {codeLetters: "ce", valueLetters: ""},
}

func (a *shellAnalyzer) interpreter(name string, rest []arg, in stdinSource) {
	kind := name
	switch {
	case strings.HasPrefix(name, "python"):
		kind = "python"
	case name == "nodejs" || name == "deno" || name == "bun":
		kind = "node"
	}
	opts, ok := interpreterOpts[kind]
	if !ok {
		opts = interpreterOpts["other"]
	}
	runCode := func(i int) {
		if i >= len(rest) {
			return
		}
		if !rest[i].lit {
			a.f.opaque(name + " runs code built at run time")
			return
		}
		a.f.merge(inspectCode(rest[i].text, a.depth+1, a.opts))
		// perl -ne 'print' .env, ruby -ne, python -c '...' file: the words
		// after the code are files (or argv) the code reads.
		a.secretArgs(name, rest[i+1:])
	}
	for i := 0; i < len(rest); i++ {
		x := rest[i]
		switch {
		case x.text == "--eval" || x.text == "--print" || x.text == "--execute":
			runCode(i + 1)
			return
		case x.text == "-m":
			return
		case x.text == "-":
			a.fromStdin(name, in, inspectCode)
			return
		case isShortCluster(x.text):
			// A cluster runs options left to right until one takes a value:
			// python3 -Bc '...', perl -we '...', python3 -W ignore -c '...'.
			for j, r := range x.text[1:] {
				attached := x.text[2+j:]
				if strings.ContainsRune(opts.codeLetters, r) {
					if attached != "" {
						if !x.lit {
							a.f.opaque(name + " runs code built at run time")
						} else {
							a.f.merge(inspectCode(attached, a.depth+1, a.opts))
						}
						a.secretArgs(name, rest[i+1:])
					} else {
						runCode(i + 1)
					}
					return
				}
				if strings.ContainsRune(opts.valueLetters, r) {
					if attached == "" {
						i++ // the value is the next word
					}
					break
				}
			}
		case strings.HasPrefix(x.text, "--"):
			// long options: self-contained or unknown; keep scanning
		default:
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
			if p, ok := a.secretOperand(c); ok {
				a.f.secretPath(p, name+" reads secret file "+c)
				return
			}
		}
	}
}

// secretOperand reports whether a reader's operand is a secret, judged on
// the path it really names: resolved against the directory cd/pushd moved
// to. After a cd into actiongate's config directory — even one spelled
// through a variable the analyzer cannot read — any relative operand is
// treated as one of its files (cd ~/.config/actiongate && cat dev.json).
// Returns the path to report, which decides self_secret.
func (a *shellAnalyzer) secretOperand(c string) (string, bool) {
	for _, r := range a.cwd.resolve(c) {
		if IsSecretPath(r) || isSecretDir(r) || strings.ContainsAny(r, "*?[") && globMatchesSecret(strings.ReplaceAll(r, `\`, "")) {
			return r, true
		}
	}
	if a.cwdSecret && !isAbsPath(c) && !strings.HasPrefix(c, "-") && c != "" {
		return a.cwdSecretDir + "/" + slash(c), true
	}
	return "", false
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

// permDestructive: a recursive chmod/chown/chgrp over a broad target (/, ~,
// $HOME, system directories), or a recursive chmod that strips every
// permission (000, a-rwx), locks a user out of their own data.
func permDestructive(name string, rest []arg) string {
	if !hasShortOrLong(rest, "R", "--recursive") {
		return ""
	}
	broad := set("/", "~", "~/", "/*", "~/*", "$HOME", "${HOME}", "/home", "/etc", "/usr", "/var", "/bin", "/lib", "/opt", "/root", "/Users", "C:", `C:\`, "C:/")
	for _, x := range rest {
		t := x.text
		if strings.HasPrefix(t, "-") {
			continue
		}
		if broad[strings.TrimRight(t, "/")] || broad[t] {
			return name + " -R over " + t
		}
		if name == "chmod" {
			switch strings.TrimLeft(t, "0") {
			case "", "a-rwx", "ugo-rwx", "a=", "ugo=":
				return "chmod -R " + t + " removes every permission"
			}
		}
	}
	return ""
}

// destructiveSQLStatement catches what the regex misses: an UPDATE with
// no WHERE clause, and a DELETE whose WHERE is always true.
func destructiveSQLStatement(text string) bool {
	for _, stmt := range strings.Split(text, ";") {
		s := strings.ToLower(strings.Join(strings.Fields(stmt), " "))
		switch {
		case strings.HasPrefix(s, "update ") && strings.Contains(s, " set ") && !strings.Contains(s, " where "):
			return true
		case strings.HasPrefix(s, "delete from ") && trivialWhere.MatchString(s):
			return true
		}
	}
	return false
}

var trivialWhere = regexp.MustCompile(`\bwhere\s+(true|1|1\s*=\s*1|'1'\s*=\s*'1'|1\s*<>\s*0|not\s+false)\s*$`)

// kubeVerb is kubectl's verb: the first positional word, skipping global
// options and their values.
func kubeVerb(rest []arg) string {
	valueOpts := set("-n", "--namespace", "--context", "--kubeconfig", "--cluster", "--user", "-s", "--server",
		"--token", "--as", "--as-group", "--request-timeout", "--cache-dir", "-l", "--selector", "-o", "--output", "-c", "--container")
	for i := 0; i < len(rest); i++ {
		t := rest[i].text
		if valueOpts[t] {
			i++
			continue
		}
		if strings.HasPrefix(t, "-") {
			continue
		}
		return t
	}
	return ""
}

// remoteCommand judges the command ssh runs on the remote host: it is run
// there, but destroying data remotely is still destroying data.
func (a *shellAnalyzer) remoteCommand(rest []arg) {
	valueOpts := "BbcDEeFIiJLlmOoPpQRSWw"
	i := 0
	for ; i < len(rest); i++ {
		t := rest[i].text
		if t == "--" {
			i++
			break
		}
		if !isShortCluster(t) {
			break
		}
		if last := t[len(t)-1]; len(t) == 2 && strings.IndexByte(valueOpts, last) >= 0 {
			i++ // -p 22, -i key, -o Opt=x
		}
	}
	if i+1 >= len(rest) {
		return // host only: an interactive session
	}
	code, ok := joinLiteral(rest[i+1:])
	if !ok {
		a.f.opaque("ssh runs a remote command built at run time")
		return
	}
	a.f.merge(shellDepth(code, a.depth+1, a.opts))
}

// awk can run shell commands: system("..."), print | "cmd", "cmd" | getline.
func (a *shellAnalyzer) awk(rest []arg) {
	var program string
	for i := 0; i < len(rest); i++ {
		t := rest[i].text
		switch {
		case t == "-f" || t == "--file":
			a.f.opaque("awk runs a program from a file")
			return
		case t == "-v" || t == "-F" || t == "--assign" || t == "--field-separator":
			i++
		case strings.HasPrefix(t, "-"):
		default:
			if !rest[i].lit {
				a.f.opaque("awk program built at run time")
				return
			}
			program = t
			i = len(rest)
		}
	}
	if !strings.Contains(program, "system") && !strings.Contains(program, "|") {
		return
	}
	if awkSystemComputed.MatchString(program) {
		a.f.opaque("awk runs a shell command built at run time")
	}
	ran := false
	for _, s := range stringLiterals(program) {
		if strings.Contains(s, " ") {
			a.f.merge(shellDepth(s, a.depth+1, a.opts))
			ran = true
		}
	}
	if !ran {
		a.f.opaque("awk runs a shell command")
	}
}

var awkSystemComputed = regexp.MustCompile(`system\s*\(\s*[^"'\s]`)

// sedExec: GNU sed's e command and s///e flag run shell commands.
func (a *shellAnalyzer) sedExec(rest []arg) {
	var scripts []string
	for i := 0; i < len(rest); i++ {
		t := rest[i].text
		switch {
		case t == "-e" || t == "--expression":
			if i+1 < len(rest) {
				scripts = append(scripts, rest[i+1].text)
				i++
			}
		case t == "-f" || t == "--file":
			a.f.opaque("sed runs a script from a file")
			return
		case strings.HasPrefix(t, "-"):
		default:
			if len(scripts) == 0 {
				scripts = append(scripts, t)
			}
			i = len(rest)
		}
	}
	for _, s := range scripts {
		if m := sedECommand.FindStringSubmatch(s); m != nil {
			a.f.opaque("sed executes a shell command (e)")
			if strings.TrimSpace(m[2]) != "" {
				a.f.merge(shellDepth(m[2], a.depth+1, a.opts))
			}
		}
		if sedSubstituteExec(s) {
			a.f.opaque("sed executes the pattern space as a command (s///e)")
		}
	}
}

var sedECommand = regexp.MustCompile(`(^|[;\n{}]|^\s*\d+|/)\s*e(\s+([^;\n}]*))?($|[;\n}])`)

// sedSubstituteExec reports an s command with the e flag (s/x/cmd/e): it
// splits each s command on its own delimiter, honouring backslashes, and
// reads only its flags.
func sedSubstituteExec(script string) bool {
	for i := 0; i < len(script); i++ {
		if script[i] != 's' || i+1 >= len(script) {
			continue
		}
		if i > 0 && (isWordByte(script[i-1])) {
			continue // part of a word, not a command
		}
		delim := script[i+1]
		if delim == '\\' || delim == '\n' || delim == ' ' || isWordByte(delim) {
			continue
		}
		j, parts := i+2, 0
		for j < len(script) && parts < 2 {
			switch script[j] {
			case '\\':
				j++
			case delim:
				parts++
			}
			j++
		}
		if parts < 2 {
			return false
		}
		for j < len(script) && strings.IndexByte(";}\n ", script[j]) < 0 {
			if script[j] == 'e' {
				return true
			}
			if strings.IndexByte("gpiImM0123456789w", script[j]) < 0 {
				break
			}
			if script[j] == 'w' {
				break // w FILE: the rest is a file name
			}
			j++
		}
		i = j
	}
	return false
}

func isWordByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// dangerousVerbs can destroy data depending on their flags and operands.
var dangerousVerbs = set("rm", "rmdir", "shred", "unlink", "chmod", "chown", "chgrp", "dd", "truncate", "wipefs", "find", "rimraf")

// gitRewriting are the git subcommands whose flags decide whether history
// or work is destroyed.
var gitRewriting = set("push", "reset", "clean", "branch", "checkout", "restore", "stash", "rebase", "filter-branch", "filter-repo", "update-ref", "reflog")

// verbTools decide destructiveness by a verb word (kubectl delete, docker
// volume rm, terraform destroy, aws ... terminate-instances).
var verbTools = set("kubectl", "oc", "docker", "podman", "terraform", "tofu", "aws", "gcloud", "az", "helm", "redis-cli", "rsync", "git")

func computedArgsMatter(name string, rest []arg) bool {
	if dangerousVerbs[name] || strings.HasPrefix(name, "mkfs") {
		return true
	}
	if verbTools[name] {
		// A computed word at or before the verb hides which verb runs
		// (git $(echo push) --force, docker $(echo volume) rm x); computed
		// operands after a known verb (an image tag, a file) do not.
		for _, x := range rest {
			if !x.lit {
				return true
			}
			if !strings.HasPrefix(x.text, "-") {
				break // the first positional word, literal
			}
		}
		if name == "git" {
			return gitRewriting[gitSubcommand(texts(rest))]
		}
	}
	return false
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
	// An argv list (subprocess.run(['rm','-rf','/x']), spawn("rm",
	// ["-rf", ...])) is a command too: join it and judge it as shell.
	if depth <= maxDepth {
		for _, m := range argvList.FindAllString(code, 8) {
			words := stringLiterals(m)
			if len(words) >= 2 {
				f.merge(shellDepth(shellJoin(words), depth+1, o))
			}
		}
	}
	for _, s := range stringLiterals(code) {
		if IsSecretPath(s) {
			f.secretPath(s, "inline code opens secret file "+s)
		}
		if IsControlPath(s) {
			f.selfTamper("inline code names actiongate control file " + s)
		}
		if strings.Contains(s, " ") && depth <= maxDepth {
			inner := shellDepth(s, depth+1, o)
			if inner.Destructive {
				f.destructive("inline code runs a destructive shell command")
			}
			if inner.SecretAccess {
				f.secret("inline code runs a shell command that reads secrets")
			}
			if inner.SelfSecret {
				f.SelfSecret = true
				f.add("inline code runs a shell command that reads actiongate's own secrets")
			}
			if inner.SelfTamper {
				f.selfTamper("inline code runs a shell command that modifies actiongate control files")
			}
		}
	}
	return f
}

// argvList is a bracketed list of at least two string literals.
var argvList = regexp.MustCompile(`[\[(]\s*(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')(?:\s*,\s*(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'))+\s*,?\s*[\])]`)

// shellJoin renders argv as one shell command line, single-quoting words
// that need it, so the shell parser sees the same words.
func shellJoin(words []string) string {
	out := make([]string, len(words))
	for i, w := range words {
		if w != "" && !strings.ContainsAny(w, " \t\n'\"\\$`;&|<>(){}*?[]#~!") {
			out[i] = w
			continue
		}
		out[i] = "'" + strings.ReplaceAll(w, "'", `'\''`) + "'"
	}
	return strings.Join(out, " ")
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
		"sudo": set("-u", "-g", "-p", "-C", "-D", "-h", "-r", "-t", "-U", "-R",
			"--user", "--group", "--prompt", "--close-from", "--chdir", "--host", "--role", "--type", "--other-user", "--chroot"),
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
			"stdbuf", "xargs", "timeout", "npx", "pnpx", "bunx", "unbuffer", "chronic",
			"busybox", "toybox", "ionice", "chrt", "taskset", "setsid", "flock", "caffeinate":
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
			case isLongPrefix(t, "--force") || isLongPrefix(t, "--mirror") || isLongPrefix(t, "--delete") ||
				isLongPrefix(t, "--force-with-lease") || isLongPrefix(t, "--force-if-includes"):
				return "git push rewrites or deletes remote history" // --forc, --del, ... too
			case isShortCluster(t) && strings.ContainsAny(t, "fd"):
				return "git push rewrites or deletes remote history"
			case strings.HasPrefix(t, "+"):
				return "git push with a forced refspec"
			case strings.HasPrefix(t, ":") && len(t) > 1:
				return "git push deletes a remote branch"
			}
		}
	case "reset":
		for _, t := range rest {
			if isLongPrefix(t, "--hard") {
				return "git reset --hard discards work"
			}
		}
	case "clean":
		for _, t := range rest {
			if isLongPrefix(t, "--force") || isShortCluster(t) && strings.Contains(t, "f") {
				return "git clean deletes untracked files"
			}
		}
	case "branch":
		del, force := false, false
		for _, t := range rest {
			del = del || isLongPrefix(t, "--delete") || isShortCluster(t) && strings.Contains(t, "d")
			force = force || isLongPrefix(t, "--force") || isShortCluster(t) && strings.Contains(t, "f")
			if t == "-D" || isShortCluster(t) && strings.Contains(t, "D") {
				return "git branch -D deletes unmerged work"
			}
		}
		if del && force {
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
			if p.Dollar {
				// $'\x72\x6d' is "rm": decode it the way bash does, so the
				// analyzer judges the word that actually runs.
				b.WriteString(decodeANSIC(p.Value))
			} else {
				b.WriteString(p.Value)
			}
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

// decodeANSIC decodes the body of a bash $'...' string: \a \b \e \f \n \r
// \t \v \\ \' \" \?, \xHH, \uHHHH, \UHHHHHHHH, \NNN (octal) and \cX. Like
// bash, it ends the string at the first NUL it produces ($'rm\x00x' is rm).
func decodeANSIC(s string) string {
	out := decodeANSICAll(s)
	if i := strings.IndexByte(out, 0); i >= 0 {
		return out[:i]
	}
	return out
}

func decodeANSICAll(s string) string {
	var b strings.Builder
	hexVal := func(h string) (int, bool) {
		n := 0
		for _, c := range h {
			switch {
			case c >= '0' && c <= '9':
				n = n*16 + int(c-'0')
			case c >= 'a' && c <= 'f':
				n = n*16 + int(c-'a') + 10
			case c >= 'A' && c <= 'F':
				n = n*16 + int(c-'A') + 10
			default:
				return 0, false
			}
		}
		return n, true
	}
	isHex := func(c byte) bool {
		return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch c := s[i]; c {
		case 'a':
			b.WriteByte(7)
		case 'b':
			b.WriteByte(8)
		case 'e', 'E':
			b.WriteByte(27)
		case 'f':
			b.WriteByte(12)
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'v':
			b.WriteByte(11)
		case '\\', '\'', '"', '?':
			b.WriteByte(c)
		case 'x', 'u', 'U':
			maxDigits := map[byte]int{'x': 2, 'u': 4, 'U': 8}[c]
			j := i + 1
			for j < len(s) && j-i-1 < maxDigits && isHex(s[j]) {
				j++
			}
			if n, ok := hexVal(s[i+1 : j]); ok && j > i+1 {
				if c == 'x' {
					b.WriteByte(byte(n))
				} else {
					b.WriteRune(rune(n))
				}
				i = j - 1
			} else {
				b.WriteByte('\\')
				b.WriteByte(c)
			}
		case 'c':
			if i+1 < len(s) {
				b.WriteByte(s[i+1] & 0x1f)
				i++
			}
		default:
			if c >= '0' && c <= '7' {
				n, j := 0, i
				for j < len(s) && j-i < 3 && s[j] >= '0' && s[j] <= '7' {
					n = n*8 + int(s[j]-'0')
					j++
				}
				b.WriteByte(byte(n))
				i = j - 1
			} else {
				b.WriteByte('\\')
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}

// isLongPrefix reports whether t (before any "=value") is an abbreviation
// of the long option full that GNU getopt and git would accept — any
// prefix with at least one character after "--" (rm --r is --recursive).
// An ambiguous abbreviation errors out in the tool itself, so treating it
// as the dangerous option only fails closed.
func isLongPrefix(t, full string) bool {
	name, _, _ := strings.Cut(t, "=")
	return strings.HasPrefix(name, "--") && len(name) >= 3 && strings.HasPrefix(full, name)
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
		if x.text == long || isLongPrefix(x.text, long) {
			return true // --rec is --recursive
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
