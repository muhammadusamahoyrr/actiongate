// Package facts derives structured, policy-relevant facts from a raw tool
// call so CEL rules can ask "is this destructive?" instead of searching the
// command text for "rm -rf". Text matching is trivially evaded (rm -fr,
// rm -r -f, 'r”m', bash -c '...'); facts are computed from a parse of the
// command, so every spelling of the same operation produces the same facts.
//
// The analysis is static and deliberately conservative in one direction:
// anything it cannot see through (eval of a variable, a pipe into a shell,
// a command name built at runtime, unparseable input) is reported as opaque
// rather than as safe, so a policy can route it to a human. Derive is pure:
// no I/O, no clock, no environment lookups.
package facts

import (
	"path"
	"sort"
	"strings"
)

// Facts is what a policy may know about an action beyond its raw params.
type Facts struct {
	// Destructive: the action irreversibly deletes data in bulk or rewrites
	// shared history (recursive delete, force push, DROP TABLE, mkfs, ...).
	Destructive bool
	// SecretAccess: the action reads, copies or sends credential material
	// (.env, private keys, cloud credentials) or edits it with a file tool.
	SecretAccess bool
	// Opaque: the action runs code the analyzer cannot inspect statically.
	Opaque bool
	// InlineDynamic: inline interpreter code (python -c, node -e, a
	// here-doc) builds strings or names at run time (concatenation,
	// getattr, __import__, join, chr), which pattern inspection cannot
	// see through. Kept apart from Opaque so a pack can choose the trade-off.
	InlineDynamic bool
	// SelfTamper: the action writes, moves or deletes a file actiongate's
	// own enforcement depends on (the Claude Code hook settings, ag-hook,
	// gateway state, dev.json). See tamper.go.
	SelfTamper bool
	// SelfSecret: the action reads actiongate's OWN secrets — anything in its
	// per-user config directory (dev.json: DB password and signing seeds;
	// gateway.json: the gateway credential and key; pgdata: the database
	// files). Implies SecretAccess. The policy engine denies it before any
	// pack rule runs (see internal/policy), so no pack can allow it.
	SelfSecret bool
	// Reasons explains each fact that is true, for the audit trail.
	Reasons []string
}

// Keys lists every fact name a rule may use as facts.<name>. Policies are
// validated against it at compile time (internal/policy), so a typo or a
// fact this build does not know is rejected instead of failing every
// evaluation.
func Keys() []string {
	m := Facts{}.Map()
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Map is the CEL-facing form. Every key is always present, so rules can read
// facts.destructive without a has() guard. Reasons stay out of CEL: they
// explain a decision, they are not an input to it.
func (f Facts) Map() map[string]bool {
	return map[string]bool{
		"destructive":    f.Destructive,
		"secret_access":  f.SecretAccess,
		"opaque":         f.Opaque,
		"inline_dynamic": f.InlineDynamic,
		"self_tamper":    f.SelfTamper,
		"self_secret":    f.SelfSecret,
	}
}

func (f *Facts) destructive(reason string) {
	f.Destructive = true
	f.add(reason)
}

func (f *Facts) secret(reason string) {
	f.SecretAccess = true
	f.add(reason)
}

// secretPath is secret for a detector that resolved the path it flagged:
// when that path is actiongate's own, it also sets SelfSecret — decided on
// the analyzer's resolved path, never by re-reading the raw text.
func (f *Facts) secretPath(p, reason string) {
	f.secret(reason)
	if IsActiongateSecretPath(p) {
		f.SelfSecret = true
		f.add("reads actiongate's own secrets (its config directory)")
	}
}

func (f *Facts) opaque(reason string) {
	f.Opaque = true
	f.add(reason)
}

func (f *Facts) inlineDynamic(reason string) {
	f.InlineDynamic = true
	f.add(reason)
}

func (f *Facts) add(reason string) {
	for _, r := range f.Reasons {
		if r == reason {
			return
		}
	}
	f.Reasons = append(f.Reasons, reason)
}

func (f *Facts) merge(o Facts) {
	f.Destructive = f.Destructive || o.Destructive
	f.SecretAccess = f.SecretAccess || o.SecretAccess
	f.Opaque = f.Opaque || o.Opaque
	f.InlineDynamic = f.InlineDynamic || o.InlineDynamic
	f.SelfTamper = f.SelfTamper || o.SelfTamper
	f.SelfSecret = f.SelfSecret || o.SelfSecret
	for _, r := range o.Reasons {
		f.add(r)
	}
}

// Derive computes facts for one tool call. Tools it does not know produce
// empty facts, so unrelated tools are never affected by fact-based rules.
//
// A panic inside the analysis (a parser edge case) never escapes: it yields
// opaque, so the action goes to a human instead of crashing the control plane.
func Derive(tool string, params map[string]any) Facts { return DeriveWith(tool, params, Options{}) }

// Options switch parts of the Bash analysis off, for ablation studies, or on,
// for refinements under evaluation. The zero value is the shipped analyzer;
// PowerShell and file tools ignore them.
type Options struct {
	// Tokenize replaces the syntax tree with quote-aware tokenization:
	// commands are split at ;, &&, ||, | and &, words at white space, quotes
	// are removed, and nothing is expanded or re-parsed. The per-command
	// semantics stay the same.
	Tokenize bool
	// TokenizePlus is Tokenize plus here-document bodies handed to the
	// command that reads them and static variable substitution: the two
	// capabilities the full analyzer gained from real traffic, without an AST.
	TokenizePlus bool
	// NoReaders drops the read-versus-mention distinction: any argument
	// naming a credential file counts as secret access.
	NoReaders bool
	// NoVarResolve stops substituting variables assigned a static value.
	NoVarResolve bool
	// ExemptRegenerable stops treating a recursive rm as destructive when
	// every target is a conventionally regenerable path (build outputs,
	// dependency and cache directories, temporary directories).
	ExemptRegenerable bool
}

// DeriveWith is Derive with analysis options.
func DeriveWith(tool string, params map[string]any, o Options) (f Facts) {
	defer func() {
		if r := recover(); r != nil {
			f = Facts{Opaque: true, Reasons: []string{"analyzer failed on this input"}}
		}
	}()
	str := func(k string) string {
		s, _ := params[k].(string)
		return s
	}
	switch tool {
	case "Bash", "bash":
		f = ShellWith(str("command"), o)
	case "PowerShell":
		f = PowerShell(str("command"))
	case "Read", "Edit", "MultiEdit", "Write", "NotebookEdit":
		p := str("file_path")
		if p == "" {
			p = str("notebook_path")
		}
		if IsSecretPath(p) {
			f.secretPath(p, "file tool on secret path "+path.Base(slash(p)))
		}
		if tool != "Read" && IsControlPath(p) {
			f.selfTamper(tool + " on actiongate control file " + path.Base(slash(p)))
		}
	case "read_file":
		if p := str("path"); IsSecretPath(p) {
			f.secretPath(p, "file tool on secret path "+path.Base(slash(p)))
		}
	case "Grep":
		if p := str("path"); IsSecretPath(p) {
			f.secretPath(p, "grep inside secret path "+path.Base(slash(p)))
		}
		if g := str("glob"); g != "" && globMatchesSecret(g) {
			f.secret("grep glob covers secret files: " + g)
		}
	case "Glob", "LS", "WebFetch", "WebSearch", "TodoWrite":
		// Read-only, or no file operand.
	default:
		// A tool we do not know (a new built-in, an MCP write_file, ...):
		// assume it may write any path it is given, under any key and at
		// any depth (edits: [{path: ...}]).
		if p, ok := findString(params, 0, func(s string) bool { return IsControlPath(s) || IsControlDir(s) }); ok {
			f.selfTamper(tool + " on actiongate control path " + path.Base(slash(p)))
		}
		// ...and may read any path it is given.
		if p, ok := findString(params, 0, IsActiongateSecretPath); ok {
			f.secretPath(p, tool+" on actiongate secret path "+path.Base(slash(p)))
		}
	}
	// The detectors set SelfSecret from the path they resolved. As a
	// second, fail-closed net: a secret access whose raw text also names
	// actiongate's config directory counts too (it can only add a deny).
	// Scripts the command runs, attached by the gateway (write-then-run,
	// audit H2): judged as if their text had been typed inline.
	if _, ok := params[ScriptsKey]; ok {
		f.merge(deriveScripts(params, o))
	}
	if f.SecretAccess && mentionsActiongateSecret(params) {
		f.SelfSecret = true
		f.add("reads actiongate's own secrets (its config directory)")
	}
	return f
}

// findString returns the first string anywhere in v (maps, slices, nested)
// that match accepts. Depth is bounded so a hostile payload cannot recurse
// without end, and nesting past the bound counts as a match (fail closed):
// otherwise burying a path one level deeper would hide it.
func findString(v any, depth int, match func(string) bool) (string, bool) {
	if depth > 8 {
		return "(nested too deeply to inspect)", true
	}
	switch x := v.(type) {
	case string:
		return x, match(x)
	case map[string]any:
		for _, e := range x {
			if s, ok := findString(e, depth+1, match); ok {
				return s, true
			}
		}
	case []any:
		for _, e := range x {
			if s, ok := findString(e, depth+1, match); ok {
				return s, true
			}
		}
	}
	return "", false
}

// secretNames are probes for glob arguments: a pattern that would match any
// of them is treated as touching secrets.
var secretNames = []string{".env", ".env.local", ".env.production", "id_rsa", "id_ed25519", "server.pem", "server.key", "credentials", ".netrc"}

var templateSuffixes = []string{".example", ".sample", ".template", ".dist", ".defaults", ".schema"}

// IsSecretPath reports whether a path names credential material. Templates
// (.env.example) and public keys (*.pub) are not secrets.
func IsSecretPath(p string) bool {
	p = strings.Trim(strings.TrimSpace(p), `"'`)
	if p == "" {
		return false
	}
	if IsActiongateSecretPath(p) {
		return true
	}
	p = strings.ToLower(slash(p))
	base := path.Base(p)
	if strings.HasSuffix(base, ".pub") {
		return false
	}
	for _, s := range templateSuffixes {
		if strings.HasSuffix(base, s) {
			return false
		}
	}
	switch base {
	case ".env", ".netrc", ".pgpass", ".git-credentials", ".npmrc", ".pypirc",
		"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials", "credentials.json":
		return true
	}
	if strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env") {
		return true
	}
	switch path.Ext(base) {
	case ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore":
		return true
	}
	if strings.Contains("/"+p, "/.ssh/") && base != "known_hosts" && base != "config" && base != ".ssh" {
		return true
	}
	return false
}

// globMatchesSecret reports whether a glob names secret files. A negated
// glob (!**/node_modules/**) excludes files, and a pattern with fewer than
// three literal characters (*, s*) is a directory sweep, not a target.
// isSecretDir reports a directory that holds only credential material, so
// archiving or copying it whole is a secret read (tar czf - ~/.ssh).
func isSecretDir(p string) bool {
	p = strings.TrimRight(strings.ToLower(slash(strings.Trim(p, `"'`))), "/")
	switch path.Base(p) {
	case ".ssh", ".aws", ".gnupg", ".kube", ".docker":
		return true
	}
	return false
}

func globMatchesSecret(pattern string) bool {
	if strings.HasPrefix(pattern, "!") {
		return false
	}
	base := path.Base(slash(pattern))
	literals := 0
	for _, r := range base {
		if !strings.ContainsRune("*?[]{}", r) {
			literals++
		}
	}
	if literals < 3 {
		return false
	}
	for _, name := range secretNames {
		// Shell globs never match a leading dot unless the pattern has one.
		if strings.HasPrefix(name, ".") && !strings.HasPrefix(base, ".") {
			continue
		}
		if ok, _ := path.Match(base, name); ok {
			return true
		}
	}
	return false
}

func slash(p string) string { return strings.ReplaceAll(p, `\`, "/") }
