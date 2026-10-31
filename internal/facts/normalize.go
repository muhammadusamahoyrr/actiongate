package facts

import (
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// Normalize renders a bash command line the way the analyzer sees it, as
// plain text: every word is replaced by its static value (quotes and escapes
// removed, braces expanded, variables assigned a static value earlier in the
// line substituted), wrapper commands are stripped, and the code inside
// bash -c, sh -c and eval of literals is appended in normalized form.
//
// It exists for the normalize-then-regex evaluation baseline (cmd/agbench),
// which separates what normalization contributes from what per-tool
// semantics contribute. Policies use Shell, not this function. Input that
// does not parse is returned unchanged.
func Normalize(cmd string) string { return normalizeDepth(cmd, 0) }

func normalizeDepth(cmd string, depth int) string {
	if depth > maxDepth {
		return cmd
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(cmd), "")
	if err != nil {
		return cmd
	}
	n := &normalizer{a: &shellAnalyzer{depth: depth, stdin: map[*syntax.Stmt]stdinSource{}, vars: map[string]string{}}, depth: depth}
	var parts []string
	for _, st := range file.Stmts {
		if s := n.stmt(st); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(append(parts, n.nested...), "; ")
}

type normalizer struct {
	a      *shellAnalyzer
	depth  int
	nested []string
}

func (n *normalizer) stmt(st *syntax.Stmt) string {
	var out string
	switch c := st.Cmd.(type) {
	case *syntax.CallExpr:
		if len(c.Args) == 0 {
			n.a.assign(c.Assigns)
			return ""
		}
		out = n.call(c)
	case *syntax.DeclClause:
		n.a.assign(c.Args)
		return ""
	case *syntax.BinaryCmd:
		return n.stmt(c.X) + " " + c.Op.String() + " " + n.stmt(c.Y)
	default:
		// Blocks, loops and conditionals are printed as written.
		var b strings.Builder
		_ = syntax.NewPrinter(syntax.SingleLine(true)).Print(&b, st)
		return b.String()
	}
	for _, r := range st.Redirs {
		switch {
		case r.Hdoc != nil:
			out += " " + r.Op.String() + " " + n.a.approx(r.Hdoc)
		case r.Word != nil:
			out += " " + r.Op.String() + " " + n.a.approx(r.Word)
		}
	}
	return strings.ReplaceAll(out, "\x00", "$VAR")
}

func (n *normalizer) call(c *syntax.CallExpr) string {
	var args []arg
	for _, w := range c.Args {
		cw := &syntax.Word{Parts: append([]syntax.WordPart(nil), w.Parts...)}
		syntax.SplitBraces(cw)
		for _, bw := range expand.Braces(cw) {
			s, ok := n.a.literal(bw)
			if !ok {
				s = n.a.approx(bw)
			}
			args = append(args, arg{text: s, lit: ok})
		}
	}
	args = unwrap(args)
	if len(args) == 0 {
		return ""
	}
	name := cmdName(args[0].text)
	rest := args[1:]
	switch {
	case shells[name]:
		for i, x := range rest {
			if (x.text == "-c" || isShortCluster(x.text) && strings.Contains(x.text, "c")) && i+1 < len(rest) && rest[i+1].lit {
				n.nested = append(n.nested, normalizeDepth(rest[i+1].text, n.depth+1))
				break
			}
		}
	case name == "eval":
		if code, ok := joinLiteral(rest); ok {
			n.nested = append(n.nested, normalizeDepth(code, n.depth+1))
		}
	}
	return strings.Join(texts(args), " ")
}
