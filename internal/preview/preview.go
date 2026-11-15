// Package preview renders an action for the human asked to approve it
// (audit H6): the approval card used to say only "Approval needed: Bash by
// claude-code" and the rule id, so `rm -rf node_modules` and `rm -rf ~`
// looked identical. A preview shows what will run — with credentials
// masked and the length bounded — and why the analyzer flagged it.
package preview

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// MaxCommand bounds the command text shown; longer commands are cut with
// a note, never silently.
const MaxCommand = 600

// Action is the human-readable summary of a tool call.
func Action(tool string, params map[string]any) string {
	str := func(k string) string {
		s, _ := params[k].(string)
		return s
	}
	switch tool {
	case "Bash", "bash", "PowerShell":
		return Mask(truncate(str("command"), MaxCommand))
	case "Read", "Edit", "MultiEdit", "Write", "NotebookEdit":
		p := str("file_path")
		if p == "" {
			p = str("notebook_path")
		}
		// Paths are shown as written, never masked: the approver must see
		// exactly which file.
		if tool == "Write" {
			return fmt.Sprintf("%s %s (%d bytes)", tool, p, len(str("content")))
		}
		return fmt.Sprintf("%s %s", tool, p)
	}
	// Anything else: its parameters, masked and bounded, keys sorted so
	// the preview is stable.
	keys := make([]string, 0, len(params))
	for k := range params {
		if !strings.HasPrefix(k, "_actiongate") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		v, err := json.Marshal(params[k])
		if err != nil {
			continue
		}
		fmt.Fprintf(&b, "%s=%s ", k, v)
	}
	return Mask(truncate(strings.TrimSpace(b.String()), MaxCommand))
}

// Body is the approval message body: what runs, where the rule landed, and
// the analyzer's reasons.
func Body(tool, agent, rule, risk string, params map[string]any, reasons []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "*%s* by *%s* · rule `%s` (%s)\n", inline(tool), inline(agent), inline(rule), inline(risk))
	if a := Action(tool, params); a != "" {
		fmt.Fprintf(&b, "```\n%s\n```\n", fence(a))
	}
	// Reasons quote the command (file names, …), so they stay inside a code
	// block too: nothing agent-written is rendered as markup.
	if len(reasons) > 0 {
		b.WriteString("Why:\n```\n")
		for i, r := range reasons {
			if i == 5 {
				fmt.Fprintf(&b, "… and %d more\n", len(reasons)-5)
				break
			}
			b.WriteString("- " + fence(Mask(r)) + "\n")
		}
		b.WriteString("```\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// inline makes a value safe for one line of markup: no newlines, no
// emphasis or code markers.
func inline(s string) string {
	return strings.NewReplacer("\n", " ", "\r", " ", "*", "", "_", "-", "`", "'", "~", "-").Replace(s)
}

// fence keeps text from closing the code block it sits in.
func fence(s string) string { return strings.ReplaceAll(s, "```", "'''") }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + fmt.Sprintf(" … [%d more bytes not shown]", len(s)-cut)
}

var maskers = []struct {
	re   *regexp.Regexp
	repl string
}{
	// Every pattern masks only PLAIN LITERAL values: no $, backtick, ;, |,
	// &, <, >, ( or ), so masking can never hide something that executes
	// (TOKEN="$(rm -rf ~)" is shown as written). Masked spans are marked.
	//
	// Authorization schemes first ("Authorization: Bearer x" — the key=value
	// rule below would otherwise mask the word Bearer and leave x).
	{regexp.MustCompile(`(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{8,}`), "$1 " + masked},
	// key=value / key: value for credential-like keys: a single-quoted
	// value (literal in every shell), a double-quoted one without
	// expansions, or a bare one without metacharacters.
	// The value — bare or quoted — must consist ONLY of token characters:
	// no spaces, quotes, $, backslashes or other metacharacters inside, so
	// a regex over raw text can never disagree with the shell about where
	// the value ends. Anything else is shown as written.
	{regexp.MustCompile(`(?i)\b([A-Za-z0-9_]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth|credential)[A-Za-z0-9_]*)(\s*[=:]\s*)('[A-Za-z0-9._~+/=@%:!,-]+'|"[A-Za-z0-9._~+/=@%:!,-]+"|[A-Za-z0-9._~+/=@%:!,-]+)(?:[\s;&|)]|$)`), "$1$2" + masked + " "},
	// Credentials in URLs.
	{regexp.MustCompile(`(://[A-Za-z0-9._~%-]+):[A-Za-z0-9._~%!*'+=,-]+@`), "$1:" + masked + "@"},
	// Well-known token shapes.
	{regexp.MustCompile(`\b(sk-[A-Za-z0-9_-]{8,}|sk_live_[A-Za-z0-9]{8,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|agt1_[A-Za-z0-9_.-]+|agc_[A-Za-z0-9_-]+|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`), masked},
}

// masked marks a hidden credential so the approver knows text was removed.
const masked = "[credential hidden]"

// Mask hides credential-shaped substrings. It is a best effort for display
// only; the policy decision never depends on it.
func Mask(s string) string {
	for _, m := range maskers {
		s = m.re.ReplaceAllString(s, m.repl)
	}
	return s
}
