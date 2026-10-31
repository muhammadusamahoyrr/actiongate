// agbench evaluates policy packs against ActionGate-Bench (bench/actions.jsonl)
// and, optionally, against real agent traffic taken from Claude Code
// transcripts. It drives the same policy.Engine the control plane uses, so the
// numbers describe the shipped decision logic, not a re-implementation. No
// database, network or clock-dependent state is involved.
//
//	agbench [-data bench/actions.jsonl] [-packs v1=bench/baseline/claude-code-v1.json,claude-code]
//	        [-transcripts ~/.claude/projects] [-misses] [-out results.md]
//
// A pack is either the name of an embedded starter pack or NAME=PATH to a
// JSON policy file; NAME=norm:PATH evaluates that file on commands rewritten
// by facts.Normalize (the normalize-then-regex baseline), and
// NAME=with:tok+noreaders+novars+exempt:PATH evaluates it with facts derived
// by an analyzer variant (see facts.Options). Labelled actions report detection and false positives;
// transcript actions are unlabelled and report only how often each pack would
// interrupt the agent (friction).
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/muhammadusamahoyrr/actiongate/internal/facts"
	"github.com/muhammadusamahoyrr/actiongate/internal/policy"
	"github.com/muhammadusamahoyrr/actiongate/policies"
)

type action struct {
	ID        string         `json:"id"`
	Category  string         `json:"category"`
	Technique string         `json:"technique"`
	Tool      string         `json:"tool"`
	Params    map[string]any `json:"params"`
	Expect    string         `json:"expect"`
}

type pack struct {
	name     string
	snapshot *policy.CompiledSnapshot
	// normalize: shell commands are rewritten by facts.Normalize before the
	// rules see them (the normalize-then-regex baseline). Spec: NAME=norm:PATH.
	normalize bool
	// opts: facts are derived with these analyzer options instead of the
	// shipped analyzer. Spec: NAME=with:tok+noreaders+novars+exempt:PATH.
	opts    facts.Options
	useOpts bool
}

// outcome is one pack's verdict on one action. An evaluation error is
// recorded as deny: the orchestrator fails closed on errors.
type outcome struct {
	decision string
	rule     string
	err      error
}

// governedTools are the transcript tools a policy can meaningfully act on;
// anything else (TodoWrite, Agent, ...) would only dilute the friction rate.
var governedTools = map[string]bool{
	"Bash": true, "PowerShell": true, "Read": true, "Edit": true,
	"Write": true, "NotebookEdit": true, "Grep": true,
}

func main() {
	data := flag.String("data", "bench/actions.jsonl", "labelled benchmark (JSONL)")
	packSpec := flag.String("packs", "v1=bench/baseline/claude-code-v1.json,claude-code,relaxed,paranoid", "comma-separated packs: embedded name or NAME=PATH")
	transcripts := flag.String("transcripts", "", "optional directory of Claude Code *.jsonl transcripts for the friction measurement")
	codex := flag.String("codex", "", "optional directory of OpenAI Codex CLI session logs (~/.codex/sessions) for the friction measurement")
	misses := flag.Bool("misses", false, "list every action a pack got wrong")
	out := flag.String("out", "", "write the markdown report here instead of stdout")
	samples := flag.String("trace-samples", "", "print every transcript action this pack stops to stderr, for local review only")
	callsPath := flag.String("calls", "", "optional call records from public session exports (bench/tools/dataclaw_calls.py) for per-developer friction")
	maxLen := flag.Int("maxlen", 0, "with -calls: keep only shell commands shorter than this, from every export (0: keep complete calls)")
	minShell := flag.Int("min-shell", 50, "with -calls: leave out developers with fewer shell calls")
	compare := flag.String("compare", "", "with -calls: comma-separated A:B pairs for sign tests over developers")
	disagree := flag.String("disagree", "", "with -calls: A:B, sample calls stopped by only one of the two packs for a blind audit")
	disagreeN := flag.Int("disagree-n", 30, "with -disagree: items per side")
	disagreeOut := flag.String("disagree-out", "audit", "with -disagree: output prefix for PREFIX-items.jsonl and PREFIX-key.jsonl")
	seed := flag.Int64("seed", 20261031, "with -disagree: sampling seed")
	flag.Parse()

	engine, err := policy.NewEngine()
	check(err)
	packs, err := loadPacks(engine, *packSpec)
	check(err)
	actions, err := loadActions(*data)
	check(err)

	dst := os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		check(err)
		dst = f
	}
	w := &report{bufio.NewWriter(dst)}
	defer func() {
		check(w.Flush())
		check(dst.Close())
	}()

	results := make([][]outcome, len(packs))
	for i, p := range packs {
		results[i] = make([]outcome, len(actions))
		for j, a := range actions {
			results[i][j] = p.evaluate(a.Tool, a.Params)
		}
	}

	if *codex != "" {
		traffic, err := loadCodex(*codex)
		check(err)
		defer writeFriction(w, packs, traffic, "Codex CLI session logs")
	}
	w.printf("# ActionGate-Bench results\n\n%d labelled actions (`%s`).\n\n", len(actions), *data)
	writeSummary(w, packs, actions, results)
	writeCategories(w, packs, actions, results)
	if *transcripts != "" {
		traffic, err := loadTranscripts(*transcripts)
		check(err)
		writeFriction(w, packs, traffic, "Claude Code transcripts")
		for _, p := range packs {
			if p.name != *samples {
				continue
			}
			for _, a := range traffic {
				if o := p.evaluate(a.Tool, a.Params); stopped(o) {
					fmt.Fprintf(os.Stderr, "%s\t%s\t%s\t%s\n", o.decision, o.rule, a.Tool, describe(a.Params))
				}
			}
		}
	}
	if *callsPath != "" {
		calls, err := loadCalls(*callsPath, *maxLen)
		check(err)
		res := writeDevelopers(w, packs, calls, *minShell, *compare)
		writeReasons(w, calls, *minShell)
		if *disagree != "" {
			check(writeDisagreements(packs, calls, res, *disagree, *disagreeN, *seed, *disagreeOut))
		}
	}
	if *misses {
		writeMisses(w, packs, actions, results)
	}
}

// report buffers the markdown output. bufio.Writer keeps the first write
// error and returns it from Flush, so individual writes need no check.
type report struct{ *bufio.Writer }

func (r *report) printf(format string, a ...any) { _, _ = fmt.Fprintf(r, format, a...) }

func (r *report) println(a ...any) { _, _ = fmt.Fprintln(r, a...) }

func (p pack) evaluate(tool string, params map[string]any) outcome {
	if p.normalize && (tool == "Bash" || tool == "bash") {
		if c, ok := params["command"].(string); ok {
			cp := make(map[string]any, len(params))
			for k, v := range params {
				cp[k] = v
			}
			cp["command"] = facts.Normalize(c)
			params = cp
		}
	}
	if p.useOpts {
		d, err := p.snapshot.Evaluate(policy.Input{AgentID: "agbench", ToolName: tool, Environment: "dev", Params: params,
			Facts: facts.DeriveWith(tool, params, p.opts).Map()})
		if err != nil {
			return outcome{decision: string(policy.Deny), rule: "eval-error", err: err}
		}
		return outcome{decision: string(d.Decision), rule: d.MatchedRuleID}
	}
	return evaluate(p.snapshot, tool, params)
}

func evaluate(s *policy.CompiledSnapshot, tool string, params map[string]any) outcome {
	d, err := s.Evaluate(policy.Input{AgentID: "agbench", ToolName: tool, Environment: "dev", Params: params})
	if err != nil {
		return outcome{decision: string(policy.Deny), rule: "eval-error", err: err}
	}
	return outcome{decision: string(d.Decision), rule: d.MatchedRuleID}
}

func harmful(a action) bool { return a.Expect != string(policy.Allow) }

func stopped(o outcome) bool { return o.decision != string(policy.Allow) }

func writeSummary(w *report, packs []pack, actions []action, results [][]outcome) {
	w.println("## Summary")
	w.println()
	w.println("- **Recall**: harmful actions the pack stops (deny or approval).")
	w.println("- **False-positive rate**: benign actions the pack interrupts.")
	w.println("- **Exact**: decision equals the label (deny vs approval vs allow).")
	w.println()
	w.println("Latency is measured separately: `go test ./policies -run '^$' -bench PackOnHeldOutB`.")
	w.println()
	w.println("| Pack | Recall | False-positive rate | Exact | Eval errors |")
	w.println("|---|---|---|---|---|")
	for i, p := range packs {
		var nHarm, caught, nBenign, fp, exact, errs int
		for j, a := range actions {
			o := results[i][j]
			if o.err != nil {
				errs++
			}
			if o.decision == a.Expect {
				exact++
			}
			if harmful(a) {
				nHarm++
				if stopped(o) {
					caught++
				}
			} else {
				nBenign++
				if stopped(o) {
					fp++
				}
			}
		}
		w.printf("| %s | %s | %s | %s | %d |\n", p.name,
			ratio(caught, nHarm), ratio(fp, nBenign), ratio(exact, len(actions)), errs)
	}
	w.println()
}

func writeCategories(w *report, packs []pack, actions []action, results [][]outcome) {
	var cats []string
	seen := map[string]bool{}
	for _, a := range actions {
		if !seen[a.Category] {
			seen[a.Category] = true
			cats = append(cats, a.Category)
		}
	}
	w.println("## By category")
	w.println()
	w.println("Cells count actions stopped (deny or approval). For `benign` lower is better; for every other category higher is better.")
	w.println()
	header := "| Category | n |"
	sep := "|---|---|"
	for _, p := range packs {
		header += " " + p.name + " |"
		sep += "---|"
	}
	w.println(header)
	w.println(sep)
	for _, c := range cats {
		n := 0
		counts := make([]int, len(packs))
		for j, a := range actions {
			if a.Category != c {
				continue
			}
			n++
			for i := range packs {
				if stopped(results[i][j]) {
					counts[i]++
				}
			}
		}
		row := fmt.Sprintf("| %s | %d |", c, n)
		for _, k := range counts {
			row += " " + ratio(k, n) + " |"
		}
		w.println(row)
	}
	w.println()
}

func writeMisses(w *report, packs []pack, actions []action, results [][]outcome) {
	w.println("## Misses")
	for i, p := range packs {
		w.printf("\n### %s\n\n", p.name)
		any := false
		for j, a := range actions {
			o := results[i][j]
			if o.decision == a.Expect {
				continue
			}
			any = true
			w.printf("- `%s` %s %s: expected `%s`, got `%s` (rule `%s`)\n",
				a.ID, a.Tool, describe(a.Params), a.Expect, o.decision, o.rule)
		}
		if !any {
			w.println("None.")
		}
	}
}

// writeFriction reports only aggregates: transcripts are private, so no
// individual command is ever printed.
func writeFriction(w *report, packs []pack, traffic []action, source string) {
	w.printf("## Friction on real agent traffic (%s)\n", source)
	w.println()
	byTool := map[string]int{}
	for _, a := range traffic {
		byTool[a.Tool]++
	}
	tools := make([]string, 0, len(byTool))
	for t := range byTool {
		tools = append(tools, t)
	}
	sort.Strings(tools)
	parts := make([]string, 0, len(tools))
	for _, t := range tools {
		parts = append(parts, fmt.Sprintf("%s %d", t, byTool[t]))
	}
	w.printf("%d tool calls extracted from %s (%s). Unlabelled: the rate below is how often each pack would stop the agent, not an error rate.\n\n", len(traffic), source, strings.Join(parts, ", "))
	w.println("| Pack | Interrupted | Denied | Approval | Shell calls interrupted |")
	w.println("|---|---|---|---|---|")
	for _, p := range packs {
		var stop, deny, appr, shell, shellStop int
		for _, a := range traffic {
			o := p.evaluate(a.Tool, a.Params)
			isShell := a.Tool == "Bash" || a.Tool == "PowerShell"
			if isShell {
				shell++
			}
			if !stopped(o) {
				continue
			}
			stop++
			if isShell {
				shellStop++
			}
			if o.decision == string(policy.Deny) {
				deny++
			} else {
				appr++
			}
		}
		w.printf("| %s | %s | %d | %d | %s |\n", p.name, ratio(stop, len(traffic)), deny, appr, ratio(shellStop, shell))
	}
	w.println()
}

func ratio(k, n int) string {
	if n == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%d/%d (%.0f%%)", k, n, 100*float64(k)/float64(n))
}

func describe(params map[string]any) string {
	for _, k := range []string{"command", "file_path", "path"} {
		if v, ok := params[k].(string); ok {
			v = strings.NewReplacer("`", "'", "\n", " ⏎ ", "\t", " ").Replace(v)
			return "`" + v + "`"
		}
	}
	b, _ := json.Marshal(params)
	return "`" + string(b) + "`"
}

func loadPacks(engine *policy.Engine, spec string) ([]pack, error) {
	var packs []pack
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name, path, isFile := strings.Cut(item, "=")
		norm := false
		if p, ok := strings.CutPrefix(path, "norm:"); ok {
			path, norm = p, true
		}
		var opts facts.Options
		useOpts := false
		if rest, ok := strings.CutPrefix(path, "with:"); ok {
			list, p, found := strings.Cut(rest, ":")
			if !found {
				return nil, fmt.Errorf("pack %q: want with:OPTS:PATH", name)
			}
			path, useOpts = p, true
			for _, o := range strings.Split(list, "+") {
				switch o {
				case "tok":
					opts.Tokenize = true
				case "tokplus":
					opts.TokenizePlus = true
				case "noreaders":
					opts.NoReaders = true
				case "novars":
					opts.NoVarResolve = true
				case "exempt":
					opts.ExemptRegenerable = true
				case "":
				default:
					return nil, fmt.Errorf("pack %q: unknown option %q", name, o)
				}
			}
		}
		var raw []byte
		if isFile {
			b, err := os.ReadFile(path) //nolint:gosec // G304: reading the pack file the user named is the point
			if err != nil {
				return nil, err
			}
			raw = b
		} else {
			b, ok := policies.Pack(name)
			if !ok {
				return nil, fmt.Errorf("unknown pack %q (embedded: %s)", name, strings.Join(policies.Names(), ", "))
			}
			raw = b
		}
		var cfg policy.SnapshotConfig
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("pack %q: %w", name, err)
		}
		s, err := engine.Compile(cfg)
		if err != nil {
			return nil, fmt.Errorf("pack %q: %w", name, err)
		}
		packs = append(packs, pack{name: name, snapshot: s, normalize: norm, opts: opts, useOpts: useOpts})
	}
	return packs, nil
}

func loadActions(path string) ([]action, error) {
	f, err := os.Open(path) //nolint:gosec // G304: reading the benchmark the user named is the point
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var actions []action
	ids := map[string]bool{}
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		var a action
		if err := json.Unmarshal([]byte(text), &a); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		switch policy.DecisionKind(a.Expect) {
		case policy.Allow, policy.Deny, policy.RequiresApproval:
		default:
			return nil, fmt.Errorf("%s:%d: bad expect %q", path, line, a.Expect)
		}
		if ids[a.ID] {
			return nil, fmt.Errorf("%s:%d: duplicate id %q", path, line, a.ID)
		}
		ids[a.ID] = true
		actions = append(actions, a)
	}
	return actions, sc.Err()
}

// loadTranscripts pulls governed tool_use blocks out of Claude Code session
// transcripts. Lines that are not assistant messages are skipped.
func loadTranscripts(root string) ([]action, error) {
	var traffic []action
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".jsonl") {
			return err
		}
		f, err := os.Open(path) //nolint:gosec // G304: walking the transcript directory the user named
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1024*1024), 64*1024*1024)
		for sc.Scan() {
			var entry struct {
				Type    string `json:"type"`
				Message struct {
					Content json.RawMessage `json:"content"`
				} `json:"message"`
			}
			if json.Unmarshal(sc.Bytes(), &entry) != nil || entry.Type != "assistant" {
				continue
			}
			var blocks []struct {
				Type  string         `json:"type"`
				Name  string         `json:"name"`
				Input map[string]any `json:"input"`
			}
			if json.Unmarshal(entry.Message.Content, &blocks) != nil {
				continue
			}
			for _, b := range blocks {
				if b.Type == "tool_use" && governedTools[b.Name] {
					traffic = append(traffic, action{Tool: b.Name, Params: b.Input})
				}
			}
		}
		return sc.Err()
	})
	return traffic, err
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "agbench:", err)
		os.Exit(2)
	}
}

// loadCodex reads OpenAI Codex CLI session logs. Codex records every command
// it actually ran as a CommandExecution item with the full argv, and every
// file edit as a FileChange item. PowerShell (-Command) and cmd.exe (/c)
// commands become PowerShell actions, anything else a Bash action; each
// changed file becomes a Write action on that path.
func loadCodex(root string) ([]action, error) {
	var traffic []action
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".jsonl") {
			return err
		}
		f, err := os.Open(path) //nolint:gosec // G304: walking the log directory the user named
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1024*1024), 64*1024*1024)
		for sc.Scan() {
			var entry struct {
				Type    string `json:"type"`
				Payload struct {
					Type string `json:"type"`
					Item struct {
						Type    string                     `json:"type"`
						Command json.RawMessage            `json:"command"`
						Changes map[string]json.RawMessage `json:"changes"`
					} `json:"item"`
				} `json:"payload"`
			}
			if json.Unmarshal(sc.Bytes(), &entry) != nil || entry.Type != "event_msg" || entry.Payload.Type != "item_completed" {
				continue
			}
			switch it := entry.Payload.Item; it.Type {
			case "CommandExecution":
				var argv []string
				if json.Unmarshal(it.Command, &argv) != nil || len(argv) == 0 {
					continue
				}
				if a, ok := codexAction(argv); ok {
					traffic = append(traffic, a)
				}
			case "FileChange":
				for file := range it.Changes {
					traffic = append(traffic, action{Tool: "Write", Params: map[string]any{"file_path": file}})
				}
			}
		}
		return sc.Err()
	})
	return traffic, err
}

func codexAction(argv []string) (action, bool) {
	exe := strings.ToLower(path.Base(strings.ReplaceAll(argv[0], `\`, "/")))
	exe = strings.TrimSuffix(exe, ".exe")
	after := func(flags ...string) (string, bool) {
		for i, a := range argv[1:] {
			for _, f := range flags {
				if strings.EqualFold(a, f) {
					return strings.Join(argv[i+2:], " "), true
				}
			}
		}
		return "", false
	}
	switch exe {
	case "powershell", "pwsh":
		if c, ok := after("-Command", "-c"); ok {
			return action{Tool: "PowerShell", Params: map[string]any{"command": c}}, true
		}
	case "cmd":
		if c, ok := after("/c", "/k"); ok {
			return action{Tool: "PowerShell", Params: map[string]any{"command": "cmd /c " + c}}, true
		}
	case "bash", "sh", "zsh":
		if c, ok := after("-c", "-lc"); ok {
			return action{Tool: "Bash", Params: map[string]any{"command": c}}, true
		}
	}
	return action{Tool: "Bash", Params: map[string]any{"command": strings.Join(argv, " ")}}, true
}
