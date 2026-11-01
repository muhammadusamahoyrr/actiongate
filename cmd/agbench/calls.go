package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"sort"
	"strings"

	"github.com/muhammadusamahoyrr/actiongate/internal/facts"
)

// callRecord is one line written by bench/tools/dataclaw_calls.py: a tool
// call from a public session export, tagged with its developer and session.
type callRecord struct {
	Dev      string         `json:"dev"`
	Session  string         `json:"session"`
	Agent    string         `json:"agent"`
	Tool     string         `json:"tool"`
	Params   map[string]any `json:"params"`
	Complete bool           `json:"complete"`
}

// loadCalls keeps complete calls; with maxLen > 0 it also drops shell calls
// whose command is maxLen characters or longer, so that every export is
// compared on the same, uncut range of commands.
func loadCalls(path string, maxLen int) ([]callRecord, error) {
	f, err := os.Open(path) //nolint:gosec // G304: reading the call file the user named is the point
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []callRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 64*1024*1024)
	for sc.Scan() {
		var c callRecord
		if json.Unmarshal(sc.Bytes(), &c) != nil {
			continue
		}
		if maxLen > 0 && isShellTool(c.Tool) {
			cmd, _ := c.Params["command"].(string)
			if len(cmd) >= maxLen {
				continue
			}
			c.Complete = true // every export stores commands this short in full
		}
		if !c.Complete {
			continue
		}
		out = append(out, c)
	}
	return out, sc.Err()
}

func isShellTool(t string) bool { return t == "Bash" || t == "PowerShell" }

// writeDevelopers reports shell friction per developer, pooled and
// macro-averaged, and one-sided sign tests over developers for each
// comparison "A:B" (H: A stops fewer calls than B). Developers with fewer
// than minShell shell calls are left out. Only aggregates are printed.
func writeDevelopers(w *report, packs []pack, calls []callRecord, minShell int, compare string) [][]outcome {
	results := make([][]outcome, len(packs))
	for i, p := range packs {
		results[i] = make([]outcome, len(calls))
		for j, c := range calls {
			results[i][j] = p.evaluate(c.Tool, c.Params)
		}
	}
	type agg struct {
		shell int
		stop  []int
		agent map[string]int
	}
	devs := map[string]*agg{}
	for j, c := range calls {
		if !isShellTool(c.Tool) {
			continue
		}
		a := devs[c.Dev]
		if a == nil {
			a = &agg{stop: make([]int, len(packs)), agent: map[string]int{}}
			devs[c.Dev] = a
		}
		a.shell++
		a.agent[c.Agent]++
		for i := range packs {
			if stopped(results[i][j]) {
				a.stop[i]++
			}
		}
	}
	var names []string
	for d, a := range devs {
		if a.shell >= minShell {
			names = append(names, d)
		}
	}
	sort.Strings(names)

	w.printf("## Friction per developer (public exports)\n\n%d developers with at least %d shell calls. Cells: share of that developer's shell calls the pack stops.\n\n", len(names), minShell)
	header, sep := "| Developer | Agents | Shell calls |", "|---|---|---|"
	for _, p := range packs {
		header += " " + p.name + " |"
		sep += "---|"
	}
	w.println(header)
	w.println(sep)
	pooledN := 0
	pooled := make([]int, len(packs))
	macro := make([]float64, len(packs))
	for k, d := range names {
		a := devs[d]
		var ag []string
		for name, n := range a.agent {
			ag = append(ag, fmt.Sprintf("%s %d", name, n))
		}
		sort.Strings(ag)
		row := fmt.Sprintf("| D%02d | %s | %d |", k+1, strings.Join(ag, ", "), a.shell)
		for i := range packs {
			row += fmt.Sprintf(" %.2f%% |", 100*float64(a.stop[i])/float64(a.shell))
			pooled[i] += a.stop[i]
			macro[i] += 100 * float64(a.stop[i]) / float64(a.shell)
		}
		pooledN += a.shell
		w.println(row)
	}
	row1, row2 := fmt.Sprintf("| **Pooled** | | %d |", pooledN), "| **Macro mean** | | |"
	for i := range packs {
		row1 += fmt.Sprintf(" %.2f%% |", 100*float64(pooled[i])/float64(max(pooledN, 1)))
		row2 += fmt.Sprintf(" %.2f%% |", macro[i]/float64(max(len(names), 1)))
	}
	w.println(row1)
	w.println(row2)
	w.println()

	idx := map[string]int{}
	for i, p := range packs {
		idx[p.name] = i
	}
	for _, pair := range strings.Split(compare, ",") {
		a, b, ok := strings.Cut(strings.TrimSpace(pair), ":")
		ia, okA := idx[a]
		ib, okB := idx[b]
		if !ok || !okA || !okB {
			continue
		}
		fewer, more := 0, 0
		for _, d := range names {
			x, y := devs[d].stop[ia], devs[d].stop[ib]
			// compare rates; both packs see the same calls, so counts suffice
			if x < y {
				fewer++
			} else if x > y {
				more++
			}
		}
		w.printf("- **%s vs %s**: %s stops fewer calls for %d developers, more for %d, ties %d; one-sided sign test p = %.4g.\n",
			a, b, a, fewer, more, len(names)-fewer-more, signP(fewer, fewer+more))
	}
	w.println()
	return results
}

// writeReasons tallies why the shipped analyzer stops shell calls: the first
// words of each fact reason, pooled and for the developers with the highest
// friction. No command text is printed.
func writeReasons(w *report, calls []callRecord, minShell int) {
	type tally map[string]int
	pooled := tally{}
	byDev := map[string]tally{}
	shell := map[string]int{}
	stops := map[string]int{}
	for _, c := range calls {
		if !isShellTool(c.Tool) {
			continue
		}
		shell[c.Dev]++
		f := facts.Derive(c.Tool, c.Params)
		if !f.Destructive && !f.SecretAccess && !f.Opaque {
			continue
		}
		stops[c.Dev]++
		if byDev[c.Dev] == nil {
			byDev[c.Dev] = tally{}
		}
		seen := map[string]bool{}
		for _, r := range f.Reasons {
			words := strings.Fields(r)
			if len(words) > 4 {
				words = words[:4]
			}
			k := strings.Join(words, " ")
			if !seen[k] {
				seen[k] = true
				pooled[k]++
				byDev[c.Dev][k]++
			}
		}
	}
	top := func(t tally, n int) string {
		type kv struct {
			k string
			v int
		}
		var xs []kv
		for k, v := range t {
			xs = append(xs, kv{k, v})
		}
		sort.Slice(xs, func(i, j int) bool { return xs[i].v > xs[j].v || xs[i].v == xs[j].v && xs[i].k < xs[j].k })
		var parts []string
		for i := 0; i < len(xs) && i < n; i++ {
			parts = append(parts, fmt.Sprintf("%s (%d)", xs[i].k, xs[i].v))
		}
		return strings.Join(parts, "; ")
	}
	w.println("## Why facts stop calls")
	w.println()
	w.printf("Pooled: %s\n\n", top(pooled, 10))
	var devs []string
	for d, n := range shell {
		if n >= minShell {
			devs = append(devs, d)
		}
	}
	rate := func(d string) float64 { return float64(stops[d]) / float64(shell[d]) }
	sort.Slice(devs, func(i, j int) bool { return rate(devs[i]) > rate(devs[j]) })
	for i := 0; i < len(devs) && i < 5; i++ {
		w.printf("- %.2f%% of %d calls: %s\n", 100*rate(devs[i]), shell[devs[i]], top(byDev[devs[i]], 4))
	}
	w.println()
}

// signP is P(X >= k) for X ~ Binomial(n, 1/2).
func signP(k, n int) float64 {
	if n == 0 {
		return 1
	}
	p := 0.0
	for i := k; i <= n; i++ {
		p += math.Exp(lchoose(n, i) - float64(n)*math.Ln2)
	}
	return math.Min(p, 1)
}

func lchoose(n, k int) float64 {
	a, _ := math.Lgamma(float64(n + 1))
	b, _ := math.Lgamma(float64(k + 1))
	c, _ := math.Lgamma(float64(n - k + 1))
	return a - b - c
}

// writeDisagreements samples up to n shell calls stopped only by A and up to
// n stopped only by B (seeded, spread across developers), mixes and shuffles
// them, and writes two files: items (what annotators see, no policy) and a
// key (which policy stopped each item). Public data only.
func writeDisagreements(packs []pack, calls []callRecord, results [][]outcome, spec string, n int, seed int64, prefix string) error {
	a, b, ok := strings.Cut(spec, ":")
	ia, ib := -1, -1
	for i, p := range packs {
		if p.name == a {
			ia = i
		}
		if p.name == b {
			ib = i
		}
	}
	if !ok || ia < 0 || ib < 0 {
		return fmt.Errorf("-disagree %q: want A:B with both packs loaded", spec)
	}
	var onlyA, onlyB []int
	for j, c := range calls {
		if !isShellTool(c.Tool) {
			continue
		}
		sa, sb := stopped(results[ia][j]), stopped(results[ib][j])
		if sa && !sb {
			onlyA = append(onlyA, j)
		} else if sb && !sa {
			onlyB = append(onlyB, j)
		}
	}
	r := rand.New(rand.NewSource(seed)) //nolint:gosec // G404: a seeded sample, not a secret
	pick := func(ix []int) []int {
		r.Shuffle(len(ix), func(x, y int) { ix[x], ix[y] = ix[y], ix[x] })
		// round-robin over developers so one developer cannot fill the sample
		byDev := map[string][]int{}
		var order []string
		for _, j := range ix {
			d := calls[j].Dev
			if _, ok := byDev[d]; !ok {
				order = append(order, d)
			}
			byDev[d] = append(byDev[d], j)
		}
		var out []int
		for len(out) < n {
			added := false
			for _, d := range order {
				if len(byDev[d]) > 0 && len(out) < n {
					out = append(out, byDev[d][0])
					byDev[d] = byDev[d][1:]
					added = true
				}
			}
			if !added {
				break
			}
		}
		return out
	}
	type item struct {
		j      int
		source string
	}
	var items []item
	for _, j := range pick(onlyA) {
		items = append(items, item{j, a + "-only"})
	}
	for _, j := range pick(onlyB) {
		items = append(items, item{j, b + "-only"})
	}
	r.Shuffle(len(items), func(x, y int) { items[x], items[y] = items[y], items[x] })
	fi, err := os.Create(prefix + "-items.jsonl") //nolint:gosec // G304: writing to the prefix the user named is the point
	if err != nil {
		return err
	}
	defer func() { _ = fi.Close() }()
	fk, err := os.Create(prefix + "-key.jsonl") //nolint:gosec // G304: writing to the prefix the user named is the point
	if err != nil {
		return err
	}
	defer func() { _ = fk.Close() }()
	ei, ek := json.NewEncoder(fi), json.NewEncoder(fk)
	for k, it := range items {
		c := calls[it.j]
		id := fmt.Sprintf("q%03d", k+1)
		if err := ei.Encode(map[string]any{"id": id, "tool": c.Tool, "command": c.Params["command"]}); err != nil {
			return err
		}
		if err := ek.Encode(map[string]any{"id": id, "stopped_by": it.source, "dev": devHash(c.Dev), "agent": c.Agent,
			"decision_a": results[ia][it.j].decision, "decision_b": results[ib][it.j].decision}); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "disagreements: %s-only %d, %s-only %d; sampled %d items\n", a, len(onlyA), b, len(onlyB), len(items))
	return nil
}

// devHash replaces a developer identifier with a short hash, so audit keys
// can be shared without naming anyone.
func devHash(d string) string {
	sum := sha256.Sum256([]byte(d))
	return "dev-" + hex.EncodeToString(sum[:])[:8]
}
