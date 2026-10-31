# Reproducing the evaluation

The method, results and limitations are in the paper: [`docs/paper/main.pdf`](../paper/main.pdf) (source `docs/paper/main.tex`). This page lists the command that produces each number in the paper.

## Policies compared

| Name in the paper | File |
|---|---|
| v1 (substring, shipped) | `bench/baseline/claude-code-v1.json` |
| Strong regex | `bench/baseline/regex-strong.json` |
| Tuned regex (one tuning pass on real traffic) | `bench/baseline/regex-tuned.json` |
| Vocabulary-matched regex | `bench/baseline/regex-matched.json` |
| … on normalized commands | pack spec `normvocab=norm:bench/baseline/regex-matched.json` (agbench rewrites each Bash command with `facts.Normalize` first) |
| Facts ablations | pack specs `tok=with:tok:policies/claude-code.json` (tokenization instead of the AST), `tokplus=with:tokplus:policies/claude-code.json` (tokenizer plus here-documents and static variables), `with:noreaders:…`, `with:novars:…`, `with:exempt:…` (regenerable-path exemption); see `facts.Options` |
| Tuning ablation (cumulative edits 1–4) | `bench/baseline/ablation/regex-t1.json` … `regex-t4.json` |
| Gate-all | `bench/baseline/gate-all.json` |
| Facts (current default) | `policies/claude-code.json` |
| Facts-strict | `bench/baseline/facts-strict.json` |

**Codex.** `-codex DIR` reads OpenAI Codex CLI session logs (`~/.codex/sessions`) the same way `-transcripts` reads Claude Code transcripts. It takes every executed command from the logs' `CommandExecution` items and every edited file from their `FileChange` items, and prints only aggregates. The paper's organic Codex numbers come from a frozen copy whose manifest hash starts `2686606e`. The staged Bash run is `bench/codex-bash.jsonl`; evaluate it with `go run ./cmd/agbench -data bench/codex-bash.jsonl -packs $P -misses`.

**Real traffic in the paper** was measured on a frozen copy of the transcripts, which excludes the session that wrote the paper. The manifest of that copy has a SHA-256 hash starting `60f161cc`. To measure your own corpus, freeze a copy first, then pass its directory to `-transcripts`.

## Out-of-sample: other developers' public traces

Pre-registered in [`PREREGISTRATION.md`](PREREGISTRATION.md) (analyzer hash `6809d27d…`, fixed before any public trace was read).

```bash
pip install duckdb                     # SWE-chat needs a Hugging Face token that accepted its terms
python bench/tools/swechat_calls.py swechat_calls.jsonl                 # SALT-NLP/SWE-chat, pinned revision
python bench/tools/dataclaw_calls.py EXPORTS_DIR dataclaw_calls.jsonl  # DataClaw exports
python bench/tools/dataclaw_calls.py --raw RAW_DIR raw_calls.jsonl     # raw Claude Code / Codex / Cursor uploads
F=policies/claude-code.json
go run ./cmd/agbench -data bench/heldout-b.jsonl \
  -packs v1=bench/baseline/claude-code-v1.json,regex=bench/baseline/regex-strong.json,tuned=bench/baseline/regex-tuned.json,vocab=bench/baseline/regex-matched.json,facts=$F,tok=with:tok:$F,tokplus=with:tokplus:$F \
  -calls swechat_calls.jsonl -compare facts:tokplus,facts:vocab,facts:tuned,facts:tok \
  -disagree facts:vocab -disagree-out bench/human/audit
```

`-calls` prints friction per developer (developers are numbered, never named), pooled and macro-averaged, and one-sided sign tests over developers; `-disagree` writes the blind audit sample. Add `-maxlen 290` for the secondary analysis that admits short commands from exports that cut long inputs.

**Off-the-shelf parser ablation (exploratory, deviation 9).** `pip install tree-sitter tree-sitter-bash`, then build a front-end map over every input and add the pack `ts=front:front.jsonl:with:tokplus:$F`:

```bash
python bench/tools/ts_front.py front.jsonl bench/heldout-b.jsonl bench/adaptive.jsonl swechat_calls.jsonl ~/.claude/projects
go run ./cmd/agbench -data bench/heldout-b.jsonl -packs facts=$F,tokplus=with:tokplus:$F,ts=front:front.jsonl:with:tokplus:$F \
  -calls swechat_calls.jsonl -compare facts:ts,ts:tokplus,ts:vocab
```

Results: [`bench/RESULTS-ts-ablation.md`](../../bench/RESULTS-ts-ablation.md). A command missing from the map fails closed and counts as an eval error, so build the map over every file you evaluate. On SWE-chat-sized inputs, run one agbench at a time (the map and the calls together need several GB of memory).

**Human labels.** `python bench/tools/make_label_kit.py bench/human/audit-items.jsonl bench/human` builds `bench/human/label-kit.html`: 50 held-out B actions and the 60 audit items, shuffled, labels hidden. Annotators follow [`LABELING.md`](LABELING.md) and export a JSON file; `python bench/tools/agreement.py bench/human/label-kit-key.jsonl bench/human/audit-key.jsonl labels-*.json` reports kappa, agreement with the benchmark labels, and the audit result.

## Commands

Define the seven packs once:

```bash
P=v1=bench/baseline/claude-code-v1.json,regex=bench/baseline/regex-strong.json,tuned=bench/baseline/regex-tuned.json,vocab=bench/baseline/regex-matched.json,gateall=bench/baseline/gate-all.json,facts=policies/claude-code.json,strict=bench/baseline/facts-strict.json
```

All regex packs, including the ablation set, are generated by `python bench/baseline/make_regex_baselines.py`.

Then, from the repository root:

| Paper result | Command |
|---|---|
| Table I, held-out B (primary test) | `go run ./cmd/agbench -data bench/heldout-b.jsonl -packs $P -misses` |
| Table I, adaptive probes | `go run ./cmd/agbench -data bench/adaptive.jsonl -packs $P -misses` |
| Table I, held-out A | Recorded in `bench/RESULTS-heldout.md` (see the note below) |
| Table II, development set by technique | `go run ./cmd/agbench -data bench/actions.jsonl -packs $P -misses` |
| Table III and real-traffic friction | `go run ./cmd/agbench -packs $P -transcripts ~/.claude/projects` |
| Latency | `go test ./policies -run '^$' -bench PackOnHeldOutB -benchtime 30000x` |
| Analyzer tests and the development-set regression test | `go test ./internal/facts ./policies` |
| Fuzzing the analyzer | `go test ./internal/facts -run '^$' -fuzz FuzzShell -fuzztime 60s` |

**Held-out A.** It was evaluated on an earlier frozen analyzer (v2.1). Its results are recorded in `bench/RESULTS-heldout.md`. The current analyzer was afterwards fixed using A's misses, so its post-hoc score on A (`bench/RESULTS-heldout-posthoc.md`) is not a test result.

**Real traffic.** The friction command reads your own Claude Code transcripts and prints only aggregate numbers. The paper's traffic is not published.

**Held-out B.** Never tune the analyzer against it. It is the test set.
