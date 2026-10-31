# Pre-registration: out-of-sample test on other developers' public traces

Written 2026-10-31T03:22Z, before any public trace was downloaded or read.

## Frozen artifacts

SHA-256 over `internal/facts/*.go`, `internal/policy/*.go`, `policies/claude-code.json` and the four regex/v1 baseline packs (in that order, as printed by `sha256sum`, then hashed again): `6809d27dbebc94e15e71914a90fa068321e52cf5f38ef08ae4cc4ea9ebabd835`. Base commit `967fd1be`. Neither the analyzer nor any pack is changed after this point for this test; bugs found are reported, not fixed.

Exact command (Git Bash, repository root; `sha256sum` prints Windows binary-mode `*` markers, which are part of the hashed text):

```bash
sha256sum internal/facts/*.go internal/policy/*.go policies/claude-code.json \
  bench/baseline/regex-matched.json bench/baseline/regex-tuned.json \
  bench/baseline/regex-strong.json bench/baseline/claude-code-v1.json | sha256sum
```

This registration is timestamped only by the files and this session's records; it was not deposited with an external registry (OSF, Zenodo) before the data were read. The analysis harness (`cmd/agbench`, `bench/tools`) is outside the hash; see Deviations.

## Data

Public, MIT-licensed Claude Code and Codex session exports on Hugging Face published by their owners (DataClaw and `my-personal-*-data` datasets). Forks that re-upload another person's export are dropped; one developer = one dataset owner. Developers with fewer than 50 shell calls are excluded. Only aggregates and audit samples are reported.

## Hypotheses (one-sided, unit = developer)

- **H1 (AST vs fair tokenizer).** Facts stop fewer shell calls than tokenizer+ (`with:tokplus`) for more developers than the reverse. Sign test over developers with at least one difference, alpha 0.05.
- **H2 (facts vs vocabulary regex).** Facts stop fewer shell calls than the vocabulary-matched regex for more developers than the reverse. Same test.
- **H3 (warranted stops).** In blind audits of disagreement samples, the share of fact-only stops containing a gated action exceeds the share of vocabulary-regex-only stops (denials and approvals pooled), Fisher exact test.

Secondary, descriptive: pooled and macro-averaged friction for every pack; per-developer distribution.

## Amendment 1 (2026-10-31, after download, before any policy was run on the data)

Inspecting command *lengths* (no command text and no policy decision) showed that most exports were made by an older DataClaw version that cuts every tool input at about 300 characters. A cut command cannot be parsed, so the AST analyzer would mark it opaque; the cut also removes exactly the multi-line programs on which H1 is about. Therefore:

- **Primary analysis** uses only exports whose shell inputs are complete (longest command well above 400 characters).
- **Secondary analysis (H1b, H2b)** uses every export, restricted to commands shorter than 290 characters, which are complete in every export. Both policies see the same calls. Because it drops long programs, it is a conservative test of H1.
- Exports that are byte-identical copies of another (same session ids) count once, under the earliest uploader.
- Tool names are mapped: Claude Code `Bash`; Codex `exec_command`/`shell`; Gemini CLI `run_shell_command` → shell. File tools (`Read`, `Edit`, `Write`, `NotebookEdit`, `Grep`) are kept for the all-call rate.

## Amendment 2 (2026-10-31, before any policy was run on any public data)

Further sources found while searching the Hub, all with complete (raw) inputs:

- **SWE-chat** (`SALT-NLP/SWE-chat`, ODC-By, COLM 2026): real users' Claude Code, Codex and Gemini CLI sessions collected through the Entire.io CLI, with a `user_id` per session. When access is granted it becomes the **primary** data set; developer = `user_id`.
- Raw `~/.claude/projects` and Codex rollout uploads by individual developers (Hub "agent traces" format), where the dataset is a person's own work: `vedalken/merchantscroll-traces`, `kingkw1/read-along-ai-agent-traces`, `naazimsnh02/tutordesk-agent-traces`, `thomwolf/am-session-*`, `yellowbeeblackbee/claude-traces`, `Mike0021/codex-sessions`, `trace-commons/agent-traces`, `ultralazr/claude-code-traces`.
- Excluded by rule, not by result: automated runs (paper-reproduction `repro-*`, benchmark harnesses, `ml-intern` agent sessions, distillation sets of synthetic tasks) and re-uploads of another person's data.

The hypotheses, packs, thresholds and tests above are unchanged. Every source is reported separately as well as pooled, so no source can be dropped after the fact.

## Audit plan

Seeded sample (seed 20261031) of up to 30 fact-only and 30 regex-only stops across developers, mixed and shuffled, labelled blind to policy by (a) a Claude agent and (b) two human annotators using `docs/research/LABELING.md`. Agreement reported as Cohen's kappa. Because these traces are public, the audit items can be shown to human annotators.

## Deviations from this registration (recorded 2026-10-31, after the results)

1. **Converter fixed after a first primary run was seen.** The first run of the self-published primary analysis wrongly admitted short commands from string-format (cutting) exports, against Amendment 1 (20 developers; facts vs tokenizer+ 11 vs 4, facts vs vocabulary regex 2 vs 13). `dataclaw_calls.py` was then changed to mark every string-format input incomplete, which implements Amendment 1, and the analysis was rerun (13 developers). SWE-chat was not affected (all inputs complete).
2. **Truncation rule implemented by input format.** Amendment 1 says "longest command well above 400 characters"; the code uses the input format (dict = complete, string = cut). Every dict-format export with at least 50 shell calls has a longest command above 400 characters, so the two rules select the same exports.
3. **Dedup.** Copies are counted once under the owner whose directory sorts first, not the earliest uploader (upload order was not recorded). Raw uploads were not checked against DataClaw exports for overlap.
4. **Audit.** The audit sample was drawn from SWE-chat only; a second sample from the self-published exports was drawn but not labelled. Only the Claude agent has labelled it; the two human annotations are pending (labelling kit in `bench/human`). The sample takes one stop per developer (round-robin), so it estimates the share among developers' typical stops, not among all stops, and it did not apply the 50-call threshold.
5. **Test direction bug.** `agreement.py` first chose the one-sided direction from the data; it now uses the registered direction (fact-only > other). The reported p (0.35) was already in the registered direction.
6. **Harness edits after labelling** that do not change any registered number: developer ids hashed in the audit key; a reasons tally added to the report; usernames redacted in the labelling page.
7. **Per-agent breakdown** (not registered) was first run with a 20-call threshold; the paper reports it at the registered 50-call threshold and labels it exploratory.
8. **Exploratory analyses added after the results** and labelled as such: effect sizes (median and bootstrap intervals of per-developer differences), leave-top-10-out, SWE-chat restricted to commands under 290 characters, SWE-chat without the 32 developers who work in the collection tool vendor's repositories, a joint relabelling of the in-sample and out-of-sample audit items under one protocol (its `readable-dynamic` label was added after the discrepancy between the two audits was seen), and, after a fourth external review, a blind audit of SWE-chat calls on which facts and tokenizer+ disagree (`-disagree tokplus:facts`, seed 20261101). The paper now says "pre-specified" rather than "pre-registered", because this file was not deposited with an external registry.
