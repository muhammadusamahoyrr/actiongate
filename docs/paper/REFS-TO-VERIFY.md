# References to verify by hand

Every entry in `refs.bib` with an arXiv identifier of 2604 or later, with each claim `main.tex` makes from it. For each one, open the arXiv page, check the title, the authors and the listed claims, and tick the boxes.

Two entries were checked against their arXiv **abstract pages** (not the full text) by a fetch during the round-4 revision (2026-10-31). That check is noted under each one. All other entries still need a full manual check.

| Key | arXiv | Title in refs.bib |
|---|---|---|
| liu2026care | 2607.21642 | CARE: Pre-Execution Command Verification for Shell-Executing LLM Agents |
| zhao2026clawguard | 2604.11790 | ClawGuard: A Runtime Security Framework for Tool-Augmented LLM Agents Against Indirect Prompt Injection |
| zhong2026yolofs | 2604.13536 | Don't Let AI Agents YOLO Your Files: Information and Control in Agent-Native Filesystems |
| baumann2026swechat | 2604.20779 | SWE-chat: Coding Agent Interactions From Real Users in the Wild |
| ji2026permissiongate | 2604.04978 | Measuring the Permission Gate: A Stress-Test Evaluation of Claude Code's Auto Mode |
| li2026options | 2605.11360 | Options, Not Clicks: Lattice Refinement for Consent-Driven MCP Authorization |
| tang2026misalignment | 2605.29442 | How Coding Agents Fail Their Users: A Large-Scale Analysis of Developer-Agent Misalignment in 20,574 Real-World Sessions |
| hu2026saber | 2606.01317 | SABER: Benchmarking Operational Safety of LLM Coding Agents in Stateful Project Workspaces |
| weng2026consent | 2606.02668 | What You Approve Is What Executes: Consent Integrity for Black-Box LLM Agents |
| zheng2026actplane | 2606.25189 | ActPlane: Programmable OS-Level Policy Enforcement for Agent Harnesses |
| michael2026permissions | 2607.13718 | How Agents Ask for Permission: User Permissions for AI Agents, from Interfaces to Enforcement |
| singh2026issuetrojanbench | 2607.20759 | IssueTrojanBench: Benchmarking AI Coding Agents Against Malicious Issue Requests |
| yan2026userpolicies | 2608.27443 | Do User-Authored Permission Policies Improve Protection Against AI Agent Overreach? |
| dai2026agentguard | 2609.16287 | AgentGuard: Learning Execution Guardrails from Anomalous Coding-Agent Trajectories |

## Claims made in the paper

### ji2026permissiongate (2604.04978)

The abstract page (v3, revised 22 Oct 2026) was fetched on 2026-10-31. It reports an end-to-end FNR of 81.0% (95% CI 73.8–87.4) on 253 state-changing actions, and says that 36.8% of state-changing actions "fall outside the classifier's scope via Tier 2 (in-project file edits)". The full text was not checked.

- [ ] An independent stress test of Claude Code's auto mode found **81% false negatives**.
- [ ] The test covered **253 ambiguous state-changing actions**.
- [ ] **37%** of them fell outside the classifier's scope as **in-project file edits**. Check whether "37% of all state-changing actions" matches the paper's own denominator.
- [ ] Authors: Ji, Li, Ma, Jiang, Gao, Wang.

### baumann2026swechat (2604.20779)

The abstract page was fetched on 2026-10-31. Title and authors match: Baumann, Padmakumar, Li, Yang, Yang, Koyejo. The page says the paper was accepted at COLM 2026. It describes about 18,000 sessions from open-source developers. The full text was not checked.

- [ ] SWE-chat contains real sessions of Claude Code, Codex, Pi, OpenCode and other agents.
- [ ] It is mined from public GitHub repositories that checkpoint agent sessions with the **Entire.io CLI**.
- [ ] Its developer identifier is the commit author resolved through GitHub. This comes from the dataset card and schema; check it against the paper.
- [ ] License ODC-By; dataset revision 202b071f (from the Hugging Face dataset, not the paper).
- [ ] Used to study developer-agent misalignment (together with tang2026misalignment).

### liu2026care (2607.21642)

- [ ] It parses agent shell commands, compares with a regex baseline and ablates its structural layer.
- [ ] It canonicalizes and parses shell commands, scores risk with weights tuned on a development split, and sends borderline cases to an LLM judge.
- [ ] It is cited as an example of a learned classifier or LLM judge for unknown tools and dynamic code.

### zhao2026clawguard (2604.11790)

- [ ] It enforces deterministic policies over tool calls. It is listed with Progent, AgentSpec, Conseca and Datalog monitors.

### zheng2026actplane (2606.25189)

- [ ] It is an example of effects that bypass the tool layer, which are out of scope for this paper.
- [ ] It provides OS-level enforcement that bounds where damage lands.

### zhong2026yolofs (2604.13536)

- [ ] It provides recoverable or agent-native filesystems that bound where damage lands.

### hu2026saber (2606.01317) and singh2026issuetrojanbench (2607.20759)

- [ ] Benchmarks find that agents act unsafely in a large share of risky situations.
- [ ] They score agents rather than gates.

### li2026options (2605.11360)

- [ ] It reduces prompts through scoped consent.

### weng2026consent (2606.02668)

- [ ] It argues that approvals are only as honest as what they display.

### tang2026misalignment (2605.29442)

- [ ] It uses real-session corpora such as SWE-chat to study developer-agent misalignment. Check that it actually uses SWE-chat, or reword.
- [ ] The title says 20,574 real-world sessions.

### michael2026permissions (2607.13718)

- [ ] It systematizes user-level permission systems for AI agents.

### yan2026userpolicies (2608.27443)

- [ ] User-authored allow/ask/never rules reduce prompts but can weaken protection.

### dai2026agentguard (2609.16287)

- [ ] It learns execution rules from anomalous coding-agent trajectories.
