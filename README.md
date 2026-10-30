# actiongate

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go 1.25+](https://img.shields.io/badge/go-1.25%2B-00ADD8?logo=go)](go.mod)
[![Latest release](https://img.shields.io/github/v/release/muhammadusamahoyrr/actiongate)](https://github.com/muhammadusamahoyrr/actiongate/releases/latest)

**An action firewall for AI coding agents.**

Claude Code, Cursor and other agents can run shell commands, delete files and read your secrets. actiongate sits between the agent and your machine:

| Action | Result | Example |
|---|---|---|
| Harmless | ✅ passes instantly | `ls`, reading source files |
| Forbidden | 🛑 blocked, with the rule that fired | reading `.env`, `id_rsa` |
| Dangerous | ⏸️ waits until a human taps **Approve** in Slack | `rm -rf`, `git push --force`, `DROP TABLE` |

Every decision goes into a tamper-evident audit log that you can verify yourself.

![actiongate in action: .env read blocked, rm -rf paused for Slack approval, audit chain verified](docs/assets/hero.svg)

---

## Quickstart

No Docker or database setup needed. `actiongate up` runs its own embedded PostgreSQL.

1. Download the binaries from the [latest release](https://github.com/muhammadusamahoyrr/actiongate/releases/latest), or build them with Go 1.25+: `go build -o bin/ ./cmd/...`

2. Start the stack and leave it running:
   ```bash
   actiongate up
   ```

3. In the project you want to protect (new terminal):
   ```bash
   actiongate protect claude-code
   ```

4. Start Claude Code there and ask it to read `.env` (blocked) or run `rm -rf` (waits for approval).

`actiongate up` is safe to re-run, for example after a reboot. While it is down, protected projects **fail closed**: governed tools are blocked, never silently allowed.

---

## Why actiongate

- **Works with closed agents.** No SDK and no code changes. It hooks in at the MCP tool boundary and through Claude Code's `PreToolUse` hook.
- **Your credentials stay home.** Decisions are made centrally, but tools run on your machine. An approved action runs only with a signed, single-use, 60-second grant that the gateway checks locally.
- **History can't be quietly rewritten.** Audit events are hash-chained and sealed into signed epochs. The `verify` tool recomputes every hash and signature from the raw rows, so an edit made directly in the database shows up as `ok:false` and names the exact event.

See it for yourself:
```bash
actiongate tamper-demo
```
This seals real events on a throwaway database, then acts as a malicious DBA: it disables the append-only trigger and rewrites an approval. The database accepts the edit, but verification fails and names the tampered event. Your real audit chain is never touched.

---

## How it works

```
 AI agent ──► gateway (your machine) ──► control plane (policy + approvals)
                  │                            │
                  │  signed, single-use grant  │──► Slack: [Approve] [Deny]
                  ▼                            ▼
             tool runs locally            hash-chained audit log
```

1. The **gateway** sends each tool call to the **control plane**.
2. The control plane checks it against ordered [CEL](https://cel.dev) rules (first match wins). It then issues a signed grant, denies the call and names the rule, or holds it for approval.
3. Approvals use single-use HMAC tokens resolved by compare-and-swap, so two approvers can't both resolve one request and replays are rejected.
4. The gateway checks the grant's signature, request hash and expiry before running the tool, then reports a signed outcome.
5. A background sealer chains and signs every event. If an outcome never arrives, the action is recorded as `OutcomeUnknown`, never guessed.

---

## Policy packs

Choose a pack when you protect a project, so you don't have to write rules yourself:

| Pack | Behavior |
|---|---|
| `claude-code` (default) | Blocks secrets. Destructive shell commands wait for approval. Everything else passes. |
| `paranoid` | Blocks secrets. **Every** shell command and file change waits for approval. Reads pass. |
| `relaxed` | Blocks secrets. Only catastrophic commands (`rm -rf /`, `dd`, `mkfs`, `DROP DATABASE`…) wait. |

```bash
actiongate protect claude-code -pack paranoid
```

Custom rules are plain JSON with CEL conditions:

```json
{ "id": "approve-destructive",
  "condition": "tool_name == \"Bash\" && params.command.contains(\"rm -rf\")",
  "decision": "requires_approval" }
```

Policies are compiled before they are saved, so a broken rule is rejected at setup time and never fails at runtime.

---

## More features

- **Slack approvals** with Approve/Deny buttons. Clicks are signature-verified and recorded with the approver's identity.
- **Any MCP agent:** wrap its server command as `gateway mcp -- <your server>`.
- **Any hook-based agent:** `gateway check` exits `0` allowed, `2` denied, `3` timeout.
- **Windows service:** `actiongate service install` keeps protection running across reboots.
- **Health report:** `actiongate doctor` checks the database, schema, tenant, keys, sealer and control plane.
- **Embedded PostgreSQL 18** with backup/restore and safe upgrades. Or point `-db-url` at your own PostgreSQL 18+.
- **Claude Code plugin** with `/actiongate:protect`, `/actiongate:status` and `/actiongate:tamper-demo`.

---

## Built with

Go · PostgreSQL (row-level security, append-only triggers) · pgx + sqlc · River · cel-go · ConnectRPC + Protobuf · Ed25519 · MCP Go SDK · Slack · Testcontainers

```bash
make test   # full suite against real PostgreSQL, with -race
make lint   # buf lint + breaking-change check
```

Code layout: `cmd/` has five binaries (`actiongate`, `controlplane`, `gateway`, `ag-hook`, `verify`). `internal/` holds the policy engine, approvals, grants, queue workers, sealer and MCP proxy. Database migrations are in `migrations/` and the wire contract is in `proto/`.

---

## Documentation

| Document | What it covers |
|---|---|
| [User Guide](docs/GUIDE.md) | Concepts, custom policies, Slack setup, audit verification, configuration, troubleshooting |
| [Manual setup](docs/MANUAL_SETUP.md) | Step-by-step setup with an external PostgreSQL |
| [Architecture](docs/plan.md) | Design record and decisions |
| [Tech stack](docs/tech-stack.md) | Technology choices and why |
| [Verification log](VERIFICATION.md) | What was tested, milestone by milestone |
| [Claude plugin](claude-plugin/) | Slash commands for Claude Code |

## License

Apache-2.0. See [LICENSE](LICENSE).
