# actiongate User Guide

This is the complete guide to installing, configuring, and operating
actiongate. If you just want to get running in a minute, start with the
[README quickstart](../README.md#quickstart-60-seconds) — this guide goes
deeper into every step.

**Contents**

1. [Concepts — how actiongate works](#1-concepts--how-actiongate-works)
2. [Installation](#2-installation)
3. [Getting started](#3-getting-started)
4. [Policy packs](#4-policy-packs)
5. [Writing custom policies](#5-writing-custom-policies)
6. [Approvals](#6-approvals)
7. [Verifying the audit log](#7-verifying-the-audit-log)
8. [Running unattended](#8-running-unattended)
9. [Governing other agents](#9-governing-other-agents)
10. [Configuration reference](#10-configuration-reference)
11. [Troubleshooting](#11-troubleshooting)
12. [Uninstalling](#12-uninstalling)

---

## 1. Concepts — how actiongate works

actiongate has two halves:

- **The gateway** runs on your machine. It intercepts an agent's tool calls
  (via an MCP proxy or a Claude Code hook), asks the control plane for a
  decision, and executes only when it holds a valid grant. Your credentials
  and files never leave your machine.
- **The control plane** evaluates policies and coordinates approvals. It
  never executes anything and never sees your credentials. It can run
  locally (the default `actiongate up` setup) or on a shared server.

Every governed tool call flows through the same pipeline:

```
agent tool call ──► gateway ──► control plane
                                   │
                     ┌─────────────┼─────────────┐
                     ▼             ▼             ▼
                   allow         deny      requires approval
                     │             │             │
              signed grant    named rule    Slack / callback
                     │        back to agent      │
                     ▼                     approved? ──► signed grant
              tool executes
                     │
                     ▼
            signed outcome receipt ──► hash-chained audit log
```

Key terms you will see throughout this guide:

| Term | Meaning |
|---|---|
| **ExecutionGrant** | A signed, single-use authorization with a ≤ 60-second lifetime, bound to the exact request content. The gateway verifies its signature, content hash, and expiry locally before executing anything. |
| **Policy** | An ordered list of rules; the first rule whose condition matches decides the outcome (`allow`, `deny`, or `requires_approval`). No match falls through to the policy's default. |
| **Fail closed** | If the control plane is unreachable, governed tools are blocked — never silently allowed. |
| **Audit chain** | Every event is appended to a per-tenant log that a background sealer numbers, hash-chains, and seals into signed epochs. The `verify` tool re-derives every hash and signature from raw data, so tampering — even by a database administrator — is detectable. |
| **OutcomeUnknown** | If an outcome report never arrives (e.g. the gateway crashed mid-execution), the action is honestly recorded as unknown, never guessed. |

## 2. Installation

**Prerequisites:** Docker Desktop (actiongate manages PostgreSQL for you —
or point it at any existing PostgreSQL 16+ with `actiongate up -db-url`).

### Option A — release binaries (recommended)

Download the archive for your platform (Windows, macOS, Linux) from the
[latest release](https://github.com/muhammadusamahoyrr/actiongate/releases/latest)
and extract it somewhere on your `PATH`. It contains all five binaries —
`actiongate`, `gateway`, `ag-hook`, `controlplane`, `verify` — plus the
database `migrations/` folder.

> The binaries must stay in the same directory: `ag-hook` locates `gateway`
> next to itself, and `protect` locates `ag-hook` the same way.

### Option B — build from source

Requires Go 1.25+:

```bash
git clone https://github.com/muhammadusamahoyrr/actiongate
cd actiongate
go build -o bin/ ./cmd/...
```

## 3. Getting started

### Step 1 — start the stack

```bash
actiongate up
```

This is idempotent — run it any time. It starts (or reuses) a Postgres
container, applies migrations, provisions a tenant with the `claude-code`
starter policy, enrolls your gateway, round-trips a self-test action, and
serves the control plane in the foreground. State (database URL, signing-key
seeds, tenant ID) persists in your user config directory, so a second `up`
after a reboot rebuilds exactly the same environment.

For unattended operation that survives reboots, see
[Running unattended](#8-running-unattended).

### Step 2 — protect a project

In each project you want governed:

```bash
cd path/to/your/project
actiongate protect claude-code            # default pack
actiongate protect claude-code -pack paranoid   # or stricter
```

This installs two hooks into the project's `.claude/settings.local.json`
(your existing settings are preserved; a backup is written on first
install):

- a **PreToolUse** hook — the enforcement point; every governed tool call
  is checked before it runs, and
- a **SessionStart** hook — warns loudly at session start if the control
  plane is down (because governed tools fail closed).

The hooks take effect in **new** Claude Code sessions.

### Step 3 — see it work

Start Claude Code in the protected project and:

- ask it to read your `.env` → 🛑 **blocked**, with the rule named;
- ask it to run `rm -rf` on something → ⏸ **paused** until a human
  approves (in Slack, or via the callback endpoint);
- ask it to list files → passes instantly.

Every one of those decisions is now in the sealed audit log
([verify it](#7-verifying-the-audit-log)).

## 4. Policy packs

Starter packs exist so you don't have to write policy rules for tool
schemas you've never seen. Pick one at protect time; switch any time by
re-running `protect` with a different `-pack`.

| Pack | Secrets reads | Destructive shell | Everything else |
|---|---|---|---|
| `claude-code` (default) | denied | waits for approval (`rm -rf`, force-push, `DROP TABLE`, …) | allowed |
| `paranoid` | denied | **every** shell command and file mutation waits | reads allowed |
| `relaxed` | denied | only catastrophes wait (`rm -rf /`, `dd`, `mkfs`, `DROP DATABASE`, …) | allowed |

All packs deny secrets reads — that is not negotiable in any pack.

## 5. Writing custom policies

A policy is JSON: a `default_decision` plus an ordered list of rules.
**First match wins**; no match falls through to the default.

```json
{
  "default_decision": "allow",
  "rules": [
    {
      "id": "deny-secrets",
      "condition": "tool_name == \"read_file\" && has(params.path) && params.path.contains(\".env\")",
      "decision": "deny",
      "risk_classification": "secrets"
    },
    {
      "id": "approve-destructive",
      "condition": "tool_name == \"bash\" && has(params.command) && params.command.contains(\"rm -rf\")",
      "decision": "requires_approval",
      "risk_classification": "destructive"
    }
  ]
}
```

- **Conditions** are [CEL](https://cel.dev) expressions over `tool_name`,
  `agent_id`, `environment`, and `params` (the tool call's parameters).
- **Decisions** are `allow`, `deny`, or `requires_approval`.
- Policies are **compiled before they are stored** — a syntactically broken
  rule, an unknown variable, or a non-boolean condition is rejected at
  provisioning time and can never fail at runtime.

> **Always guard `params` access with `has()`.** A condition that reads
> `params.command` on a tool call that has no `command` key errors the
> evaluation — and an evaluation error fails **closed**, blocking the call.
> `has(params.command) && params.command.contains(...)` is the safe form.

Apply a policy to your tenant:

```bash
controlplane admin set-policy -tenant <TENANT_ID> -policy policy.json
```

Policy changes are versioned snapshots — every decision in the audit log
records exactly which policy version produced it. A policy change can
tighten the path of an already-pending action, but never loosen it.

## 6. Approvals

When a rule decides `requires_approval`, the action parks and the agent's
tool call blocks until a human decides (or the approval expires).

### Slack (recommended)

Create a Slack app with a bot token (scope `chat:write`) and interactivity
pointed at `https://<your-host>/slack/interaction`, then configure:

```bash
export AG_SLACK_BOT_TOKEN="xoxb-..."
export AG_SLACK_SIGNING_SECRET="..."
export AG_SLACK_CHANNEL="C0123456789"
```

(For the Windows service, put `slack_bot_token` / `slack_signing_secret` /
`slack_channel` into `%APPDATA%\actiongate\dev.json` instead — services
don't see your shell environment.)

Approval requests appear as messages with **Approve** / **Deny** buttons.
Clicks are signature-verified against Slack's signing secret and recorded
with the Slack user's identity.

### Without Slack — the callback endpoint

Any channel that can deliver a token works. Each approval mints a
single-use, HMAC-signed, expiring token; POST it back to decide:

```bash
curl -X POST http://localhost:8091/approval/callback \
  -H "Content-Type: application/json" \
  -d '{"token":"<TOKEN>","decision":"approved","approver_id":"you","reason":"ok"}'
```

Approvals are resolved with compare-and-swap: two concurrent approvers
can't double-resolve, and a replayed token is rejected without changing
the outcome.

## 7. Verifying the audit log

Everything actiongate does is appended to a per-tenant audit stream that a
background sealer numbers, hash-chains (SHA-256), and seals into epochs
signed by a key the application does not hold.

```bash
verify -database-url "$AG_DATABASE_URL" -tenant <TENANT_ID> \
  -key epoch-1=<EPOCH_PUBLIC_KEY_BASE64>
# {"ok":true,"epochs":53,"events_sealed":204,"unsealed_tail":0,"problems":null}
```

`verify` trusts nothing but the public key: it re-derives every event
hash, epoch root, and signature from the raw database rows. If anyone —
including a database administrator — edits history, `ok` flips to `false`
and the exact tampered event is named. Exit codes: `0` verified, non-zero
otherwise, so it drops straight into CI or a cron job.

To see this property demonstrated safely:

```bash
actiongate tamper-demo
```

It seals real events on a **throwaway database**, verifies them
(`ok:true`), then plays a malicious DBA — disables the append-only
trigger and rewrites an approval. The database accepts the edit, and
re-verification returns `ok:false` naming the exact event. Your real
chain is never touched.

> **Keep your epoch key seed safe and stable.** Regenerating the epoch
> signing seed under the same key ID makes previously sealed epochs
> unverifiable. `actiongate up` persists the seeds for you.

## 8. Running unattended

### Windows service

```powershell
actiongate service install    # from an elevated terminal, once
```

After that the control plane starts automatically after every reboot
(delayed start), restarts itself on failure, waits patiently for
Docker/Postgres to come up, and logs to `%APPDATA%\actiongate\service.log`.

```powershell
actiongate service status     # health check — no elevation needed
actiongate service stop|start # manage it
actiongate service uninstall  # remove it
```

A useful side effect of running as a service: a governed agent running as
your user **cannot kill the firewall** — stopping the service requires
elevation.

### Linux / macOS

Run the `controlplane` binary under systemd or launchd with the `AG_*`
environment variables from the
[configuration reference](#10-configuration-reference). Native
`service install` support for these platforms is planned.

## 9. Governing other agents

### Any MCP agent (Claude Code, Cursor, custom)

Change one line of the agent's MCP config so the server command runs
through the gateway:

```json
{ "mcpServers": { "mytools": {
    "command": "gateway",
    "args": ["mcp", "--", "node", "my-mcp-server.js"]
} } }
```

The proxy mirrors the downstream server's tools verbatim and routes every
`tools/call` through your policy. Denied calls return to the agent as an
explained error; gated calls pause inside the tool call until approved.
Denied or timed-out calls **never** reach the downstream server.

> Note for Claude Code specifically: its built-in Read/Write/Edit/Bash
> tools never cross the MCP boundary, so MCP wrapping alone does not
> govern them. That is why `actiongate protect claude-code` installs the
> PreToolUse hook — it is the enforcement point that actually covers the
> built-in tools. Use both together for full coverage.

### Any agent with pre/post tool hooks

The gateway CLI is the exact contract hook systems need:

```bash
gateway check  -agent <id> -session <uuid> -request-id <id> \
               -tool <name> -params '<json>' [-wait 10m]
gateway report -action <action-id> -status success|failure
```

`check` exits `0` allowed / `2` denied / `3` approval timeout / `1` error,
and blocks while an approval is pending (up to `-wait`). `report` sends
the signed outcome receipt.

## 10. Configuration reference

### Control plane environment

| Env var | Required | Purpose |
|---|---|---|
| `AG_DATABASE_URL` | yes | Postgres connection string |
| `AG_TOKEN_SECRET` | yes (≥ 32 bytes) | HMAC secret for approval callback tokens |
| `AG_LISTEN` | no (`:8091`) | Control plane listen address |
| `AG_GRANT_KEY_SEED` / `AG_EPOCH_KEY_SEED` | recommended | Base64 32-byte signing seeds; ephemeral (with a loud warning) if unset |
| `AG_APPROVER_DEFAULT` | no (`team-lead`) | Default approver target |
| `AG_SLACK_BOT_TOKEN` / `AG_SLACK_SIGNING_SECRET` / `AG_SLACK_CHANNEL` | no | Slack approvals |

### Files on disk

| Path | Contents |
|---|---|
| `%APPDATA%\actiongate\dev.json` (Windows) / user config dir | Environment managed by `actiongate up` / the service: DB URL, token secret, key seeds, tenant ID. File mode 0600. |
| `%APPDATA%\actiongate\gateway.json` | Gateway enrollment: local keypair (private key never leaves the machine) and pinned control-plane keys. 0600. |
| `%APPDATA%\actiongate\service.log` | Windows service log. |
| `<project>\.claude\settings.local.json` | The PreToolUse + SessionStart hooks installed by `protect`. |

### Hook / CLI exit codes

| Code | Meaning |
|---|---|
| `0` | allowed — grant verified, proceed |
| `2` | denied — the reason names the matched rule |
| `3` | approval timeout |
| `1` | error (control plane unreachable, bad arguments, …) — treated as fail closed by the hook |

## 11. Troubleshooting

**Claude Code says governed tools are blocked / a warning appears at
session start.** The control plane is down — this is fail-closed working
as designed. Run `actiongate service status` (or `actiongate up`) to
bring it back.

**`actiongate up` says the port is in use.** `up` probes `/healthz` on an
already-running control plane and reuses it. If something *else* owns
port 8091, set `AG_LISTEN` to another address.

**A policy change blocked everything.** Almost always a `params` access
without `has()` — the evaluation errors and fails closed for every tool.
See [Writing custom policies](#5-writing-custom-policies).

**`gateway check` mangles JSON parameters on Windows.** PowerShell 5.1
corrupts JSON arguments containing spaces. Run it from Git Bash, or avoid
spaces in inline `-params`.

**`verify` reports `ok:false` after I rotated keys.** The epoch key ID
must keep its key. If you generated a new seed under the same ID, old
epochs can no longer verify — restore the original seed, or accept that
history before the rotation verifies only with the old public key.

**Rebuilding binaries fails with "file in use" (Windows).** Stop the
service (`actiongate service stop`) or the foreground `up` before
`go build -o bin/`.

**Slack messages never arrive when running as a service.** Services don't
inherit your shell environment — put the Slack settings in
`%APPDATA%\actiongate\dev.json` (see [Approvals](#6-approvals)).

## 12. Uninstalling

```powershell
actiongate service uninstall            # remove the Windows service (elevated)
docker rm -f actiongate-db              # remove the database container
```

Then, per protected project, remove the `ag-hook` entries from
`.claude/settings.local.json` (a `.bak` backup of your pre-actiongate
settings was written on first install), and delete
`%APPDATA%\actiongate\` if you want the enrollment, keys, and logs gone
too — but note that deleting the key seeds makes previously sealed audit
epochs unverifiable.
