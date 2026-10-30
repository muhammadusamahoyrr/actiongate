# Manual setup (external PostgreSQL)

> Back to the [README](../README.md) · Full [User Guide](GUIDE.md)

The step-by-step path — what `actiongate up` automates, useful for
understanding the pieces or wiring a non-local deployment. This path uses an
**external** PostgreSQL; `actiongate up` instead runs an embedded one for you.

**Prerequisites:** Go 1.25+, Docker (or any PostgreSQL 18+), and the
[goose](https://github.com/pressly/goose) migration tool
(`go install github.com/pressly/goose/v3/cmd/goose@latest`).

### 1. Get the binaries (2 min)

**No Go needed:** download the archive for your platform (Windows, macOS,
Linux) from the
[latest release](https://github.com/muhammadusamahoyrr/actiongate/releases/latest)
and extract it — it contains `actiongate`, `gateway`, `ag-hook`,
`controlplane`, `verify`, and the database `migrations/` folder used in
step 2.

Or build from source (Go 1.25+):

```bash
git clone https://github.com/muhammadusamahoyrr/actiongate
cd actiongate
go build -o bin/ ./cmd/...
```

### 2. Start Postgres and migrate (2 min)

```bash
docker run -d --name actiongate-db \
  -e POSTGRES_USER=ag -e POSTGRES_PASSWORD=ag -e POSTGRES_DB=actiongate \
  -p 5432:5432 postgres:18-alpine

goose -dir migrations postgres "postgres://ag:ag@localhost:5432/actiongate?sslmode=disable" up
```

### 3. Start the control plane (1 min)

```bash
export AG_DATABASE_URL="postgres://ag:ag@localhost:5432/actiongate?sslmode=disable"
export AG_TOKEN_SECRET="change-me-to-32-plus-random-bytes!!"
./bin/controlplane
```

It listens on `:8091`. On first start it prints generated signing-key seeds —
save them as `AG_GRANT_KEY_SEED` and `AG_EPOCH_KEY_SEED` so keys survive
restarts.

### 4. Create a tenant with a policy (2 min)

Save as `policy.json` — plain English version: *allow everything, deny
reading secrets files, require human approval for destructive shell commands:*

```json
{
  "default_decision": "allow",
  "rules": [
    {
      "id": "deny-secrets",
      "condition": "tool_name == \"read_file\" && params.path.contains(\".env\")",
      "decision": "deny",
      "risk_classification": "secrets"
    },
    {
      "id": "approve-destructive",
      "condition": "tool_name == \"bash\" && params.command.contains(\"rm -rf\")",
      "decision": "requires_approval",
      "risk_classification": "destructive"
    }
  ]
}
```

Conditions are [CEL](https://cel.dev) expressions over `tool_name`,
`agent_id`, `environment`, and `params`. Policies are compiled before they
are stored — a broken rule is rejected at provisioning, never at runtime.

```bash
export AG_DATABASE_URL="postgres://ag:ag@localhost:5432/actiongate?sslmode=disable"
TENANT=$(./bin/controlplane admin create-tenant -policy policy.json)
TOKEN=$(./bin/controlplane admin enroll-token -tenant $TENANT)
```

### 5. Enroll your gateway (1 min)

```bash
./bin/gateway enroll -server http://localhost:8091 -token $TOKEN -name my-laptop
```

This generates a keypair on your machine (the private key never leaves it),
exchanges the single-use token for a credential, and pins the control
plane's signing keys.

### 6. Try it (2 min)

An allowed action — returns a verified grant, exit code 0:

```bash
./bin/gateway check -agent me -session $(uuidgen) -request-id r1 \
  -tool bash -params '{"command":"ls"}'
./bin/gateway report -action <ACTION_ID_FROM_ABOVE> -status success
```

A denied action — exit code 2, and it tells you exactly which rule fired:

```bash
./bin/gateway check -agent me -session $(uuidgen) -request-id r2 \
  -tool read_file -params '{"path":"/app/.env"}'
# denied: denied by rule deny-secrets
```

A gated action — this call **blocks and waits for a human**:

```bash
./bin/gateway check -agent me -session $(uuidgen) -request-id r3 \
  -tool bash -params '{"command":"rm -rf /tmp/x"}' -wait 10m
```

With Slack configured (next section) an Approve/Deny message appears in your
channel. Without Slack, approve it from a second terminal:

```bash
TOKEN=$(docker exec actiongate-db psql -U ag -d actiongate -tAc \
  "select args->>'callback_token' from river_job where kind='deliver_approval' order by id desc limit 1")
curl -X POST http://localhost:8091/approval/callback \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$TOKEN\",\"decision\":\"approved\",\"approver_id\":\"you\",\"reason\":\"ok\"}"
```

The blocked `check` immediately returns with its grant, exit 0.

### 7. Wrap a real agent (2 min)

**MCP agents (Claude Code, Cursor, anything MCP):** change one line of the
agent's MCP config so the server command runs through the gateway:

```json
{ "mcpServers": { "mytools": {
    "command": "gateway",
    "args": ["mcp", "--", "node", "my-mcp-server.js"]
} } }
```

Every tool call now routes through your policy. Denied calls come back to
the agent as an explained error; gated calls pause inside the agent's tool
call until someone approves.

**Claude Code:** `actiongate protect claude-code` does this for you — it
installs the `ag-hook` PreToolUse bridge (Claude Code's built-in
Read/Write/Bash tools never cross the MCP boundary, so the hook is the
enforcement point that actually governs them), a SessionStart hook that
warns loudly when the control plane is down (governed tools fail closed,
never silently), and applies your chosen policy pack. A Claude Code
plugin with `/actiongate:protect`, `/actiongate:status`, and
`/actiongate:tamper-demo` commands lives in
[claude-plugin/](claude-plugin/).

**Other agent hooks:** `gateway check` exits `0` allowed / `2` denied /
`3` timeout, and `gateway report` sends the outcome — the exact contract
PreToolUse/PostToolUse-style hooks need.

### 8. Verify the audit trail (1 min)

Everything above was recorded, hash-chained, and sealed. Check it yourself:

```bash
./bin/verify -database-url "$AG_DATABASE_URL" -tenant $TENANT \
  -key epoch-1=<EPOCH_PUBLIC_KEY_BASE64>
# {"ok":true,"epochs":4,"events_sealed":15,"unsealed_tail":0,"problems":null}
```

`verify` trusts nothing but the public key: it re-derives every event hash,
epoch root, and signature from the raw rows. If anyone — including a
database admin — edited history, `ok` becomes `false` and the exact
tampered event is named.

