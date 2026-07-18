// ag-hook bridges Claude Code's PreToolUse hook to actiongate. Claude Code
// runs it before every matched built-in tool call (Read/Edit/Write/Bash/…),
// passing the call as JSON on stdin. We turn that into a `gateway check` and
// translate the verdict back into Claude Code's hook contract:
//
//	allowed            -> exit 0, no output   (Claude Code proceeds normally)
//	denied             -> exit 2 + reason     (Claude Code blocks, model sees why)
//	requires_approval  -> gateway blocks until a human decides, then as above
//	anything uncertain -> exit 2 (fail closed; the action does NOT run)
//
// This is the enforcement point MCP-wrapping can't reach: the agent's own
// built-in tools never cross the MCP boundary, but they all cross this hook.
//
// A second mode, `ag-hook -warn`, is a SessionStart hook: it prints a loud
// warning when the control plane is unreachable (governed tools would fail
// closed with mysterious errors otherwise) and always exits 0 — a health
// warning must never block a session from starting.
//
// Configuration (all optional):
//
//	AG_HOOK_AGENT    agent id reported to the control plane (default "claude-code")
//	AG_HOOK_WAIT     how long to block on approval, Go duration (default "5m")
//	AG_HOOK_GATEWAY  path to the gateway binary (default: next to this binary)
//	AG_HOOK_SERVER   control-plane URL for -warn (default: enrolled server)
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/muhammadusamahoyrr/actiongate/internal/gateway"
)

type hookInput struct {
	SessionID string          `json:"session_id"`
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

type checkResult struct {
	Allowed     bool   `json:"Allowed"`
	Explanation string `json:"Explanation"`
	RuleID      string `json:"RuleID"`
}

// block prints a reason to stderr and exits 2 — Claude Code's signal to stop
// the tool call and hand the reason back to the model.
func block(reason string) {
	fmt.Fprintln(os.Stderr, reason)
	os.Exit(2)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func gatewayPath() (string, error) {
	if p := os.Getenv("AG_HOOK_GATEWAY"); p != "" {
		return p, nil
	}
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	name := "gateway"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(filepath.Dir(self), name), nil
}

// warn implements SessionStart: silent when healthy, loud when the stack
// is down. Exit is always 0.
func warn() {
	serverURL := os.Getenv("AG_HOOK_SERVER")
	if serverURL == "" {
		if path, err := gateway.DefaultStatePath(); err == nil {
			if state, err := gateway.LoadState(path); err == nil {
				serverURL = state.ServerURL
			}
		}
	}
	if serverURL == "" {
		serverURL = "http://localhost:8091"
	}
	client := &http.Client{Timeout: 2 * time.Second}
	// #nosec G704 -- the URL is the operator's own enrolled control plane
	// (state file / AG_HOOK_SERVER); probing its health is this mode's job.
	resp, err := client.Get(serverURL + "/healthz")
	if err == nil {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK && strings.Contains(string(body), `"ok"`) {
			return
		}
	}
	fmt.Printf(`⚠️ actiongate: the control plane at %s is NOT reachable, but this
project's tools are governed by it. Read/Edit/Write/Bash/Grep will FAIL
CLOSED (blocked) until it is back. Fix: 'actiongate service status', then
'actiongate service start' (or 'actiongate up' in a terminal).
`, serverURL)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-warn" {
		warn()
		os.Exit(0)
	}
	var in hookInput
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		block("actiongate: could not read hook input; failing closed")
	}
	if in.ToolName == "" {
		os.Exit(0) // nothing to govern
	}

	session := in.SessionID
	if _, err := uuid.Parse(session); err != nil {
		session = uuid.NewString()
	}
	params := string(in.ToolInput)
	if params == "" || params == "null" {
		params = "{}"
	}

	wait := envOr("AG_HOOK_WAIT", "5m")
	if _, err := time.ParseDuration(wait); err != nil {
		wait = "5m"
	}
	gw, err := gatewayPath()
	if err != nil {
		block("actiongate: cannot locate gateway; failing closed")
	}

	// #nosec G204 -- gw is the sibling gateway binary (or the operator's
	// explicit AG_HOOK_GATEWAY override); invoking it is this bridge's
	// entire purpose.
	cmd := exec.Command(gw, "check",
		"-agent", envOr("AG_HOOK_AGENT", "claude-code"),
		"-session", session,
		"-request-id", uuid.NewString(),
		"-tool", in.ToolName,
		"-params", params,
		"-wait", wait,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	// Prefer the structured verdict; fall back to exit code.
	var res checkResult
	_ = json.Unmarshal(stdout.Bytes(), &res)

	code := 0
	if ee, ok := runErr.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if runErr != nil {
		block("actiongate: control-plane check failed to run; failing closed")
	}

	switch code {
	case 0:
		os.Exit(0) // allowed — let Claude Code's normal flow continue
	case 2:
		reason := res.Explanation
		if reason == "" {
			reason = "denied by policy"
		}
		block(fmt.Sprintf("🛑 actiongate blocked this action: %s (rule %q)", reason, res.RuleID))
	case 3:
		block("⏳ actiongate: approval timed out — the action was not executed")
	default:
		block(fmt.Sprintf("actiongate: unexpected check exit %d; failing closed. %s", code, stderr.String()))
	}
}
