// ag-hook bridges Claude Code's PreToolUse hook to actiongate. Claude Code
// runs it before every matched built-in tool call (Read/Edit/Write/Bash/…),
// passing the call as JSON on stdin. We turn that into a `gateway check` and
// translate the verdict back into Claude Code's hook contract:
//
//	allowed            -> exit 0, no output   (Claude Code proceeds normally;
//	                      gateway warnings go to stderr and ag-hook.log)
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
//
// With -locked (the admin-installed managed hook), AG_HOOK_AGENT and
// AG_HOOK_GATEWAY are ignored and the gateway state path comes from the OS
// profile, because the governed agent can set hook env vars via settings.
package main

import (
	"bytes"
	"context"
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

const (
	// maxWait + checkSlack must stay below the hook timeout that
	// `actiongate protect` installs (hookTimeoutSecs = 360).
	maxWait    = 5*time.Minute + 15*time.Second
	checkSlack = 30 * time.Second
)

type hookInput struct {
	SessionID string          `json:"session_id"`
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
	// Cwd is the session's working directory: scripts a command runs are
	// read from here so their text can be judged (write-then-run).
	Cwd string `json:"cwd"`
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

// maxHookLog bounds ag-hook.log; past it the log is rotated to .1.
const maxHookLog = 1 << 20

// recordWarning surfaces a non-blocking gateway warning: on stderr (Claude
// Code shows a successful hook's stderr in its transcript view) and appended
// to ag-hook.log in the actiongate config dir, so it survives the session.
// It never fails the hook: the action was allowed.
func recordWarning(msg string) {
	fmt.Fprintln(os.Stderr, "actiongate warning:", msg)
	dir, err := os.UserConfigDir()
	if err != nil {
		return
	}
	path := filepath.Join(dir, "actiongate", "ag-hook.log")
	if fi, err := os.Stat(path); err == nil && fi.Size() > maxHookLog {
		_ = os.Rename(path, path+".1")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = fmt.Fprintf(f, "%s %s\n", time.Now().UTC().Format(time.RFC3339), strings.ReplaceAll(msg, "\n", " | "))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// overridable is envOr for settings that change WHO is governed or BY
// WHAT: ignored when locked.
func overridable(key, fallback string) string {
	if locked {
		return fallback
	}
	return envOr(key, fallback)
}

func gatewayPath() (string, error) {
	if p := os.Getenv("AG_HOOK_GATEWAY"); p != "" && !locked {
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

// locked is set by -locked, which `actiongate protect -managed` puts in the
// admin-owned managed hook. Claude Code settings can set environment
// variables for hooks, so the governed agent could point AG_HOOK_GATEWAY at
// a no-op or APPDATA at a forged gateway state. Locked, ag-hook ignores
// those overrides: the gateway is always the sibling binary (admin-only
// install dir) and the state path comes from the OS profile, not env.
var locked bool

func main() {
	warnMode := false
	for _, a := range os.Args[1:] {
		switch a {
		case "-warn":
			warnMode = true
		case "-locked":
			locked = true
		}
	}
	if warnMode {
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

	// Claude Code kills a hook that outlives its timeout (360s, set by
	// `actiongate protect`), and a killed hook does NOT block the tool call.
	// So the approval wait is capped below that, and the gateway gets a hard
	// deadline: running out of time must end in exit 2, never in a kill.
	waitDur, err := time.ParseDuration(envOr("AG_HOOK_WAIT", "5m"))
	if err != nil || waitDur <= 0 {
		waitDur = 5 * time.Minute
	}
	if waitDur > maxWait {
		waitDur = maxWait
	}
	wait := waitDur.String()
	gw, err := gatewayPath()
	if err != nil {
		block("actiongate: cannot locate gateway; failing closed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), waitDur+checkSlack)
	defer cancel()
	checkArgs := []string{"check",
		"-agent", overridable("AG_HOOK_AGENT", "claude-code"),
		"-session", session,
		"-request-id", uuid.NewString(),
		"-tool", in.ToolName,
		"-params", "-", // on stdin: a Write of a large file exceeds the OS argument limit
		"-wait", wait,
	}
	if in.Cwd != "" {
		checkArgs = append(checkArgs, "-cwd", in.Cwd)
	}
	if locked {
		state, err := profileStatePath()
		if err != nil {
			block("actiongate: cannot locate the gateway state from the OS profile; failing closed")
		}
		checkArgs = append(checkArgs, "-state", state)
	}
	// #nosec G204 -- gw is the sibling gateway binary (or, unlocked, the
	// operator's explicit AG_HOOK_GATEWAY override); invoking it is this
	// bridge's entire purpose.
	cmd := exec.CommandContext(ctx, gw, checkArgs...)
	cmd.Stdin = strings.NewReader(params)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	// Prefer the structured verdict; fall back to exit code.
	var res checkResult
	_ = json.Unmarshal(stdout.Bytes(), &res)

	if ctx.Err() != nil {
		block("actiongate: control-plane check timed out; failing closed")
	}
	code := 0
	if ee, ok := runErr.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if runErr != nil {
		block("actiongate: control-plane check failed to run; failing closed")
	}

	switch code {
	case 0:
		// Allowed. Anything the gateway still wrote to stderr is a problem
		// that did not change the verdict — most importantly a failed state
		// save. Those used to be dropped here, which made them invisible.
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			recordWarning(msg)
		}
		os.Exit(0) // let Claude Code's normal flow continue
	case 2:
		reason := res.Explanation
		if reason == "" {
			reason = "denied by policy"
		}
		block(fmt.Sprintf("🛑 actiongate blocked this action: %s (rule %q)", reason, res.RuleID))
	case 3:
		block("⏳ actiongate: approval timed out — the action was not executed. " +
			"A human can approve held actions in Slack, or in a terminal with `actiongate approvals` " +
			"(the agent cannot approve its own).")
	default:
		block(fmt.Sprintf("actiongate: unexpected check exit %d; failing closed. %s", code, stderr.String()))
	}
}
