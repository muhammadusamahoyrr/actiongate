// The customer-side gateway CLI (plan §2). V1 surface:
//
//	gateway enroll -server URL -token TOK [-name NAME] [-state PATH]
//	gateway check  -agent A -session S -request-id R -tool T -params JSON
//	               [-env E] [-wait 10m] [-state PATH]
//	gateway report -action ID -status success|failure|partial [-error MSG]
//	               [-state PATH]
//	gateway mcp    [-agent A] [-env E] [-wait 10m] [-state PATH] -- CMD [ARGS...]
//
// check exits 0 when the action is authorized (grant verified locally),
// 2 when denied (explanation on stderr), 3 on decision timeout, 1 on error —
// the contract agent hooks (e.g. Claude Code PreToolUse) build on. report is
// the PostToolUse half. mcp wraps a downstream MCP server: point the agent's
// config at `gateway mcp -- <original command>` and every tool call routes
// through the control plane (plan §21.2 auto-wrap).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/muhammadusamahoyrr/actiongate/internal/gateway"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: gateway <enroll|check|report> [flags]")
		return 1
	}
	ctx := context.Background()
	switch args[0] {
	case "enroll":
		return cmdEnroll(ctx, args[1:])
	case "check":
		return cmdCheck(ctx, args[1:])
	case "report":
		return cmdReport(ctx, args[1:])
	case "mcp":
		return cmdMCP(ctx, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		return 1
	}
}

func statePath(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	return gateway.DefaultStatePath()
}

func cmdEnroll(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	server := fs.String("server", "", "control plane URL (required)")
	token := fs.String("token", "", "enrollment token (required)")
	name := fs.String("name", "gateway", "gateway name")
	stateFlag := fs.String("state", "", "state file path")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *server == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "enroll: -server and -token are required")
		return 1
	}
	path, err := statePath(*stateFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "enroll:", err)
		return 1
	}
	state, err := gateway.Enroll(ctx, nil, *server, *token, *name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "enroll:", err)
		return 1
	}
	if err := state.Save(path); err != nil {
		fmt.Fprintln(os.Stderr, "enroll: save state:", err)
		return 1
	}
	fmt.Printf("enrolled as %s (tenant %s); state: %s\n", state.GatewayID, state.TenantID, path)
	return 0
}

func loadGateway(stateFlag string) (*gateway.Gateway, string, error) {
	path, err := statePath(stateFlag)
	if err != nil {
		return nil, "", err
	}
	state, err := gateway.LoadState(path)
	if err != nil {
		return nil, "", fmt.Errorf("load state (run `gateway enroll` first?): %w", err)
	}
	return &gateway.Gateway{State: state}, path, nil
}

func cmdCheck(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	agent := fs.String("agent", "", "agent id (required)")
	session := fs.String("session", "", "session uuid (required)")
	requestID := fs.String("request-id", "", "native request id (required)")
	tool := fs.String("tool", "", "tool name (required)")
	paramsJSON := fs.String("params", "{}", "tool params as JSON object")
	env := fs.String("env", "default", "environment")
	wait := fs.Duration("wait", 10*time.Minute, "how long to wait for a decision")
	stateFlag := fs.String("state", "", "state file path")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *agent == "" || *session == "" || *requestID == "" || *tool == "" {
		fmt.Fprintln(os.Stderr, "check: -agent, -session, -request-id, and -tool are required")
		return 1
	}
	var params map[string]any
	if err := json.Unmarshal([]byte(*paramsJSON), &params); err != nil {
		fmt.Fprintln(os.Stderr, "check: -params:", err)
		return 1
	}
	gw, path, err := loadGateway(*stateFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "check:", err)
		return 1
	}

	res, err := gw.Check(ctx, gateway.CheckInput{
		AgentID: *agent, SessionID: *session, NativeRequestID: *requestID,
		ToolName: *tool, Params: params, Environment: *env, Wait: *wait,
	})
	// Persist the pending receipt regardless of outcome shape.
	if saveErr := gw.State.Save(path); saveErr != nil {
		fmt.Fprintln(os.Stderr, "check: save state:", saveErr)
	}
	out, _ := json.Marshal(res)
	fmt.Println(string(out))
	switch {
	case err == nil:
		return 0
	case errors.Is(err, gateway.ErrDenied):
		fmt.Fprintln(os.Stderr, "denied:", res.Explanation)
		return 2
	case errors.Is(err, gateway.ErrTimedOut):
		fmt.Fprintln(os.Stderr, "timed out waiting for a decision")
		return 3
	default:
		fmt.Fprintln(os.Stderr, "check:", err)
		return 1
	}
}

func cmdReport(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	action := fs.String("action", "", "action id from check (required)")
	status := fs.String("status", "", "success|failure|partial (required)")
	errMsg := fs.String("error", "", "error message, if any")
	outputRef := fs.String("output-ref", "", "reference to output stored elsewhere")
	stateFlag := fs.String("state", "", "state file path")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *action == "" || *status == "" {
		fmt.Fprintln(os.Stderr, "report: -action and -status are required")
		return 1
	}
	gw, path, err := loadGateway(*stateFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "report:", err)
		return 1
	}
	res, err := gw.Report(ctx, gateway.ReportInput{
		ActionID: *action, Status: *status, Error: *errMsg, OutputRef: *outputRef,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "report:", err)
		return 1
	}
	if err := gw.State.Save(path); err != nil {
		fmt.Fprintln(os.Stderr, "report: save state:", err)
	}
	out, _ := json.Marshal(res)
	fmt.Println(string(out))
	return 0
}

func cmdMCP(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	agent := fs.String("agent", "mcp-agent", "agent id reported to the control plane")
	env := fs.String("env", "default", "environment")
	wait := fs.Duration("wait", 10*time.Minute, "how long a tool call may wait for approval")
	stateFlag := fs.String("state", "", "state file path")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	rest := fs.Args()
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "mcp: downstream server command required after --")
		return 1
	}
	gw, path, err := loadGateway(*stateFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcp:", err)
		return 1
	}
	// stdout is the MCP channel; everything else goes to stderr.
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	proxy := &gateway.MCPProxy{
		Gateway: gw, AgentID: *agent, Environment: *env, Wait: *wait, Logger: logger,
	}
	// #nosec G204 -- the downstream command is the user's own MCP server,
	// given explicitly on the command line; running it is this command's job.
	downstream := &mcp.CommandTransport{Command: exec.CommandContext(ctx, rest[0], rest[1:]...)}
	err = proxy.Run(ctx, &mcp.StdioTransport{}, downstream)
	if saveErr := gw.State.Save(path); saveErr != nil {
		fmt.Fprintln(os.Stderr, "mcp: save state:", saveErr)
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "mcp:", err)
		return 1
	}
	return 0
}
