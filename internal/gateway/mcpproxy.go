package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// MCPProxy is the auto-wrap enforcement point (plan §21.2): it exposes a
// downstream MCP server's tools unchanged, but every tools/call routes
// through the control plane first and executes only under a verified grant.
// The agent needs zero code changes — its config points at the proxy
// instead of the original server.
//
// Enforcement rules:
//   - Denied, timed out, or errored checks NEVER reach the downstream
//     server (fail closed).
//   - Outcomes are reported from what the downstream actually returned; a
//     failed receipt delivery is logged and left to the outcome-deadline
//     timer, which marks the action OutcomeUnknown — the honest fallback.
type MCPProxy struct {
	Gateway     *Gateway
	AgentID     string
	Environment string
	// Wait bounds how long a tool call may block on a human approval.
	Wait   time.Duration
	Logger *slog.Logger
}

func (p *MCPProxy) logger() *slog.Logger {
	if p.Logger != nil {
		return p.Logger
	}
	return slog.Default()
}

func (p *MCPProxy) wait() time.Duration {
	if p.Wait > 0 {
		return p.Wait
	}
	return 10 * time.Minute
}

// Run connects to the downstream server, mirrors its tools, and serves the
// wrapped surface until the agent disconnects or ctx ends.
func (p *MCPProxy) Run(ctx context.Context, serverTransport, downstreamTransport mcp.Transport) error {
	client := mcp.NewClient(&mcp.Implementation{Name: "actiongate-gateway", Version: "0.1.0"}, nil)
	down, err := client.Connect(ctx, downstreamTransport, nil)
	if err != nil {
		return fmt.Errorf("connect downstream: %w", err)
	}
	defer func() { _ = down.Close() }()

	server := mcp.NewServer(&mcp.Implementation{Name: "actiongate-gateway", Version: "0.1.0"}, nil)
	sessionID := uuid.NewString()

	var cursor string
	mirrored := 0
	for {
		page, err := down.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return fmt.Errorf("list downstream tools: %w", err)
		}
		for _, tool := range page.Tools {
			server.AddTool(tool, p.handler(down, sessionID, tool.Name))
			mirrored++
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	p.logger().Info("actiongate mcp proxy serving", "tools", mirrored, "session", sessionID)
	return server.Run(ctx, serverTransport)
}

func (p *MCPProxy) handler(down *mcp.ClientSession, sessionID, toolName string) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		params := map[string]any{}
		if len(req.Params.Arguments) > 0 {
			if err := json.Unmarshal(req.Params.Arguments, &params); err != nil {
				return refusal(fmt.Sprintf("actiongate: arguments are not a JSON object: %v", err)), nil
			}
		}

		check, err := p.Gateway.Check(ctx, CheckInput{
			AgentID:         p.AgentID,
			SessionID:       sessionID,
			NativeRequestID: uuid.NewString(),
			ToolName:        toolName,
			Params:          params,
			Environment:     p.Environment,
			Wait:            p.wait(),
		})
		switch {
		case errors.Is(err, ErrDenied):
			explanation := check.Explanation
			if explanation == "" {
				explanation = "denied by policy"
			}
			return refusal("actiongate: " + explanation), nil
		case errors.Is(err, ErrTimedOut):
			return refusal("actiongate: approval timed out; the action was not executed"), nil
		case err != nil:
			// Fail closed: any uncertainty means no execution.
			p.logger().Error("check failed", "tool", toolName, "error", err)
			return refusal("actiongate: control plane check failed; the action was not executed"), nil
		}

		startedAt := time.Now()
		out, callErr := down.CallTool(ctx, &mcp.CallToolParams{
			Name:      toolName,
			Arguments: req.Params.Arguments,
		})

		report := ReportInput{
			ActionID:  check.ActionID,
			StartedAt: startedAt, CompletedAt: time.Now(),
		}
		switch {
		case callErr != nil:
			report.Status = "failure"
			report.Error = callErr.Error()
		case out.IsError:
			report.Status = "failure"
			report.Error = "downstream tool reported an error"
		default:
			report.Status = "success"
		}
		if _, reportErr := p.Gateway.Report(ctx, report); reportErr != nil {
			// The outcome-deadline timer will mark this OutcomeUnknown —
			// honest, and better than blocking the agent on retries here.
			p.logger().Error("outcome receipt failed", "action", check.ActionID, "error", reportErr)
		}

		if callErr != nil {
			return refusal(fmt.Sprintf("actiongate: downstream call failed: %v", callErr)), nil
		}
		return out, nil
	}
}

func refusal(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
}
