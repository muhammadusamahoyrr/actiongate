// Downstream MCP server for the live demo: a plain, unaware tool server.
// It exposes read_file and bash and just does what it's told. It has NO
// knowledge of actiongate — the whole point is that governance happens in
// the proxy in front of it, so a call it never receives can never run.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func args(req *mcp.CallToolRequest) map[string]any {
	m := map[string]any{}
	if len(req.Params.Arguments) > 0 {
		_ = json.Unmarshal(req.Params.Arguments, &m)
	}
	return m
}

func text(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

func main() {
	srv := mcp.NewServer(&mcp.Implementation{Name: "demo-tools", Version: "0.1.0"}, nil)
	objectSchema := json.RawMessage(`{"type":"object"}`)

	// read_file actually reads from disk. If actiongate ever lets a .env
	// path through, the secret leaks — so we can prove it doesn't.
	srv.AddTool(&mcp.Tool{Name: "read_file", Description: "read a file from disk", InputSchema: objectSchema},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			path, _ := args(req)["path"].(string)
			fmt.Fprintf(os.Stderr, "[downstream] read_file actually invoked for %q\n", path)
			// #nosec G304 -- deliberately unguarded: this demo server exists
			// to prove the gateway blocks bad paths before they reach it.
			b, err := os.ReadFile(path)
			if err != nil {
				return &mcp.CallToolResult{IsError: true,
					Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, nil
			}
			return text(string(b)), nil
		})

	// bash really runs the command (only reached for approved/allowed calls).
	srv.AddTool(&mcp.Tool{Name: "bash", Description: "run a shell command", InputSchema: objectSchema},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			cmd, _ := args(req)["command"].(string)
			fmt.Fprintf(os.Stderr, "[downstream] bash actually invoked: %q\n", cmd)
			// #nosec G204 -- deliberately unguarded, same reason as read_file.
			out, _ := exec.Command("bash", "-c", cmd).CombinedOutput()
			return text(fmt.Sprintf("ran %q -> %q", cmd, string(out))), nil
		})

	if err := srv.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintln(os.Stderr, "downstream:", err)
		os.Exit(1)
	}
}
