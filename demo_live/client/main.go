// The "agent": a plain MCP client. It does NOT talk to the downstream tool
// server directly — it connects to `gateway mcp -- <downstream>`, so every
// tool call it makes is transparently governed by actiongate policy.
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func textOf(res *mcp.CallToolResult) string {
	var parts []string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, tc.Text)
		}
	}
	return strings.Join(parts, "\n")
}

func line() { fmt.Println(strings.Repeat("-", 70)) }

func main() {
	ctx := context.Background()

	// Spawn the gateway proxy, which itself spawns the downstream server.
	// Agent -> gateway mcp -> downstream.  Config change = this one line.
	proxyCmd := exec.CommandContext(ctx,
		"bin/gateway.exe", "mcp", "-agent", "demo-agent", "-wait", "5m",
		"--", "bin/demo-downstream.exe")
	proxyCmd.Stderr = os.Stderr // surface gateway + downstream logs

	client := mcp.NewClient(&mcp.Implementation{Name: "demo-agent", Version: "0.1.0"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: proxyCmd}, nil)
	if err != nil {
		fmt.Println("connect:", err)
		os.Exit(1)
	}
	defer func() { _ = session.Close() }()

	// What tools does the agent see? The proxy mirrors them 1:1.
	line()
	fmt.Println("STEP 0  Agent connects through actiongate and lists tools")
	tools, _ := session.ListTools(ctx, &mcp.ListToolsParams{})
	for _, t := range tools.Tools {
		fmt.Printf("        • %s — %s\n", t.Name, t.Description)
	}

	// 1) Allowed: read a harmless file. Policy default is allow.
	line()
	fmt.Println("STEP 1  Agent calls read_file on demo_live/notes.txt  (harmless)")
	res, _ := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "read_file", Arguments: map[string]any{"path": "demo_live/notes.txt"}})
	fmt.Printf("        isError=%v\n        returned: %s\n", res.IsError, strings.TrimSpace(textOf(res)))

	// 2) Denied: read a secret. The proxy blocks it BEFORE the downstream
	//    server is ever called, so the secret never leaves disk.
	line()
	fmt.Println("STEP 2  Agent calls read_file on demo_live/secret.env  (secret!)")
	res, _ = session.CallTool(ctx, &mcp.CallToolParams{
		Name: "read_file", Arguments: map[string]any{"path": "demo_live/secret.env"}})
	fmt.Printf("        isError=%v\n        returned: %s\n", res.IsError, strings.TrimSpace(textOf(res)))
	fmt.Println("        ^ the agent got a policy refusal, NOT the API keys.")

	// 3) Gated: a destructive command. The call blocks until a human
	//    approves (Slack button, or the callback we hit from another shell).
	line()
	fmt.Println("STEP 3  Agent calls bash 'rm -rf /tmp/demo-x'  (destructive -> needs approval)")
	fmt.Printf("        %s  the tool call is now BLOCKED, waiting for a human...\n", time.Now().Format("15:04:05"))
	res, err = session.CallTool(ctx, &mcp.CallToolParams{
		Name: "bash", Arguments: map[string]any{"command": "rm -rf /tmp/demo-x"}})
	if err != nil {
		fmt.Println("        call error:", err)
		os.Exit(1)
	}
	fmt.Printf("        %s  UNBLOCKED. isError=%v\n        returned: %s\n",
		time.Now().Format("15:04:05"), res.IsError, strings.TrimSpace(textOf(res)))
	line()
	fmt.Println("DONE")
}
