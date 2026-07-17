package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/muhammadusamahoyrr/actiongate/internal/domain"
	"github.com/muhammadusamahoyrr/actiongate/internal/servertest"
	"github.com/muhammadusamahoyrr/actiongate/internal/transition"
)

// fakeDownstream is the wrapped MCP server: it counts invocations so tests
// can prove denied calls never reach it.
type fakeDownstream struct {
	bashCalls atomic.Int64
	readCalls atomic.Int64
}

func (f *fakeDownstream) server() *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "fake-tools", Version: "0.0.1"}, nil)
	objectSchema := json.RawMessage(`{"type":"object"}`)
	srv.AddTool(&mcp.Tool{Name: "bash", Description: "run a command", InputSchema: objectSchema},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			f.bashCalls.Add(1)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ran"}}}, nil
		})
	srv.AddTool(&mcp.Tool{Name: "read_file", Description: "read a file", InputSchema: objectSchema},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			f.readCalls.Add(1)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "contents"}}}, nil
		})
	return srv
}

// startProxy wires downstream server ← proxy ← agent client over in-memory
// transports and returns the agent's session.
func startProxy(t *testing.T, stack *servertest.Stack, wait time.Duration) (*mcp.ClientSession, *fakeDownstream) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	fake := &fakeDownstream{}
	dsServerT, dsClientT := mcp.NewInMemoryTransports()
	if _, err := fake.server().Connect(ctx, dsServerT, nil); err != nil {
		t.Fatalf("connect fake downstream: %v", err)
	}

	gw := enrolledGateway(t, stack)
	proxy := &MCPProxy{Gateway: gw, AgentID: "proxied-agent", Environment: "test", Wait: wait}

	proxyServerT, agentT := mcp.NewInMemoryTransports()
	proxyErr := make(chan error, 1)
	go func() { proxyErr <- proxy.Run(ctx, proxyServerT, dsClientT) }()

	agent := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0.0.1"}, nil)
	var session *mcp.ClientSession
	deadline := time.Now().Add(10 * time.Second)
	for {
		var err error
		session, err = agent.Connect(ctx, agentT, nil)
		if err == nil {
			break
		}
		select {
		case perr := <-proxyErr:
			t.Fatalf("proxy exited: %v", perr)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent could not connect to proxy: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session, fake
}

func textOf(res *mcp.CallToolResult) string {
	var parts []string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, tc.Text)
		}
	}
	return strings.Join(parts, "\n")
}

func newestActionState(t *testing.T, stack *servertest.Stack, tool string) domain.State {
	t.Helper()
	ctx := context.Background()
	var actionID uuid.UUID
	err := stack.Pool.QueryRow(ctx,
		`select id from action_requests
		  where tenant_id = $1 and tool_name = $2
		  order by created_at desc limit 1`,
		stack.TenantID, tool).Scan(&actionID)
	if err != nil {
		t.Fatalf("find action: %v", err)
	}
	state, _, err := transition.CurrentState(ctx, stack.Pool, stack.TenantID, actionID)
	if err != nil {
		t.Fatalf("CurrentState: %v", err)
	}
	return state
}

func TestMCPProxy(t *testing.T) {
	stack := servertest.Setup(t)
	ctx := context.Background()
	session, fake := startProxy(t, stack, 20*time.Second)

	t.Run("downstream tools are mirrored", func(t *testing.T) {
		tools, err := session.ListTools(ctx, &mcp.ListToolsParams{})
		if err != nil {
			t.Fatalf("ListTools: %v", err)
		}
		names := map[string]bool{}
		for _, tool := range tools.Tools {
			names[tool.Name] = true
		}
		if !names["bash"] || !names["read_file"] {
			t.Fatalf("tools = %v", names)
		}
	})

	t.Run("allowed call executes downstream and lands Succeeded", func(t *testing.T) {
		res, err := session.CallTool(ctx, &mcp.CallToolParams{
			Name: "bash", Arguments: map[string]any{"command": "ls"},
		})
		if err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if res.IsError {
			t.Fatalf("unexpected error result: %s", textOf(res))
		}
		if textOf(res) != "ran" {
			t.Fatalf("downstream output lost: %q", textOf(res))
		}
		if fake.bashCalls.Load() != 1 {
			t.Fatalf("bash calls = %d, want 1", fake.bashCalls.Load())
		}
		if state := newestActionState(t, stack, "bash"); state != domain.StateSucceeded {
			t.Fatalf("control plane state = %s, want Succeeded", state)
		}
	})

	t.Run("denied call never reaches downstream", func(t *testing.T) {
		res, err := session.CallTool(ctx, &mcp.CallToolParams{
			Name: "read_file", Arguments: map[string]any{"path": "/app/.env"},
		})
		if err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if !res.IsError {
			t.Fatal("denied call returned a non-error result")
		}
		if !strings.Contains(textOf(res), "actiongate") {
			t.Fatalf("refusal not attributed: %q", textOf(res))
		}
		if fake.readCalls.Load() != 0 {
			t.Fatalf("denied call reached downstream %d times", fake.readCalls.Load())
		}
		if state := newestActionState(t, stack, "read_file"); state != domain.StateDenied {
			t.Fatalf("control plane state = %s, want Denied", state)
		}
	})

	t.Run("approval-gated call blocks, then executes after a human approves", func(t *testing.T) {
		before := fake.bashCalls.Load()
		type outcome struct {
			res *mcp.CallToolResult
			err error
		}
		done := make(chan outcome, 1)
		go func() {
			res, err := session.CallTool(ctx, &mcp.CallToolParams{
				Name: "bash", Arguments: map[string]any{"command": "rm -rf /tmp/x"},
			})
			done <- outcome{res, err}
		}()

		approveViaCallback(t, stack, "")

		select {
		case o := <-done:
			if o.err != nil {
				t.Fatalf("CallTool: %v", o.err)
			}
			if o.res.IsError {
				t.Fatalf("approved call errored: %s", textOf(o.res))
			}
			if fake.bashCalls.Load() != before+1 {
				t.Fatalf("bash calls = %d, want %d", fake.bashCalls.Load(), before+1)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("approved call never completed")
		}
	})
}
