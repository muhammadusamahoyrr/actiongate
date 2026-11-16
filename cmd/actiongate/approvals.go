package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/muhammadusamahoyrr/actiongate/internal/approval"
	"github.com/muhammadusamahoyrr/actiongate/internal/preview"
)

// Local approvals (audit H10): without Slack, a requires_approval rule used
// to time out every time — the callback token was never shown anywhere.
// `actiongate approvals` lists what is waiting and resolves it through the
// control plane's normal callback, re-deriving the token from the token
// secret (internal/approval), so the decision is recorded exactly like a
// Slack click.
//
// The governed agent must not use it on its own held action:
//   - the engine denies any agent action that runs `actiongate approvals
//     approve|deny` or calls /approval/callback (facts.self_approval);
//   - approve/deny refuse to run without an interactive terminal and ask
//     for confirmation — an agent's tool calls have no console.
//
// Neither layer stops an agent running as a different, more privileged
// OS user than the person approving; run the agent as a standard user.

type pendingApproval struct {
	ID         uuid.UUID
	ActionID   uuid.UUID
	Created    time.Time
	Expires    time.Time
	Target     string
	Tool       string
	Agent      string
	ToolParams map[string]any
}

func cmdApprovals(args []string) int {
	sub := "list"
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "list", "ls":
		return approvalsList()
	case "approve", "deny":
		return approvalsResolve(sub, args)
	default:
		fmt.Fprintln(os.Stderr, "usage: actiongate approvals [list] | approve <id> [-reason TEXT] | deny <id> [-reason TEXT]")
		return 1
	}
}

func approvalsContext() (*devConfig, *pgxpool.Pool, uuid.UUID, error) {
	path, err := devConfigPath()
	if err != nil {
		return nil, nil, uuid.Nil, err
	}
	cfg, err := loadDevConfigAt(path)
	if err != nil {
		return nil, nil, uuid.Nil, err
	}
	tenant, err := uuid.Parse(cfg.TenantID)
	if err != nil {
		return nil, nil, uuid.Nil, fmt.Errorf("dev config has no tenant — run `actiongate up` first")
	}
	pool, err := pgxpool.New(context.Background(), cfg.DatabaseURL)
	if err != nil {
		return nil, nil, uuid.Nil, err
	}
	return cfg, pool, tenant, nil
}

func loadPending(ctx context.Context, pool *pgxpool.Pool, tenant uuid.UUID) ([]pendingApproval, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("database unreachable — is the control plane running? %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `select set_config('app.tenant_id', $1, true)`, tenant.String()); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx,
		`select a.id, a.action_request_id, a.created_at, a.expires_at, a.approver_target,
		        r.tool_name, r.agent_id, r.tool_params
		   from approval_requests a
		   join action_requests r on r.id = a.action_request_id
		  where a.tenant_id = $1 and a.status = 'pending' and a.expires_at > now()
		  order by a.created_at`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []pendingApproval
	for rows.Next() {
		var p pendingApproval
		var raw []byte
		if err := rows.Scan(&p.ID, &p.ActionID, &p.Created, &p.Expires, &p.Target, &p.Tool, &p.Agent, &raw); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(raw, &p.ToolParams)
		out = append(out, p)
	}
	return out, rows.Err()
}

func approvalsList() int {
	_, pool, tenant, err := approvalsContext()
	if err != nil {
		fmt.Fprintln(os.Stderr, "approvals:", err)
		return 1
	}
	defer pool.Close()
	pending, err := loadPending(context.Background(), pool, tenant)
	if err != nil {
		fmt.Fprintln(os.Stderr, "approvals:", err)
		return 1
	}
	if len(pending) == 0 {
		fmt.Println("No actions are waiting for approval.")
		return 0
	}
	for _, p := range pending {
		fmt.Printf("%s  %s by %s · waiting %s · expires in %s\n    %s\n\n",
			shortID(p.ID), p.Tool, p.Agent,
			time.Since(p.Created).Round(time.Second), time.Until(p.Expires).Round(time.Second),
			strings.ReplaceAll(preview.Action(p.Tool, p.ToolParams), "\n", "\n    "))
	}
	fmt.Println("Resolve one with:  actiongate approvals approve <id>   or   actiongate approvals deny <id>")
	return 0
}

func approvalsResolve(decision string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: actiongate approvals %s <id> [-reason TEXT]\n", decision)
		return 1
	}
	prefix, reason := args[0], ""
	for i := 1; i < len(args); i++ {
		if (args[i] == "-reason" || args[i] == "--reason") && i+1 < len(args) {
			reason = args[i+1]
			i++
		}
	}
	// A person, at a console. An agent's tool calls have no console, so
	// this also stops the governed agent approving its own action.
	if !isInteractiveConsole() {
		fmt.Fprintln(os.Stderr, "approvals: approving or denying needs an interactive terminal (it cannot be scripted or run by an agent)")
		return 1
	}

	cfg, pool, tenant, err := approvalsContext()
	if err != nil {
		fmt.Fprintln(os.Stderr, "approvals:", err)
		return 1
	}
	defer pool.Close()
	pending, err := loadPending(context.Background(), pool, tenant)
	if err != nil {
		fmt.Fprintln(os.Stderr, "approvals:", err)
		return 1
	}
	target, err := pickApproval(pending, prefix)
	if err != nil {
		fmt.Fprintln(os.Stderr, "approvals:", err)
		return 1
	}

	verb := map[string]string{"approve": "APPROVE", "deny": "DENY"}[decision]
	fmt.Printf("%s %s by %s:\n    %s\n%s this action? [y/N] ", shortID(target.ID), target.Tool, target.Agent,
		strings.ReplaceAll(preview.Action(target.Tool, target.ToolParams), "\n", "\n    "), verb)
	answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
		fmt.Println("Nothing changed.")
		return 1
	}

	token, err := (&approval.Service{TokenSecret: []byte(cfg.TokenSecret)}).CallbackToken(tenant, target.ID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "approvals:", err)
		return 1
	}
	approver := "local"
	if u, err := user.Current(); err == nil {
		approver = "local:" + u.Username
	}
	d := map[string]string{"approve": "approved", "deny": "denied"}[decision]
	if err := postCallback(cfg.ServerURL, token, d, approver, reason); err != nil {
		fmt.Fprintln(os.Stderr, "approvals:", err)
		return 1
	}
	fmt.Printf("%s: %s (recorded as approver %q)\n", shortID(target.ID), d, approver)
	return 0
}

// pickApproval resolves an id or unique id prefix among pending approvals.
func pickApproval(pending []pendingApproval, prefix string) (pendingApproval, error) {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	if len(prefix) < 4 {
		return pendingApproval{}, errors.New("give at least 4 characters of the id (see `actiongate approvals list`)")
	}
	var matches []pendingApproval
	for _, p := range pending {
		if strings.HasPrefix(p.ID.String(), prefix) || strings.HasPrefix(shortID(p.ID), prefix) {
			matches = append(matches, p)
		}
	}
	switch len(matches) {
	case 0:
		return pendingApproval{}, fmt.Errorf("no pending approval matches %q (expired or already resolved?)", prefix)
	case 1:
		return matches[0], nil
	}
	return pendingApproval{}, fmt.Errorf("%q matches %d pending approvals; give more of the id", prefix, len(matches))
}

// shortID is the distinguishing tail of a UUIDv7 (its head is a timestamp
// shared by approvals made close together).
func shortID(id uuid.UUID) string {
	s := strings.ReplaceAll(id.String(), "-", "")
	return s[len(s)-10:]
}

func postCallback(serverURL, token, decision, approver, reason string) error {
	body, _ := json.Marshal(map[string]string{"token": token, "decision": decision, "approver_id": approver, "reason": reason})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/approval/callback", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("control plane unreachable at %s: %w", serverURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("control plane refused (%s): %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}
