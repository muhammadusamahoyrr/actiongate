package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"actiongate/internal/admin"
)

// Admin subcommands (operator provisioning):
//
//	controlplane admin create-tenant -policy FILE
//	controlplane admin set-policy    -tenant ID -policy FILE
//	controlplane admin enroll-token  -tenant ID [-ttl 24h]
//
// All read AG_DATABASE_URL. Policy files are compiled before storage; a
// broken policy never lands.
func runAdmin(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: controlplane admin <create-tenant|set-policy|enroll-token> [flags]")
		return 1
	}
	databaseURL := os.Getenv("AG_DATABASE_URL")
	if databaseURL == "" {
		fmt.Fprintln(os.Stderr, "admin: AG_DATABASE_URL is required")
		return 1
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "admin: connect:", err)
		return 1
	}
	defer pool.Close()

	switch args[0] {
	case "create-tenant":
		fs := flag.NewFlagSet("create-tenant", flag.ContinueOnError)
		policyPath := fs.String("policy", "", "policy JSON file (required)")
		if err := fs.Parse(args[1:]); err != nil {
			return 1
		}
		policyJSON, err := readPolicy(*policyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "admin:", err)
			return 1
		}
		tenantID, err := admin.CreateTenant(ctx, pool, policyJSON)
		if err != nil {
			fmt.Fprintln(os.Stderr, "admin:", err)
			return 1
		}
		fmt.Println(tenantID)
		return 0

	case "set-policy":
		fs := flag.NewFlagSet("set-policy", flag.ContinueOnError)
		tenantFlag := fs.String("tenant", "", "tenant id (required)")
		policyPath := fs.String("policy", "", "policy JSON file (required)")
		if err := fs.Parse(args[1:]); err != nil {
			return 1
		}
		tenantID, err := uuid.Parse(*tenantFlag)
		if err != nil {
			fmt.Fprintln(os.Stderr, "admin: -tenant:", err)
			return 1
		}
		policyJSON, err := readPolicy(*policyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "admin:", err)
			return 1
		}
		version, err := admin.SetPolicy(ctx, pool, tenantID, policyJSON)
		if err != nil {
			fmt.Fprintln(os.Stderr, "admin:", err)
			return 1
		}
		fmt.Printf("policy version %d active\n", version)
		return 0

	case "enroll-token":
		fs := flag.NewFlagSet("enroll-token", flag.ContinueOnError)
		tenantFlag := fs.String("tenant", "", "tenant id (required)")
		ttl := fs.Duration("ttl", 24*time.Hour, "token validity")
		if err := fs.Parse(args[1:]); err != nil {
			return 1
		}
		tenantID, err := uuid.Parse(*tenantFlag)
		if err != nil {
			fmt.Fprintln(os.Stderr, "admin: -tenant:", err)
			return 1
		}
		token, err := admin.NewEnrollmentToken(ctx, pool, tenantID, *ttl)
		if err != nil {
			fmt.Fprintln(os.Stderr, "admin:", err)
			return 1
		}
		fmt.Println(token)
		fmt.Fprintln(os.Stderr, "single use; shown once — pass it to `gateway enroll -token`")
		return 0

	default:
		fmt.Fprintf(os.Stderr, "admin: unknown subcommand %q\n", args[0])
		return 1
	}
}

func readPolicy(path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("-policy is required")
	}
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	return raw, nil
}
