package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/muhammadusamahoyrr/actiongate/internal/dbruntime"
	"github.com/muhammadusamahoyrr/actiongate/internal/health"
)

// version is the ActionGate binary version. Overridable at build time via
// -ldflags "-X main.version=...".
var version = "dev"

// epochKeyID is the fixed signing key id the control plane uses (see
// internal/controlplane); the doctor uses it to validate sealed epochs.
const epochKeyID = "epoch-1"

// cmdDoctor runs an end-to-end health check and prints a human-readable report,
// exiting non-zero if anything is unhealthy. It is the single command to reach
// for when "it doesn't work".
func cmdDoctor(_ []string) int {
	path, err := devConfigPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "actiongate doctor:", err)
		return 1
	}
	cfg, err := loadDevConfigAt(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "actiongate doctor:", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fmt.Printf("ActionGate %s\n\n", version)

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot open database pool:", err)
		return 1
	}
	defer pool.Close()

	rep := health.Check(ctx, pool, health.Options{
		Version:     version,
		TenantID:    cfg.TenantID,
		EpochKeyIDs: []string{epochKeyID},
	})

	ok := true
	line := func(name string, c dbruntime.ComponentHealth) {
		ok = ok && c.Healthy
		fmt.Printf("%s %-16s %s\n", mark(c.Healthy), name, c.Message)
	}
	line("Database", rep.Database)
	line("Schema", rep.Schema)
	line("Tenant", rep.Tenant)
	line("Signing keys", rep.Keys)
	line("Sealer", rep.Sealer)

	// The control plane is a separate process; report it directly so a running
	// service whose HTTP endpoint is not answering is diagnosed here.
	cpHealthy := healthy(ctx, cfg.ServerURL)
	cpMsg := "answering at " + cfg.ServerURL
	if !cpHealthy {
		cpMsg = "not answering at " + cfg.ServerURL + " — hooked projects fail closed"
	}
	ok = ok && cpHealthy
	fmt.Printf("%s %-16s %s\n", mark(cpHealthy), "Control plane", cpMsg)

	fmt.Println()
	if ok {
		fmt.Println("Everything healthy.")
		return 0
	}
	fmt.Println("Some checks failed — see the ✖ lines above.")
	return 1
}

func mark(ok bool) string {
	if ok {
		return "✔"
	}
	return "✖"
}
