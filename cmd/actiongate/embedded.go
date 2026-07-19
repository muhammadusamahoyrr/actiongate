package main

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/muhammadusamahoyrr/actiongate/internal/dbruntime"
)

// startManagedDB brings up the managed embedded PostgreSQL cluster and points
// cfg.DatabaseURL at it. It replaces the old Docker container: no Docker, no
// admin PostgreSQL knowledge required.
//
// Returns the runtime to Stop on exit, or nil when the database was already
// running (e.g. started by the Windows service) — in that case the caller must
// not stop it. The port and password persist in dev.json so every start reuses
// the same identity.
func startManagedDB(ctx context.Context, cfg *devConfig, cfgPath string) (*dbruntime.Embedded, error) {
	changed := false
	if cfg.DBPassword == "" {
		pw, err := dbruntime.GeneratePassword()
		if err != nil {
			return nil, err
		}
		cfg.DBPassword = pw
		changed = true
	}

	dataDir := filepath.Join(filepath.Dir(cfgPath), "pgdata")
	rt, err := dbruntime.New(dbruntime.Config{
		DataPath: dataDir,
		Port:     uint32(cfg.DBPort), // 0 → probe a free port
		Database: "actiongate",
		Username: "ag",
		Password: cfg.DBPassword,
		Version:  version,
	})
	if err != nil {
		return nil, err
	}
	if cfg.DBPort == 0 {
		cfg.DBPort = int(rt.Port())
		changed = true
	}
	// The managed cluster is the source of truth for DatabaseURL.
	if cfg.DatabaseURL != rt.DSN() {
		cfg.DatabaseURL = rt.DSN()
		changed = true
	}
	if changed {
		if err := saveDevConfig(cfg, cfgPath); err != nil {
			return nil, err
		}
	}

	// Already up (another `actiongate up`, or the service)? Reuse it.
	if pingOnce(ctx, cfg.DatabaseURL) == nil {
		return nil, nil
	}
	if err := rt.Start(ctx); err != nil {
		return nil, fmt.Errorf("start embedded postgres: %w", err)
	}
	return rt, nil
}
