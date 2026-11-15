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
	// The port and password are decided under the dev.json lock, against
	// the freshest file: two first starts at once (`up` racing the service)
	// must not each invent a password and leave the cluster initialised
	// with one while dev.json holds the other.
	dataDir := filepath.Join(filepath.Dir(cfgPath), "pgdata")
	var rt *dbruntime.Embedded
	err := updateDevConfig(cfgPath, cfg, func(c *devConfig) (bool, error) {
		changed := false
		if c.DBPassword == "" {
			pw, err := dbruntime.GeneratePassword()
			if err != nil {
				return false, err
			}
			c.DBPassword = pw
			changed = true
		}
		r, err := dbruntime.New(dbruntime.Config{
			DataPath: dataDir,
			Port:     uint32(c.DBPort), //nolint:gosec // G115: a DB port is bounded 0-65535

			Database: "actiongate",
			Username: "ag",
			Password: c.DBPassword,
			Version:  version,
		})
		if err != nil {
			return false, err
		}
		rt = r
		if c.DBPort == 0 {
			c.DBPort = int(r.Port())
			changed = true
		}
		// The managed cluster is the source of truth for DatabaseURL.
		if c.DatabaseURL != r.DSN() {
			c.DatabaseURL = r.DSN()
			changed = true
		}
		return changed, nil
	})
	if err != nil {
		return nil, err
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
