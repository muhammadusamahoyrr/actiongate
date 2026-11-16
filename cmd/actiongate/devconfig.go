package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/muhammadusamahoyrr/actiongate/internal/fsutil"

	"github.com/muhammadusamahoyrr/actiongate/internal/controlplane"
)

// devConfig is the persisted local-development environment written by
// `actiongate up`: connection details and the signing-key seeds, so restarts
// keep the same keys (grants stay verifiable, sealed epochs stay checkable).
// It lives next to gateway.json in the user config dir, mode 0600 — these
// are real secrets for the local instance, even in dev.
type devConfig struct {
	DatabaseURL string `json:"database_url"`
	// DBPort and DBPassword persist the managed embedded PostgreSQL identity so
	// every start reuses the same port and credentials (see internal/dbruntime).
	DBPort     int    `json:"db_port,omitempty"`
	DBPassword string `json:"db_password,omitempty"`
	// AppDBPassword and SealerDBPassword are the least-privilege roles the
	// control plane runs as (internal/dbroles); DatabaseURL/DBPassword stay
	// the owning superuser, used only for migrations and administration.
	AppDBPassword    string `json:"app_db_password,omitempty"`
	SealerDBPassword string `json:"sealer_db_password,omitempty"`
	Listen           string `json:"listen"`
	ServerURL        string `json:"server_url"`
	TokenSecret      string `json:"token_secret"`
	GrantKeySeed     string `json:"grant_key_seed"` // base64 32 bytes
	EpochKeySeed     string `json:"epoch_key_seed"` // base64 32 bytes
	// GrantKeyID / EpochKeyID name the keys; empty means the defaults
	// ("grant-1", "epoch-1"). Set a new id when rotating a seed.
	GrantKeyID string `json:"grant_key_id,omitempty"`
	EpochKeyID string `json:"epoch_key_id,omitempty"`
	// EpochRetiredKeyIDs: earlier epoch key ids, kept after a rotation.
	EpochRetiredKeyIDs []string `json:"epoch_retired_key_ids,omitempty"`
	TenantID           string   `json:"tenant_id,omitempty"`

	// Optional Slack approvals. Set here (not env) so the Windows service —
	// which never sees your shell environment — picks them up too.
	SlackBotToken      string `json:"slack_bot_token,omitempty"`
	SlackSigningSecret string `json:"slack_signing_secret,omitempty"`
	SlackChannel       string `json:"slack_channel,omitempty"`
	// SlackApprovers are the Slack user ids allowed to approve; empty means
	// anyone who can click in the channel.
	SlackApprovers []string `json:"slack_approvers,omitempty"`
}

func devConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "actiongate", "dev.json"), nil
}

// loadOrInitDevConfig reads the saved environment or creates one with fresh
// random secrets. Missing fields on an existing file (older versions) are
// filled in and saved back.
//
// It runs under the dev.json lock: two first runs at once (`actiongate up`
// racing the service) must agree on one set of secrets, not each generate
// their own and let the last save win.
func loadOrInitDevConfig() (*devConfig, string, error) {
	path, err := devConfigPath()
	if err != nil {
		return nil, "", err
	}
	cfg := &devConfig{}
	err = fsutil.WithLock(path, func() error {
		disk, err := readDevConfig(path)
		if err != nil {
			return err
		}
		if disk != nil {
			cfg = disk
		}
		if fillDevDefaults(cfg) {
			return writeDevConfig(cfg, path)
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return cfg, path, nil
}

// fillDevDefaults sets every missing field and reports whether it changed
// anything.
func fillDevDefaults(cfg *devConfig) bool {
	changed := false
	set := func(field *string, value func() string) {
		if *field == "" {
			*field = value()
			changed = true
		}
	}
	set(&cfg.DatabaseURL, func() string { return "postgres://ag:ag@localhost:5432/actiongate?sslmode=disable" })
	set(&cfg.Listen, func() string { return "127.0.0.1:8091" })
	set(&cfg.ServerURL, func() string { return "http://localhost:8091" })
	set(&cfg.TokenSecret, func() string { return randomB64(32) })
	set(&cfg.GrantKeySeed, func() string { return randomB64(32) })
	set(&cfg.EpochKeySeed, func() string { return randomB64(32) })
	return changed
}

// updateDevConfig changes dev.json without losing another process's
// update. Under the dev.json lock it re-reads the file, lets fn change the
// fresh copy (fn returns whether it changed anything), and writes it back.
// On success *mem is replaced with what is on disk, so the caller also sees
// fields other processes set (and keeps theirs when fn defers to them).
//
// Never save a long-held in-memory copy with a plain write: that silently
// reverts whatever changed on disk since it was loaded.
func updateDevConfig(path string, mem *devConfig, fn func(c *devConfig) (bool, error)) error {
	return fsutil.WithLock(path, func() error {
		cur, err := readDevConfig(path)
		if err != nil {
			return err
		}
		if cur == nil {
			copied := *mem
			cur = &copied
		}
		changed, err := fn(cur)
		if err != nil {
			return err
		}
		if changed {
			if err := writeDevConfig(cur, path); err != nil {
				return err
			}
		}
		*mem = *cur
		return nil
	})
}

// readDevConfig returns the parsed file, or nil if it does not exist.
func readDevConfig(path string) (*devConfig, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	cfg := &devConfig{}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("corrupt dev config %s: %w", path, err)
	}
	return cfg, nil
}

// writeDevConfig assumes the caller holds the dev.json lock.
func writeDevConfig(cfg *devConfig, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("config dir: %w", err)
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, raw, 0o600)
}

func (c *devConfig) seed(encoded string) ([]byte, error) {
	seed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(seed) != 32 {
		return nil, fmt.Errorf("corrupt key seed in dev config")
	}
	return seed, nil
}

// loadDevConfigAt strictly loads an existing dev config (no defaults, no
// creation) — the service reads the installing user's config by explicit
// path and must never invent one somewhere else.
func loadDevConfigAt(path string) (*devConfig, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	cfg := &devConfig{}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("corrupt dev config %s: %w", path, err)
	}
	if cfg.DatabaseURL == "" || cfg.TokenSecret == "" || cfg.GrantKeySeed == "" || cfg.EpochKeySeed == "" {
		return nil, fmt.Errorf("dev config %s is incomplete — run `actiongate up` once first", path)
	}
	return cfg, nil
}

// epochPublicKeyB64 derives the epoch verification key shown in the
// `verify` hint — the public half of the seed the Sealer signs with.
func (c *devConfig) epochPublicKeyB64() (string, error) {
	seed, err := c.seed(c.EpochKeySeed)
	if err != nil {
		return "", err
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	return base64.StdEncoding.EncodeToString(pub), nil
}

func randomB64(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("randomness unavailable: %v", err))
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// redactURL hides the password in a database URL before it is printed.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(unparseable database URL)"
	}
	return u.Redacted()
}

// epochKeyID is the epoch signing key id in use.
func (c *devConfig) epochKeyID() string {
	if c.EpochKeyID != "" {
		return c.EpochKeyID
	}
	return controlplane.DefaultEpochKeyID
}
