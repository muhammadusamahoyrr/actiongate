package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	DBPort       int    `json:"db_port,omitempty"`
	DBPassword   string `json:"db_password,omitempty"`
	Listen       string `json:"listen"`
	ServerURL    string `json:"server_url"`
	TokenSecret  string `json:"token_secret"`
	GrantKeySeed string `json:"grant_key_seed"` // base64 32 bytes
	EpochKeySeed string `json:"epoch_key_seed"` // base64 32 bytes
	TenantID     string `json:"tenant_id,omitempty"`

	// Optional Slack approvals. Set here (not env) so the Windows service —
	// which never sees your shell environment — picks them up too.
	SlackBotToken      string `json:"slack_bot_token,omitempty"`
	SlackSigningSecret string `json:"slack_signing_secret,omitempty"`
	SlackChannel       string `json:"slack_channel,omitempty"`
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
func loadOrInitDevConfig() (*devConfig, string, error) {
	path, err := devConfigPath()
	if err != nil {
		return nil, "", err
	}
	cfg := &devConfig{}
	if raw, err := os.ReadFile(filepath.Clean(path)); err == nil {
		if err := json.Unmarshal(raw, cfg); err != nil {
			return nil, "", fmt.Errorf("corrupt dev config %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, "", err
	}

	changed := false
	if cfg.DatabaseURL == "" {
		cfg.DatabaseURL = "postgres://ag:ag@localhost:5432/actiongate?sslmode=disable"
		changed = true
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8091"
		changed = true
	}
	if cfg.ServerURL == "" {
		cfg.ServerURL = "http://localhost:8091"
		changed = true
	}
	if cfg.TokenSecret == "" {
		cfg.TokenSecret = randomB64(32)
		changed = true
	}
	if cfg.GrantKeySeed == "" {
		cfg.GrantKeySeed = randomB64(32)
		changed = true
	}
	if cfg.EpochKeySeed == "" {
		cfg.EpochKeySeed = randomB64(32)
		changed = true
	}
	if changed {
		if err := saveDevConfig(cfg, path); err != nil {
			return nil, "", err
		}
	}
	return cfg, path, nil
}

func saveDevConfig(cfg *devConfig, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("config dir: %w", err)
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write dev config: %w", err)
	}
	return os.Rename(tmp, path)
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
