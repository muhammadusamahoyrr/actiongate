package gateway

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// State is the gateway's persisted identity: enrollment credential, its own
// signing key, and the pinned control-plane keys. It lives in a 0600 file on
// the customer's machine — nothing in it ever reaches the vendor except the
// public key at enrollment.
type State struct {
	ServerURL       string            `json:"server_url"`
	GatewayID       string            `json:"gateway_id"`
	TenantID        string            `json:"tenant_id"`
	Credential      string            `json:"credential"`
	PrivateKeySeed  string            `json:"private_key_seed"` // base64, ed25519 seed
	ControlKeys     map[string]string `json:"control_keys"`     // key_id -> base64 public key
	PendingReceipts map[string]Grant  `json:"pending_receipts"` // action_id -> grant awaiting outcome
}

// Grant is the locally stored slice of an issued grant needed to report its
// outcome later (hook mode: check and report are separate invocations).
type Grant struct {
	GrantID   string    `json:"grant_id"`
	ActionID  string    `json:"action_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *State) PrivateKey() (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(s.PrivateKeySeed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("corrupt private key seed in state file")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func (s *State) PublicKeys() (map[string]ed25519.PublicKey, error) {
	keys := make(map[string]ed25519.PublicKey, len(s.ControlKeys))
	for id, encoded := range s.ControlKeys {
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("corrupt control-plane key %q in state file", id)
		}
		keys[id] = ed25519.PublicKey(raw)
	}
	return keys, nil
}

func LoadState(path string) (*State, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("corrupt state file %s: %w", path, err)
	}
	if s.PendingReceipts == nil {
		s.PendingReceipts = map[string]Grant{}
	}
	return &s, nil
}

func (s *State) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("state dir: %w", err)
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	return os.Rename(tmp, path)
}

// DefaultStatePath is ~/.config/actiongate/gateway.json (or the OS
// equivalent).
func DefaultStatePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "actiongate", "gateway.json"), nil
}
