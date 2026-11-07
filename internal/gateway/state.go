package gateway

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/muhammadusamahoyrr/actiongate/internal/fsutil"
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

	// loadedReceipts is PendingReceipts as last read from or written to
	// disk; SaveReceipts diffs against it.
	loadedReceipts map[string]Grant
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

// LoadState reads the state file. It remembers the pending receipts it
// loaded so SaveReceipts can later write back only this process's changes.
func LoadState(path string) (*State, error) {
	// Report a missing file without creating the directory or lock file:
	// `ag-hook -warn` probes for a state file that may not exist yet.
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	var s *State
	err := withStateLock(path, func() error {
		var err error
		s, err = readState(path)
		return err
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Save overwrites the whole state file with s. Use it for enrollment; use
// SaveReceipts after check, report or an MCP session, where other gateway
// processes may have changed the file since it was loaded.
func (s *State) Save(path string) error {
	return withStateLock(path, func() error {
		if err := writeState(path, s); err != nil {
			return err
		}
		s.loadedReceipts = copyReceipts(s.PendingReceipts)
		return nil
	})
}

// SaveReceipts merges the pending receipts this process added or removed
// since LoadState (or the last save) into the current state file, under an
// exclusive lock. Concurrent hook invocations (Claude Code runs tool calls
// in parallel) each load, wait on the control plane, then save; a plain
// Save would let the last writer drop the other processes' receipts.
func (s *State) SaveReceipts(path string) error {
	return withStateLock(path, func() error {
		current, err := readState(path)
		if err != nil {
			return err
		}
		for id, g := range s.PendingReceipts {
			if old, ok := s.loadedReceipts[id]; !ok || old != g {
				current.PendingReceipts[id] = g
			}
		}
		for id := range s.loadedReceipts {
			if _, ok := s.PendingReceipts[id]; !ok {
				delete(current.PendingReceipts, id)
			}
		}
		pruneStaleReceipts(current.PendingReceipts, time.Now())
		if err := writeState(path, current); err != nil {
			return err
		}
		s.PendingReceipts = copyReceipts(current.PendingReceipts)
		s.loadedReceipts = copyReceipts(current.PendingReceipts)
		return nil
	})
}

// withStateLock runs fn while holding an exclusive lock on path+".lock".
// The lock lives in a separate file because the state file itself is
// replaced by rename on every save.
func withStateLock(path string, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("state dir: %w", err)
	}
	lf, err := os.OpenFile(filepath.Clean(path+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open state lock: %w", err)
	}
	defer func() { _ = lf.Close() }()
	if err := lockFile(lf); err != nil {
		return fmt.Errorf("lock state: %w", err)
	}
	defer func() { _ = unlockFile(lf) }()
	return fn()
}

// readState and writeState assume the caller holds the state lock.
func readState(path string) (*State, error) {
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
	s.loadedReceipts = copyReceipts(s.PendingReceipts)
	return &s, nil
}

func writeState(path string, s *State) error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	// Unique temp name: a fixed one let concurrent writers interleave on
	// it, and the loser's rename then failed with "no such file".
	return fsutil.WriteFileAtomic(path, raw, 0o600)
}

// staleReceiptAge bounds how long an unreported receipt is kept. The
// control plane stops accepting outcomes after its outcome deadline
// (5 minutes by default), so older receipts can never be reported. Claude
// Code hook mode only runs `check`, so without pruning every allowed tool
// call would grow the state file forever.
const staleReceiptAge = 24 * time.Hour

func pruneStaleReceipts(m map[string]Grant, now time.Time) {
	for id, g := range m {
		if !g.ExpiresAt.IsZero() && now.Sub(g.ExpiresAt) > staleReceiptAge {
			delete(m, id)
		}
	}
}

func copyReceipts(m map[string]Grant) map[string]Grant {
	out := make(map[string]Grant, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
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
