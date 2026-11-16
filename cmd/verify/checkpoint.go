package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	"github.com/muhammadusamahoyrr/actiongate/internal/seal"
)

// checkpoint is the last verified head of each stream, kept outside the
// database (audit H8). A sealed chain is signed, but nothing in the
// database alone shows how long it was: someone able to delete the newest
// epochs leaves a shorter chain that still verifies. Comparing against a
// head recorded earlier, on storage the database cannot reach, catches
// that.
type checkpoint struct {
	Version int                  `json:"version"`
	Tenant  string               `json:"tenant"`
	Streams map[string]seal.Head `json:"streams"`
}

func loadCheckpoint(path string, tenantID uuid.UUID) (checkpoint, error) {
	cp := checkpoint{Version: 1, Tenant: tenantID.String(), Streams: map[string]seal.Head{}}
	raw, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, fs.ErrNotExist) {
		return cp, nil // first run: nothing to compare against yet
	}
	if err != nil {
		return cp, err
	}
	var got checkpoint
	if err := json.Unmarshal(raw, &got); err != nil {
		return cp, fmt.Errorf("checkpoint %s: %w", path, err)
	}
	if got.Version != 1 {
		return cp, fmt.Errorf("checkpoint %s: unsupported version %d", path, got.Version)
	}
	if got.Tenant != tenantID.String() {
		return cp, fmt.Errorf("checkpoint %s is for tenant %s, not %s", path, got.Tenant, tenantID)
	}
	if got.Streams == nil {
		got.Streams = map[string]seal.Head{}
	}
	return got, nil
}

// save writes the checkpoint atomically, so a crash never leaves a torn
// file that the next run would reject.
func (cp checkpoint) save(path string) error {
	raw, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".verify-checkpoint-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// checkAgainst adds a problem when the chain no longer contains the head
// recorded for this stream.
func checkAgainst(cp checkpoint, streamID uuid.UUID, report *seal.Report) {
	prev, ok := cp.Streams[streamID.String()]
	if !ok || report.Contains(prev) {
		return
	}
	report.Problems = append(report.Problems, fmt.Sprintf(
		"checkpointed head (epoch ending at sequence %d, root %s) is no longer in the chain: the log was truncated or rewritten",
		prev.LastSequence, prev.RootHash))
}
