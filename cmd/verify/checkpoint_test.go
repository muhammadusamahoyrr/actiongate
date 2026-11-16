package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/muhammadusamahoyrr/actiongate/internal/seal"
)

func TestCheckpointRoundTripAndTenantBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cp.json")
	tenant, stream := uuid.New(), uuid.New()

	cp, err := loadCheckpoint(path, tenant)
	if err != nil || len(cp.Streams) != 0 {
		t.Fatalf("missing file: %+v, %v; want an empty checkpoint", cp, err)
	}
	cp.Streams[stream.String()] = seal.Head{LastSequence: 7, RootHash: "ab"}
	if err := cp.save(path); err != nil {
		t.Fatal(err)
	}
	got, err := loadCheckpoint(path, tenant)
	if err != nil || got.Streams[stream.String()] != (seal.Head{LastSequence: 7, RootHash: "ab"}) {
		t.Fatalf("reload: %+v, %v", got, err)
	}
	if _, err := loadCheckpoint(path, uuid.New()); err == nil {
		t.Error("a checkpoint for another tenant was accepted")
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCheckpoint(path, tenant); err == nil {
		t.Error("a corrupt checkpoint was accepted")
	}
}

// A chain that no longer contains the recorded head is a problem; with no
// recorded head there is nothing to compare.
func TestCheckAgainst(t *testing.T) {
	stream := uuid.New()
	cp := checkpoint{Streams: map[string]seal.Head{stream.String(): {LastSequence: 9, RootHash: "ff"}}}

	var report seal.Report // no epochs: the recorded head is gone
	checkAgainst(cp, stream, &report)
	if len(report.Problems) != 1 || !strings.Contains(report.Problems[0], "truncated or rewritten") {
		t.Errorf("problems = %v, want the truncation problem", report.Problems)
	}

	var fresh seal.Report
	checkAgainst(cp, uuid.New(), &fresh)
	if len(fresh.Problems) != 0 {
		t.Errorf("stream without a recorded head: %v", fresh.Problems)
	}
}
