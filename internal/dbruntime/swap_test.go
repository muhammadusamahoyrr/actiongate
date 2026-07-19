package dbruntime

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// TestSwapRetriesOnSharingViolation: a rename that hits a transient Windows
// sharing violation is retried until it succeeds. Windows-specific.
func TestSwapRetriesOnSharingViolation(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("sharing-violation retry is Windows-specific")
	}
	orig := osRename
	t.Cleanup(func() { osRename = orig })

	var calls int
	osRename = func(_, _ string) error {
		calls++
		if calls < 3 {
			return &os.PathError{Op: "rename", Path: "x", Err: syscall.Errno(32)} // ERROR_SHARING_VIOLATION
		}
		return nil
	}
	if err := renameWithRetry("a", "b", 5, time.Millisecond); err != nil {
		t.Fatalf("renameWithRetry: %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 attempts (2 violations + 1 success), got %d", calls)
	}
}

// TestSwapDoesNotRetryRealErrors: a non-sharing error fails immediately.
func TestSwapDoesNotRetryRealErrors(t *testing.T) {
	orig := osRename
	t.Cleanup(func() { osRename = orig })

	var calls int
	boom := errors.New("disk full")
	osRename = func(_, _ string) error { calls++; return boom }

	err := renameWithRetry("a", "b", 5, time.Millisecond)
	if !errors.Is(err, boom) {
		t.Fatalf("expected the real error, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected no retries for a real error, got %d attempts", calls)
	}
}

// TestSwapRollbackOnFailure: when promoting staged fails, the previous live
// directory is rolled back so the old cluster stays usable.
func TestSwapRollbackOnFailure(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "live")
	staged := filepath.Join(dir, "staged")
	backup := filepath.Join(dir, "backup")
	mustMkdir(t, live)
	mustMkdir(t, staged)
	if err := os.WriteFile(filepath.Join(live, "marker"), []byte("orig"), 0o600); err != nil {
		t.Fatalf("marker: %v", err)
	}

	orig := osRename
	t.Cleanup(func() { osRename = orig })
	promoteErr := errors.New("promote failed")
	osRename = func(oldPath, newPath string) error {
		if oldPath == staged && newPath == live {
			return promoteErr // fail the staged -> live promotion
		}
		return os.Rename(oldPath, newPath) // real for move-aside and rollback
	}

	err := SwapInPlace(live, staged, backup)
	if err == nil {
		t.Fatal("expected SwapInPlace to fail")
	}
	if !dirExists(live) {
		t.Fatal("live directory was not rolled back")
	}
	b, err := os.ReadFile(filepath.Join(live, "marker"))
	if err != nil || string(b) != "orig" {
		t.Fatalf("live content lost after rollback: %q (%v)", string(b), err)
	}
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", p, err)
	}
}
