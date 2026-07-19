package dbruntime

import (
	"fmt"
	"os"
	"time"
)

// osRename is indirected so tests can inject transient failures.
var osRename = os.Rename

const (
	swapAttempts = 12
	swapBackoff  = 250 * time.Millisecond
)

// renameWithRetry renames oldPath to newPath, retrying on Windows sharing/
// access-denied errors (AV or the search indexer briefly holding a handle after
// the service stops). Other errors fail immediately.
func renameWithRetry(oldPath, newPath string, attempts int, backoff time.Duration) error {
	var err error
	for i := 0; i < attempts; i++ {
		if err = osRename(oldPath, newPath); err == nil {
			return nil
		}
		if !isSharingViolation(err) {
			return err
		}
		time.Sleep(backoff)
	}
	return fmt.Errorf("rename %s -> %s failed after %d attempts: %w", oldPath, newPath, attempts, err)
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// SwapInPlace performs a blue-green swap of data directories: it promotes staged
// to live, preserving the previous live at backup for instant rollback. The
// cluster must be stopped so no handles are held; retries absorb transient
// Windows sharing violations. The runtime's DataPath (the fixed `live` path) is
// unchanged — only the directory sitting there is replaced.
//
// This is the rename-based realization of Step 9's blue-green intent. Directory
// junctions were the original proposal, but a fixed live path with
// rename-with-retry gives the same rollback + AV tolerance without reparse-point
// APIs or privilege.
func SwapInPlace(live, staged, backup string) error {
	if !dirExists(staged) {
		return fmt.Errorf("dbruntime: swap: staged dir %s does not exist", staged)
	}
	hadLive := dirExists(live)
	if hadLive {
		if err := renameWithRetry(live, backup, swapAttempts, swapBackoff); err != nil {
			return fmt.Errorf("dbruntime: swap: move live aside: %w", err)
		}
	}
	if err := renameWithRetry(staged, live, swapAttempts, swapBackoff); err != nil {
		if hadLive {
			// Roll back so the previous cluster stays usable.
			_ = renameWithRetry(backup, live, swapAttempts, swapBackoff)
		}
		return fmt.Errorf("dbruntime: swap: promote staged: %w", err)
	}
	return nil
}
