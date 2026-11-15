package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
)

// WithLock runs fn while holding an exclusive cross-process lock on
// path+".lock". Use it around any load-modify-save of a file that several
// processes can update at once: an atomic write alone stops torn files but
// not lost updates.
//
// The lock lives in a separate file because the guarded file is replaced
// by rename on every save. The lock is advisory: it only coordinates
// processes that also call WithLock.
func WithLock(path string, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("lock dir: %w", err)
	}
	lf, err := os.OpenFile(filepath.Clean(path+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open lock: %w", err)
	}
	defer func() { _ = lf.Close() }()
	if err := lockFile(lf); err != nil {
		return fmt.Errorf("lock %s: %w", path, err)
	}
	defer func() { _ = unlockFile(lf) }()
	return fn()
}
