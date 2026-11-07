package fsutil

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

// Concurrent unlocked writers never corrupt the file or leave temp files.
// On Windows a rename can still lose to a busy target under heavy load
// (callers that need every write to land, like the gateway state, take a
// lock), so there an access-denied error is tolerated; anywhere else it is
// a failure.
func TestWriteFileAtomicConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.json")
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := WriteFileAtomic(path, []byte(`{"ok":true}`), 0o600)
			if err != nil && (runtime.GOOS != "windows" || !errors.Is(err, fs.ErrPermission)) {
				t.Errorf("WriteFileAtomic: %v", err)
			}
		}()
	}
	wg.Wait()
	if got, err := os.ReadFile(path); err != nil || string(got) != `{"ok":true}` { //nolint:gosec // G304: test temp dir
		t.Errorf("final content %q, err %v", got, err)
	}
	if left, _ := filepath.Glob(path + ".*.tmp"); len(left) != 0 {
		t.Errorf("temp files left behind: %v", left)
	}
}

func TestWriteFileAtomicKeepsModeAndSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes and unprivileged symlinks")
	}
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	if err := os.WriteFile(real, []byte("old"), 0o644); err != nil { //nolint:gosec // G306: the test needs a non-default mode to check it is kept
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := UpdateFileAtomic(link, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink was replaced: %v", err)
	}
	fi, err := os.Stat(real)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, want 0644", fi.Mode().Perm())
	}
	if got, _ := os.ReadFile(real); string(got) != "new" { //nolint:gosec // G304: test temp dir
		t.Errorf("content = %q", got)
	}
}
