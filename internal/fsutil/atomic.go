// Package fsutil holds small file helpers shared by the CLIs.
package fsutil

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// WriteFileAtomic replaces path with data so readers see either the old or
// the new content, never a partial file. The result always has mode perm;
// use it for files holding secrets.
//
//   - The temp file has a unique name in the target's directory, so
//     concurrent writers never interleave on a shared ".tmp" path.
//   - If path is a symlink, the file it points to is replaced and the link
//     is kept.
func WriteFileAtomic(path string, data []byte, perm fs.FileMode) error {
	return writeAtomic(path, data, perm, false)
}

// UpdateFileAtomic is WriteFileAtomic for files the user owns, such as an
// editor's settings: an existing file keeps its permission bits, and only a
// new file gets perm.
func UpdateFileAtomic(path string, data []byte, perm fs.FileMode) error {
	return writeAtomic(path, data, perm, true)
}

func writeAtomic(path string, data []byte, perm fs.FileMode, keepMode bool) error {
	target := path
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		target = resolved
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	mode := perm
	if fi, err := os.Stat(target); err == nil && keepMode {
		mode = fi.Mode().Perm()
	}

	tmp, err := os.CreateTemp(filepath.Dir(target), filepath.Base(target)+".*.tmp")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	tmpName := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(mode); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := rename(tmpName, target); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
