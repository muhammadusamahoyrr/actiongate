//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func programFiles() string { return "" }

// isElevated reports whether this process runs as root.
func isElevated() bool { return os.Geteuid() == 0 }

const elevateHint = "re-run it with sudo"

// checkInstallDir refuses an install directory a non-root user could write
// or replace: the directory and every ancestor must be owned by root and
// not group- or world-writable (whoever can write a parent can rename the
// directory away and put their own in its place).
func checkInstallDir(dir string) error {
	for p := filepath.Clean(dir); ; p = filepath.Dir(p) {
		fi, err := os.Stat(p)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("cannot read the owner of %s", p)
		}
		if st.Uid != 0 {
			return fmt.Errorf("%s is owned by uid %d, not root: its owner could replace the binaries", p, st.Uid)
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is group- or world-writable: other users could replace the binaries", p)
		}
		if parent := filepath.Dir(p); parent == p {
			return nil
		}
	}
}
