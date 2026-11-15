//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// programFiles is the Program Files directory as the OS records it.
func programFiles() string {
	if dir, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0); err == nil {
		return dir
	}
	if dir := os.Getenv("ProgramFiles"); dir != "" {
		return dir
	}
	return `C:\Program Files`
}

// isElevated reports whether this process runs with administrator rights
// (an elevated token under UAC).
func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// checkInstallDir refuses an install directory a standard user may be able
// to write. Program Files grants users read/execute only, and a standard
// user cannot create a subdirectory there to pre-seed a permissive ACL, so
// the directory must be inside it.
func checkInstallDir(dir string) error {
	for _, root := range []string{programFiles(), os.Getenv("ProgramFiles(x86)")} {
		if root == "" {
			continue
		}
		rel, err := filepath.Rel(root, dir)
		if err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil
		}
	}
	return fmt.Errorf("%s is not inside %s: a directory outside Program Files may be writable by standard users (and so by the agent)", dir, programFiles())
}

const elevateHint = "open an elevated terminal (right-click → Run as administrator) and run the same command"
