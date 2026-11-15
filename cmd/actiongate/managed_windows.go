//go:build windows

package main

import (
	"os"

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

const elevateHint = "open an elevated terminal (right-click → Run as administrator) and run the same command"
