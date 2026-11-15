//go:build !windows

package main

import "os"

func programFiles() string { return "" }

// isElevated reports whether this process runs as root.
func isElevated() bool { return os.Geteuid() == 0 }

const elevateHint = "re-run it with sudo"
