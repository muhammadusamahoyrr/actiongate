//go:build !windows

package main

import "os"

// isInteractiveConsole: stdin is a terminal (a character device). A pipe
// or a file — what an agent's tool call gets — is not. (/dev/null is a
// character device too, but then the confirmation prompt reads nothing and
// the command refuses.)
func isInteractiveConsole() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
