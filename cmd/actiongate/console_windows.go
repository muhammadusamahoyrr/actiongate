//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// isInteractiveConsole: stdin is a real console. A pipe, a file or NUL —
// what an agent's tool call gets — is not.
func isInteractiveConsole() bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(os.Stdin.Fd()), &mode) == nil
}
