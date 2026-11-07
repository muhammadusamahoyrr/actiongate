package main

import (
	"path/filepath"
	"strings"
)

// bashHookCommand renders a binary path the way Claude Code's hook runner
// needs it. Hooks run through Git Bash on Windows, which eats backslashes
// (C:\Users\… becomes C:Users… → exit 127 → the hook is silently treated as
// non-blocking and BYPASSED), so the path must be POSIX-style: /c/Users/….
// The 8.3 short path is preferred on Windows, and the result is always
// single-quoted: an unquoted path containing &, (, $ or ; would be split or
// run as a different command by the shell, again bypassing the hook.
func bashHookCommand(exePath string) string {
	p := windowsShortPath(exePath)
	p = filepath.ToSlash(p)
	if len(p) > 2 && p[1] == ':' && p[2] == '/' {
		p = "/" + strings.ToLower(p[:1]) + p[2:]
	}
	return shellQuote(p)
}

// shellQuote wraps s in single quotes for a POSIX shell; nothing inside
// single quotes is special except the quote itself, which is closed, escaped and reopened.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
