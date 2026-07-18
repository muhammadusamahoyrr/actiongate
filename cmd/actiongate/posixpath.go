package main

import (
	"path/filepath"
	"strings"
)

// bashHookCommand renders a binary path the way Claude Code's hook runner
// needs it. Hooks run through Git Bash on Windows, which eats backslashes
// (C:\Users\… becomes C:Users… → exit 127 → the hook is silently treated as
// non-blocking and BYPASSED), so the path must be POSIX-style: /c/Users/….
// Spaces are handled by preferring the 8.3 short path on Windows and
// quoting as a last resort.
func bashHookCommand(exePath string) string {
	p := windowsShortPath(exePath)
	p = filepath.ToSlash(p)
	if len(p) > 2 && p[1] == ':' && p[2] == '/' {
		p = "/" + strings.ToLower(p[:1]) + p[2:]
	}
	if strings.Contains(p, " ") {
		p = `"` + p + `"`
	}
	return p
}
