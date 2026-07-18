// Package policies embeds the starter policy packs so `actiongate up` and
// `actiongate protect` can provision tenants without loose files. Users
// cannot write CEL for tool schemas they have never seen — packs are the
// on-ramp; custom policy comes later via `controlplane admin set-policy`.
package policies

import (
	_ "embed"
)

// ClaudeCode is the balanced default for Claude Code's native tools:
// secrets denied, destructive shell gated on approval, everything else
// allowed (plus the MCP demo-server rules).
//
//go:embed claude-code.json
var ClaudeCode []byte

// Paranoid keeps reads free but routes every shell command and every file
// mutation through human approval; secret material is denied outright.
//
//go:embed paranoid.json
var Paranoid []byte

// Relaxed only denies secret files and gates catastrophic shell commands.
//
//go:embed relaxed.json
var Relaxed []byte

// Pack returns the named starter pack. Names returns the valid names.
func Pack(name string) ([]byte, bool) {
	switch name {
	case "claude-code":
		return ClaudeCode, true
	case "paranoid":
		return Paranoid, true
	case "relaxed":
		return Relaxed, true
	}
	return nil, false
}

func Names() []string { return []string{"claude-code", "paranoid", "relaxed"} }
