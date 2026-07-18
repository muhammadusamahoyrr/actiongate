//go:build !windows

package main

import (
	"fmt"
	"os"
)

func cmdService(_ []string) int {
	fmt.Fprintln(os.Stderr, `service: Windows-only for now. On Linux/macOS run the control plane
under your init system, e.g. a systemd unit or launchd plist executing
"controlplane" with the AG_* environment (see README "Configuration
reference"), or keep an "actiongate up" terminal open.`)
	return 1
}

func serviceHint() string { return "" }
