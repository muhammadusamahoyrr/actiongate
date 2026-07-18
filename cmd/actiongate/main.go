// actiongate is the onboarding CLI (roadmap P0): the 60-second path from
// nothing to a protected agent.
//
//	actiongate up                    start everything locally and stay running
//	actiongate protect claude-code   install the PreToolUse hook for a project
//
// The heavy machinery lives in the controlplane/gateway/verify binaries and
// their internal packages; this command only bootstraps and wires them.
package main

import (
	"fmt"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) < 1 {
		usage()
		return 1
	}
	switch args[0] {
	case "up":
		return cmdUp(args[1:])
	case "protect":
		return cmdProtect(args[1:])
	case "service":
		return cmdService(args[1:])
	case "tamper-demo":
		return cmdTamperDemo(args[1:])
	case "-h", "--help", "help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		usage()
		return 1
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: actiongate <command>

  up                     start Postgres, migrate, provision a tenant, enroll
                         the local gateway, and run the control plane
                         (leave it running; Ctrl+C stops it)
  protect claude-code    install the actiongate PreToolUse hook into a
                         project's Claude Code settings and apply a policy
                         pack (-pack claude-code|paranoid|relaxed)
  service <verb>         run the control plane as a Windows service so it
                         survives reboots: install|uninstall|start|stop|
                         status|run (install/uninstall need an elevated
                         terminal)
  tamper-demo            prove the audit log is tamper-evident: seal events
                         on a throwaway database, edit one as a "malicious
                         DBA", watch verification name the exact event

Run 'actiongate up' once, then 'actiongate protect claude-code' inside the
project you want governed. Install the service so protection survives
reboots unattended.
`)
}
