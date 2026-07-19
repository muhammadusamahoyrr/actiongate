// Package upgrade performs a cluster upgrade as four strictly ordered phases,
// exposing exactly one entrypoint so the phases can never be called
// out of order by another package (the Go compiler enforces it).
//
// The order is prepare → perform → verify → commit:
//
//	prepare  produce a verified backup first
//	perform  restore/upgrade INTO A NEW data directory (the old one untouched)
//	verify   full verify() against the pre-upgrade checkpoint + a health check
//	         against the NEW directory — verification only, no switch yet
//	commit   only now, atomically switch the active cluster to the new directory
//
// Splitting verify from commit keeps "verified" and "live" distinct: a failed
// verify must leave the old cluster untouched and never commit.
package upgrade

import "fmt"

// steps are the four phases. Unexported so only this package's run can invoke
// them, in order.
type steps struct {
	prepare func() error
	perform func() error
	verify  func() error
	commit  func() error
}

// run executes the phases in order, aborting before commit if verify fails.
func run(s steps) error {
	if err := s.prepare(); err != nil {
		return fmt.Errorf("upgrade: prepare: %w", err)
	}
	if err := s.perform(); err != nil {
		return fmt.Errorf("upgrade: perform: %w", err)
	}
	if err := s.verify(); err != nil {
		return fmt.Errorf("upgrade: verify failed — cluster NOT switched: %w", err)
	}
	if err := s.commit(); err != nil {
		return fmt.Errorf("upgrade: commit: %w", err)
	}
	return nil
}

// Options carries the concrete phase implementations. The CLI's
// `cluster upgrade` command supplies them (backup, restore-into-new-dir, verify
// against the pre-upgrade checkpoint, and the blue-green swap); Developer
// Edition never uses pg_upgrade, so Perform is a restore into a new directory.
type Options struct {
	// Prepare produces a verified backup of the current cluster.
	Prepare func() error
	// Perform restores/upgrades into a NEW data directory, leaving the old one
	// untouched.
	Perform func() error
	// Verify runs the full audit-chain verify() plus a health check against the
	// new directory. It must not switch anything.
	Verify func() error
	// Commit atomically switches the active cluster to the new directory
	// (dbruntime.SwapInPlace).
	Commit func() error
}

// Run is the ONLY exported symbol: the single entrypoint the CLI calls. It wires
// the options into the ordered phases; no other package can invoke a phase
// directly.
func Run(o Options) error {
	if o.Prepare == nil || o.Perform == nil || o.Verify == nil || o.Commit == nil {
		return fmt.Errorf("upgrade: all phases (prepare, perform, verify, commit) are required")
	}
	return run(steps{prepare: o.Prepare, perform: o.Perform, verify: o.Verify, commit: o.Commit})
}
