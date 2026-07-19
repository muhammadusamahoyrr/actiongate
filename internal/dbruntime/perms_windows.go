//go:build windows

package dbruntime

// hardenDataDirPerms is a no-op on Windows for now: initdb already restricts the
// data directory's ACL to the account that ran it, so pgdata is not
// world-readable. Stronger, SID-based lockdown (for the case where the service
// runs as a broader account than the installer) is deferred to M4, where we own
// initdb and can apply ACLs before the cluster is populated — doing it here with
// `icacls /inheritance:r` risks locking our own process out of pg_hba.conf.
func hardenDataDirPerms(string) error { return nil }
