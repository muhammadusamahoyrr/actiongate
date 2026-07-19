//go:build !windows

package dbruntime

// isSharingViolation is Windows-specific; on other platforms a rename either
// succeeds or fails for a real reason, so there is nothing transient to retry.
func isSharingViolation(error) bool { return false }
