//go:build windows

package dbruntime

import (
	"errors"
	"syscall"
)

// Windows error codes that mean "a handle is briefly held" — worth retrying.
const (
	errorAccessDenied     = syscall.Errno(5)
	errorSharingViolation = syscall.Errno(32)
)

// isSharingViolation reports whether err is a transient Windows sharing/access
// violation (AV or the search indexer holding a handle after the service stops).
func isSharingViolation(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == errorSharingViolation || errno == errorAccessDenied
	}
	return false
}
