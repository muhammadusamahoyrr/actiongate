//go:build windows

package main

import "golang.org/x/sys/windows"

// windowsShortPath returns the 8.3 short form (C:\Users\THELAP~1\…), which
// has no spaces and survives every shell. Falls back to the input when the
// volume has 8.3 names disabled.
func windowsShortPath(p string) string {
	long, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return p
	}
	n, err := windows.GetShortPathName(long, nil, 0)
	if err != nil || n == 0 {
		return p
	}
	buf := make([]uint16, n)
	n, err = windows.GetShortPathName(long, &buf[0], n)
	if err != nil || n == 0 {
		return p
	}
	return windows.UTF16ToString(buf)
}
