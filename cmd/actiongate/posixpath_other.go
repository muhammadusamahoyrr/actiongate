//go:build !windows

package main

func windowsShortPath(p string) string { return p }
