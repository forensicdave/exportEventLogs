//go:build !windows

package main

// extraHostInfo only gathers data on Windows; elsewhere there is nothing extra
// to report beyond the cross-platform basics in the manifest.
func extraHostInfo() []kv { return nil }
