//go:build !windows

package main

import "errors"

// On non-Windows platforms there is no Event Log API to call. These stubs let
// the program compile and vet everywhere; it only does real work on Windows.
var errWindowsOnly = errors.New("exporting event logs requires Windows")

func listChannels() ([]string, error) { return nil, errWindowsOnly }

func exportChannel(channel, path string) error { return errWindowsOnly }

func osVersion() string { return "n/a (non-Windows build)" }
