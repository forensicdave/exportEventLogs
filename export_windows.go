//go:build windows

package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Windows Event Log API (wevtapi.dll). These are the same entry points that
// wevtutil.exe wraps, so calling them directly removes any dependency on the
// wevtutil binary and avoids spawning a child process per channel.
var (
	modwevtapi             = syscall.NewLazyDLL("wevtapi.dll")
	procEvtOpenChannelEnum = modwevtapi.NewProc("EvtOpenChannelEnum")
	procEvtNextChannelPath = modwevtapi.NewProc("EvtNextChannelPath")
	procEvtExportLog       = modwevtapi.NewProc("EvtExportLog")
	procEvtClose           = modwevtapi.NewProc("EvtClose")
)

const (
	errInsufficientBuffer syscall.Errno = 122
	errNoMoreItems        syscall.Errno = 259

	// Flags for EvtExportLog.
	evtExportLogChannelPath         = 0x1
	evtExportLogTolerateQueryErrors = 0x1000
)

// listChannels enumerates every event log channel name via EvtOpenChannelEnum /
// EvtNextChannelPath.
func listChannels() ([]string, error) {
	enum, _, err := procEvtOpenChannelEnum.Call(0, 0) // local session, no flags
	if enum == 0 {
		return nil, fmt.Errorf("EvtOpenChannelEnum: %w", err)
	}
	defer procEvtClose.Call(enum)

	var channels []string
	buf := make([]uint16, 512)
	for {
		var used uint32
		r1, _, callErr := procEvtNextChannelPath.Call(
			enum,
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&used)),
		)
		if r1 != 0 {
			channels = append(channels, syscall.UTF16ToString(buf[:used]))
			continue
		}

		errno, _ := callErr.(syscall.Errno)
		switch errno {
		case errInsufficientBuffer:
			// `used` is the required length in UTF-16 code units; grow and retry
			// the same item (the enumerator does not advance on this error).
			if int(used) <= len(buf) {
				return channels, fmt.Errorf("EvtNextChannelPath: unexpected insufficient buffer")
			}
			buf = make([]uint16, used)
		case errNoMoreItems:
			return channels, nil
		default:
			return channels, fmt.Errorf("EvtNextChannelPath: %w", callErr)
		}
	}
}

// exportChannel exports a single channel to path, overwriting any existing file
// (EvtExportLog refuses to overwrite, so we mimic wevtutil's /ow:true by
// removing an existing target first).
func exportChannel(channel, path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing existing %s: %w", path, err)
	}

	chPtr, err := syscall.UTF16PtrFromString(channel)
	if err != nil {
		return err
	}
	queryPtr, err := syscall.UTF16PtrFromString("*")
	if err != nil {
		return err
	}
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	r1, _, callErr := procEvtExportLog.Call(
		0, // local session
		uintptr(unsafe.Pointer(chPtr)),
		uintptr(unsafe.Pointer(queryPtr)),
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(evtExportLogChannelPath|evtExportLogTolerateQueryErrors),
	)
	if r1 == 0 {
		return callErr
	}
	return nil
}

// osVersion reports the real Windows version via RtlGetVersion. (GetVersionEx is
// subject to compatibility shimming and under-reports on modern Windows;
// RtlGetVersion is not.)
func osVersion() string {
	type rtlOSVersionInfoEx struct {
		OSVersionInfoSize uint32
		MajorVersion      uint32
		MinorVersion      uint32
		BuildNumber       uint32
		PlatformID        uint32
		CSDVersion        [128]uint16
	}
	var info rtlOSVersionInfoEx
	info.OSVersionInfoSize = uint32(unsafe.Sizeof(info))

	proc := syscall.NewLazyDLL("ntdll.dll").NewProc("RtlGetVersion")
	if r0, _, _ := proc.Call(uintptr(unsafe.Pointer(&info))); r0 != 0 { // STATUS_SUCCESS == 0
		return "unknown"
	}
	return fmt.Sprintf("Windows %d.%d (Build %d)", info.MajorVersion, info.MinorVersion, info.BuildNumber)
}
