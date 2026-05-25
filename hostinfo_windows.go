//go:build windows

package main

import (
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	modkernel32                = syscall.NewLazyDLL("kernel32.dll")
	procGetSystemFirmwareTable = modkernel32.NewProc("GetSystemFirmwareTable")
	procGlobalMemoryStatusEx   = modkernel32.NewProc("GlobalMemoryStatusEx")
	procGetComputerNameExW     = modkernel32.NewProc("GetComputerNameExW")
	procGetTimeZoneInformation = modkernel32.NewProc("GetTimeZoneInformation")

	modadvapi32      = syscall.NewLazyDLL("advapi32.dll")
	procRegGetValueW = modadvapi32.NewProc("RegGetValueW")
)

const (
	rsmbSignature = 0x52534D42 // 'RSMB' raw SMBIOS firmware table provider

	hkeyLocalMachine = 0x80000002
	rrfRtRegSz       = 0x00000002
	rrfRtRegDword    = 0x00000010
)

// extraHostInfo gathers richer, Windows-specific machine details for the
// manifest: firmware/hardware identity (SMBIOS), physical memory, FQDN, OS
// provenance, machine GUID, and the host time zone. Each lookup is best-effort —
// anything unavailable is simply omitted.
func extraHostInfo() (out []kv) {
	// Firmware/registry data is the riskiest input we touch; if any lookup
	// panics, keep whatever was gathered so far and note it, so the manifest is
	// still written with timestamps, hashes, and partial host details.
	defer func() {
		if r := recover(); r != nil {
			out = append(out, kv{"Host info error", fmt.Sprintf("partial (recovered from panic: %v)", r)})
		}
	}()

	add := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			out = append(out, kv{k, v})
		}
	}

	add("FQDN", computerNameFQDN())

	if tbl, err := smbiosTable(); err == nil {
		if structs, perr := parseSMBIOS(tbl); perr == nil {
			for _, s := range structs {
				switch s.typ {
				case 0: // BIOS information
					add("BIOS vendor", s.str(0x04))
					add("BIOS version", s.str(0x05))
					add("BIOS date", s.str(0x08))
				case 1: // System information
					add("System manufacturer", s.str(0x04))
					add("System product", s.str(0x05))
					add("System version", s.str(0x06))
					add("System serial", s.str(0x07))
					add("System UUID", s.uuid(0x08))
					add("System SKU", s.str(0x19))
					add("System family", s.str(0x1A))
				case 2: // Baseboard
					add("Baseboard manufacturer", s.str(0x04))
					add("Baseboard product", s.str(0x05))
					add("Baseboard serial", s.str(0x07))
				case 3: // Chassis / enclosure
					add("Chassis serial", s.str(0x07))
					add("Chassis asset tag", s.str(0x08))
				}
			}
		}
	}

	if total, ok := totalPhysicalMemory(); ok {
		add("Physical memory", fmt.Sprintf("%.2f GiB (%d bytes)", float64(total)/(1<<30), total))
	}

	const cv = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	product := regGetString(cv, "ProductName")
	if dv := regGetString(cv, "DisplayVersion"); dv != "" {
		product = strings.TrimSpace(product + " " + dv)
	} else if rid := regGetString(cv, "ReleaseId"); rid != "" {
		product = strings.TrimSpace(product + " " + rid)
	}
	add("OS product", product)
	if v, ok := regGetDword(cv, "InstallDate"); ok {
		add("OS installed (UTC)", time.Unix(int64(v), 0).UTC().Format("2006-01-02T15:04:05Z"))
	}
	add("Machine GUID", regGetString(`SOFTWARE\Microsoft\Cryptography`, "MachineGuid"))

	add("Time zone", timeZoneInfo())

	return out
}

// smbiosTable returns the raw SMBIOS firmware table.
func smbiosTable() ([]byte, error) {
	r1, _, err := procGetSystemFirmwareTable.Call(uintptr(rsmbSignature), 0, 0, 0)
	size := uint32(r1)
	if size == 0 {
		return nil, fmt.Errorf("GetSystemFirmwareTable(size): %v", err)
	}
	buf := make([]byte, size)
	r1, _, err = procGetSystemFirmwareTable.Call(
		uintptr(rsmbSignature), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(size),
	)
	got := uint32(r1)
	if got == 0 {
		return nil, fmt.Errorf("GetSystemFirmwareTable(read): %v", err)
	}
	if got > size {
		got = size
	}
	return buf[:got], nil
}

// totalPhysicalMemory returns installed RAM in bytes via GlobalMemoryStatusEx.
func totalPhysicalMemory() (uint64, bool) {
	type memoryStatusEx struct {
		Length               uint32
		MemoryLoad           uint32
		TotalPhys            uint64
		AvailPhys            uint64
		TotalPageFile        uint64
		AvailPageFile        uint64
		TotalVirtual         uint64
		AvailVirtual         uint64
		AvailExtendedVirtual uint64
	}
	var m memoryStatusEx
	m.Length = uint32(unsafe.Sizeof(m))
	if r1, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m))); r1 == 0 {
		return 0, false
	}
	return m.TotalPhys, true
}

// computerNameFQDN returns the machine's fully qualified DNS name.
func computerNameFQDN() string {
	const physicalDNSFullyQualified = 7 // ComputerNamePhysicalDnsFullyQualified
	var size uint32
	procGetComputerNameExW.Call(physicalDNSFullyQualified, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return ""
	}
	buf := make([]uint16, size)
	if r1, _, _ := procGetComputerNameExW.Call(
		physicalDNSFullyQualified,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	); r1 == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:size])
}

// regGetString reads a REG_SZ value from HKLM\subkey.
func regGetString(subkey, name string) string {
	sk, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return ""
	}
	nm, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return ""
	}
	var size uint32
	r0, _, _ := procRegGetValueW.Call(
		uintptr(hkeyLocalMachine), uintptr(unsafe.Pointer(sk)), uintptr(unsafe.Pointer(nm)),
		uintptr(rrfRtRegSz), 0, 0, uintptr(unsafe.Pointer(&size)),
	)
	if r0 != 0 || size == 0 {
		return ""
	}
	buf := make([]uint16, (size+1)/2) // size is in bytes; never zero-length here
	r0, _, _ = procRegGetValueW.Call(
		uintptr(hkeyLocalMachine), uintptr(unsafe.Pointer(sk)), uintptr(unsafe.Pointer(nm)),
		uintptr(rrfRtRegSz), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
	)
	if r0 != 0 {
		return ""
	}
	return syscall.UTF16ToString(buf)
}

// regGetDword reads a REG_DWORD value from HKLM\subkey.
func regGetDword(subkey, name string) (uint32, bool) {
	sk, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return 0, false
	}
	nm, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, false
	}
	var data, size uint32
	size = 4
	r0, _, _ := procRegGetValueW.Call(
		uintptr(hkeyLocalMachine), uintptr(unsafe.Pointer(sk)), uintptr(unsafe.Pointer(nm)),
		uintptr(rrfRtRegDword), 0, uintptr(unsafe.Pointer(&data)), uintptr(unsafe.Pointer(&size)),
	)
	if r0 != 0 {
		return 0, false
	}
	return data, true
}

// timeZoneInfo returns the host's active time zone and UTC offset.
func timeZoneInfo() string {
	type systemTime struct {
		Year, Month, DayOfWeek, Day, Hour, Minute, Second, Milliseconds uint16
	}
	type timeZoneInformation struct {
		Bias         int32
		StandardName [32]uint16
		StandardDate systemTime
		StandardBias int32
		DaylightName [32]uint16
		DaylightDate systemTime
		DaylightBias int32
	}
	var tz timeZoneInformation
	r0, _, _ := procGetTimeZoneInformation.Call(uintptr(unsafe.Pointer(&tz)))
	if r0 == 0xffffffff { // TIME_ZONE_ID_INVALID
		return ""
	}
	name := syscall.UTF16ToString(tz.StandardName[:])
	bias := tz.Bias + tz.StandardBias
	if r0 == 2 { // TIME_ZONE_ID_DAYLIGHT
		name = syscall.UTF16ToString(tz.DaylightName[:])
		bias = tz.Bias + tz.DaylightBias
	}
	off := -bias // UTC = local + bias, so the offset from UTC is -bias minutes
	sign := "+"
	if off < 0 {
		sign, off = "-", -off
	}
	return fmt.Sprintf("%s (UTC%s%02d:%02d)", name, sign, off/60, off%60)
}
