package main

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// SMBIOS table parsing. This is deliberately OS-independent (it operates on the
// raw byte buffer returned by GetSystemFirmwareTable on Windows) so it can be
// unit-tested anywhere. Layout reference: DMTF SMBIOS specification.

// dmiStruct is one parsed SMBIOS structure: its type, the formatted area
// (including the 4-byte header), and its 1-based string set.
type dmiStruct struct {
	typ       byte
	formatted []byte
	strings   []string
}

// str returns the string referenced by the byte at offset in the formatted
// area (a 1-based index into the string set), or "" if unset/out of range.
func (s dmiStruct) str(offset int) string {
	if offset >= len(s.formatted) {
		return ""
	}
	idx := int(s.formatted[offset])
	if idx == 0 || idx > len(s.strings) {
		return ""
	}
	return strings.TrimSpace(s.strings[idx-1])
}

// uuid renders the 16-byte UUID at offset in SMBIOS byte order (the first three
// groups are little-endian), matching what Windows tools display. An all-zero
// or all-0xFF value means "not present".
func (s dmiStruct) uuid(offset int) string {
	if offset+16 > len(s.formatted) {
		return ""
	}
	b := s.formatted[offset : offset+16]
	zero, ff := true, true
	for _, x := range b {
		if x != 0x00 {
			zero = false
		}
		if x != 0xFF {
			ff = false
		}
	}
	if zero || ff {
		return "(not set)"
	}
	return fmt.Sprintf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6],
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

// parseSMBIOS parses the buffer returned by GetSystemFirmwareTable('RSMB'),
// which is a RawSMBIOSData header followed by the packed structure table.
func parseSMBIOS(raw []byte) ([]dmiStruct, error) {
	if len(raw) < 8 {
		return nil, fmt.Errorf("SMBIOS data too small (%d bytes)", len(raw))
	}
	// RawSMBIOSData: [0]=Used20 [1]=Major [2]=Minor [3]=DmiRev [4:8]=Length
	dataLen := binary.LittleEndian.Uint32(raw[4:8])
	data := raw[8:]
	if int(dataLen) <= len(data) {
		data = data[:dataLen]
	}

	var out []dmiStruct
	for i := 0; i+4 <= len(data); {
		typ := data[i]
		flen := int(data[i+1]) // formatted-area length, includes the 4-byte header
		if flen < 4 || i+flen > len(data) {
			break
		}
		formatted := data[i : i+flen]

		// The string set follows the formatted area and ends with a double NUL.
		p := i + flen
		var strs []string
		if p+1 < len(data) && data[p] == 0 && data[p+1] == 0 {
			p += 2 // structure has no strings
		} else {
			for p < len(data) {
				start := p
				for p < len(data) && data[p] != 0 {
					p++
				}
				strs = append(strs, string(data[start:p]))
				p++ // skip the string's terminating NUL
				if p < len(data) && data[p] == 0 {
					p++ // the extra NUL terminates the set
					break
				}
			}
		}

		out = append(out, dmiStruct{typ: typ, formatted: formatted, strings: strs})

		if typ == 127 || p <= i { // end-of-table structure, or no forward progress
			break
		}
		i = p
	}
	return out, nil
}
