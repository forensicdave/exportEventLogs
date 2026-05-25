package main

import (
	"encoding/binary"
	"testing"
)

func TestParseSMBIOS(t *testing.T) {
	// One Type 1 (System Information) structure: 27-byte formatted area with
	// string indices 1..4 (manufacturer/product/version/serial), a 16-byte
	// UUID, then SKU (5) and Family (6).
	formatted := []byte{
		0x01, 0x1B, 0x00, 0x01, // type, length=27, handle
		0x01, 0x02, 0x03, 0x04, // manufacturer, product, version, serial
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, // UUID bytes 0..7
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // UUID bytes 8..15
		0x06,       // wake-up type
		0x05, 0x06, // SKU, family
	}
	strs := []byte("ACME\x00Model X\x001.0\x00SN12345\x00SKU-1\x00FamilyZ\x00\x00")
	end := []byte{0x7F, 0x04, 0xFF, 0xFF, 0x00, 0x00} // type 127 end-of-table

	table := append(append(append([]byte{}, formatted...), strs...), end...)
	header := []byte{0x00, 0x03, 0x02, 0x00, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(header[4:8], uint32(len(table)))
	raw := append(header, table...)

	structs, err := parseSMBIOS(raw)
	if err != nil {
		t.Fatal(err)
	}

	var sys *dmiStruct
	for i := range structs {
		if structs[i].typ == 1 {
			sys = &structs[i]
		}
	}
	if sys == nil {
		t.Fatal("type 1 structure not found")
	}

	checks := []struct {
		name, got, want string
	}{
		{"manufacturer", sys.str(0x04), "ACME"},
		{"product", sys.str(0x05), "Model X"},
		{"version", sys.str(0x06), "1.0"},
		{"serial", sys.str(0x07), "SN12345"},
		{"sku", sys.str(0x19), "SKU-1"},
		{"family", sys.str(0x1A), "FamilyZ"},
		{"uuid", sys.uuid(0x08), "33221100-5544-7766-8899-AABBCCDDEEFF"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

func TestSMBIOSUUIDNotSet(t *testing.T) {
	var s dmiStruct
	s.formatted = make([]byte, 0x18+16) // header + offset to UUID + 16 bytes
	for i := 0x08; i < 0x18; i++ {
		s.formatted[i] = 0xFF
	}
	if got := s.uuid(0x08); got != "(not set)" {
		t.Errorf("all-FF uuid = %q, want (not set)", got)
	}
}
