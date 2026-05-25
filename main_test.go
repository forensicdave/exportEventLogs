package main

import (
	"errors"
	"strings"
	"testing"
)

func TestProtect(t *testing.T) {
	// A string panic is recovered and reported as an error.
	if err := protect(func() error { panic("boom") }); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("string panic: got %v, want error containing boom", err)
	}

	// A runtime panic (nil dereference) is recovered too — no crash.
	if err := protect(func() error { var p *int; _ = *p; return nil }); err == nil {
		t.Error("nil-deref panic: expected an error, got nil")
	}

	// No panic, no error.
	if err := protect(func() error { return nil }); err != nil {
		t.Errorf("clean run: unexpected error %v", err)
	}

	// A returned error passes through unchanged.
	sentinel := errors.New("real error")
	if err := protect(func() error { return sentinel }); !errors.Is(err, sentinel) {
		t.Errorf("returned error: got %v, want sentinel", err)
	}
}

func TestSanitizeTrailing(t *testing.T) {
	cases := map[string]string{
		"Microsoft-Windows-PowerShell/Operational": "Microsoft-Windows-PowerShell-Operational",
		"Trailing dot.":   "Trailing dot",
		"Trailing space ": "Trailing space",
		"weird...   ":     "weird",
		`a:b*c?"<>|d`:     "a-b-c-----d",
	}
	for in, want := range cases {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
	// A name that sanitizes away entirely must still yield a usable filename.
	if got := sanitize("..  "); got != "channel" {
		t.Errorf("sanitize(empty-after-trim) = %q, want channel", got)
	}
}
