package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestManifest(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Application.evtx"), []byte("hello evtx"), 0o644); err != nil {
		t.Fatal(err)
	}

	sum, size, err := sha256File(filepath.Join(dir, "Application.evtx"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("sha256(Application.evtx)=%s size=%d", sum, size)

	recs := []exportRecord{{File: "Application.evtx", Size: size, SHA256: sum}}
	start := time.Date(2026, 5, 26, 10, 30, 21, 0, time.UTC)
	end := start.Add(3*time.Minute + 21*time.Second)

	name := manifestFilename(start)
	if want := "manifest20260526103021.txt"; name != want {
		t.Errorf("manifestFilename = %q, want %q", name, want)
	}

	path := filepath.Join(dir, name)
	if err := writeManifest(path, start, end, 1, 5, recs); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("\n----- %s -----\n%s", name, out)
}

func TestFilterChannels(t *testing.T) {
	channels := []string{
		"Application",
		"Security",
		"Microsoft-Windows-Windows Defender/Operational",
		"Microsoft-Windows-Security-Mitigations/KernelMode",
	}
	got := filterChannels(channels, "DEFENDER") // case-insensitive
	if len(got) != 1 || got[0] != "Microsoft-Windows-Windows Defender/Operational" {
		t.Errorf("defender match = %v", got)
	}
	if got := filterChannels(channels, "security"); len(got) != 2 {
		t.Errorf("security match = %v, want 2", got)
	}
	if got := filterChannels(channels, "nomatch"); len(got) != 0 {
		t.Errorf("nomatch = %v, want empty", got)
	}
}
