package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/user"
	"runtime"
	"time"
)

// manifestFilename returns the name of the manifest written into the output
// directory when -manifest is set: "manifest" followed by the export start time
// as a UTC timestamp (YYYYmmDDHHMMSS) and a .txt extension, e.g.
// manifest20260526103021.txt. The manifest is a basic chain-of-custody record
// (export timestamps, host details, and a SHA-256 of each file).
func manifestFilename(start time.Time) string {
	return "manifest" + start.UTC().Format("20060102150405") + ".txt"
}

// exportRecord captures one exported file for the manifest.
type exportRecord struct {
	File   string
	Size   int64
	SHA256 string
}

// kv is an ordered key/value pair used to build the manifest's host section.
type kv struct {
	Key   string
	Value string
}

// sha256File returns the hex-encoded SHA-256 and byte size of the file at path.
func sha256File(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// writeManifest writes the export manifest to path. The content is assembled in
// memory and written in a single os.WriteFile call so a write failure (e.g. a
// full disk) surfaces as an error rather than a silently truncated file.
func writeManifest(path string, start, end time.Time, exported, skipped int, records []exportRecord) error {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown"
	}
	username := "unknown"
	if u, uErr := user.Current(); uErr == nil && u.Username != "" {
		username = u.Username
	}

	const tsFmt = "2006-01-02T15:04:05Z" // RFC 3339, UTC

	var b bytes.Buffer
	fmt.Fprintf(&b, "exportEventLogs Version %s\n", version)
	fmt.Fprintf(&b, "For more information, see %s\n\n", repoURL)

	fmt.Fprintf(&b, "Export commenced (UTC): %s\n", start.Format(tsFmt))
	fmt.Fprintf(&b, "Export finished  (UTC): %s\n", end.Format(tsFmt))
	fmt.Fprintf(&b, "Duration:               %s\n\n", end.Sub(start).Round(time.Second))

	host := []kv{
		{"Hostname", hostname},
		{"User", username},
		{"OS", runtime.GOOS + "/" + runtime.GOARCH},
		{"OS version", osVersion()},
		{"Logical CPUs", fmt.Sprintf("%d", runtime.NumCPU())},
	}
	host = append(host, extraHostInfo()...)

	width := 0
	for _, e := range host {
		if len(e.Key) > width {
			width = len(e.Key)
		}
	}
	for _, e := range host {
		fmt.Fprintf(&b, "%-*s %s\n", width+1, e.Key+":", e.Value)
	}
	fmt.Fprintln(&b)

	fmt.Fprintf(&b, "Files exported: %d (skipped %d)\n\n", exported, skipped)

	fmt.Fprintln(&b, "SHA-256 of each exported file (sha256  size-in-bytes  filename):")
	fmt.Fprintln(&b, "--------------------------------------------------------------------------------")
	for _, r := range records {
		fmt.Fprintf(&b, "%s  %d  %s\n", r.SHA256, r.Size, r.File)
	}

	return os.WriteFile(path, b.Bytes(), 0o644)
}
