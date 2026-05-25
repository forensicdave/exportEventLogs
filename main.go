// Command exportEventLogs exports every Windows event log channel to .evtx
// files in a directory.
//
// It uses the Windows Event Log API in wevtapi.dll directly (EvtOpenChannelEnum
// to list channels, EvtExportLog to export each one) rather than shelling out to
// wevtutil.exe. That means it does not depend on wevtutil being present, spawns
// no child processes, and keeps working even where wevtutil is blocked or has
// been removed. Channels that can't be exported (some Analytic/Debug logs, or
// ones the current user lacks rights to) are skipped and reported rather than
// aborting the run.
//
// Build for Windows (works as a cross-compile from any OS):
//
//	GOOS=windows GOARCH=amd64 go build -o exportEventLogs.exe
//
// Run it from an elevated (Administrator) console so restricted logs such as
// Security are included:
//
//	exportEventLogs.exe -o C:\export
//
// For more information, see https://github.com/forensicdave/exportEventLogs
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	version = "1.1"
	repoURL = "https://github.com/forensicdave/exportEventLogs"
)

// printBanner writes the program name, version, and project URL. It is shown on
// startup, with -h/--help, and with -v.
func printBanner(w io.Writer) {
	fmt.Fprintf(w, "exportEventLogs Version %s\n", version)
	fmt.Fprintf(w, "For more information, see %s\n", repoURL)
}

func main() {
	var (
		output      string
		debug       bool
		showVersion bool
		manifest    bool
		match       string
	)
	const defaultDir = "evtx-export"
	flag.StringVar(&output, "o", defaultDir, "directory to write exported .evtx files to")
	flag.StringVar(&output, "output", defaultDir, "directory to write exported .evtx files to (alias of -o)")
	flag.StringVar(&match, "match", "",
		"only export channels whose name contains this substring (case-insensitive), e.g. -match defender")
	flag.BoolVar(&debug, "debug", false, "enable verbose logging on stderr")
	flag.BoolVar(&showVersion, "v", false, "print version and exit")
	flag.BoolVar(&manifest, "manifest", false,
		"write a timestamped manifest (manifest<UTC-YYYYmmDDHHMMSS>.txt; export times, host info, and a SHA-256 of each file) to the output directory")

	// -h/--help prints the version banner ahead of the usage text.
	flag.Usage = func() {
		printBanner(os.Stderr)
		fmt.Fprintf(os.Stderr, "\nUsage of %s:\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}
	flag.Parse()

	if showVersion {
		printBanner(os.Stderr)
		return
	}

	// Always announce the version on startup.
	printBanner(os.Stderr)

	debugf := func(format string, a ...any) {
		if debug {
			fmt.Fprintf(os.Stderr, "DEBUG: "+format+"\n", a...)
		}
	}

	channels, err := listChannels()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: could not list channels: %v\n", err)
		os.Exit(1)
	}
	debugf("found %d channel(s)", len(channels))

	if match != "" {
		channels = filterChannels(channels, match)
		debugf("%d channel(s) match %q", len(channels), match)
		if len(channels) == 0 {
			fmt.Fprintf(os.Stderr, "no channels matched %q\n", match)
			os.Exit(1)
		}
	}

	if err := os.MkdirAll(output, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: could not create output directory %q: %v\n", output, err)
		os.Exit(1)
	}

	start := time.Now().UTC()

	var exported, skipped int
	var records []exportRecord
	seen := map[string]int{} // guard against two channels sanitizing to the same name
	for _, ch := range channels {
		base := sanitize(ch)
		name := base
		if n := seen[base]; n > 0 {
			name = fmt.Sprintf("%s (%d)", base, n)
		}
		seen[base]++

		dest := filepath.Join(output, name+".evtx")
		debugf("exporting %q -> %s", ch, dest)

		// protect() turns any panic into an error so one pathological channel
		// can never abort the whole export.
		if err := protect(func() error { return exportChannel(ch, dest) }); err != nil {
			skipped++
			fmt.Fprintf(os.Stderr, "WARN: skipped %q: %v\n", ch, err)
			continue
		}
		exported++

		if manifest {
			var rec exportRecord
			err := protect(func() error {
				sum, size, hErr := sha256File(dest)
				if hErr != nil {
					return hErr
				}
				rec = exportRecord{File: filepath.Base(dest), Size: size, SHA256: sum}
				return nil
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "WARN: could not hash %s: %v\n", dest, err)
			} else {
				records = append(records, rec)
			}
		}
	}

	end := time.Now().UTC()
	fmt.Fprintf(os.Stderr, "done: exported %d, skipped %d -> %s\n", exported, skipped, output)

	if manifest {
		path := filepath.Join(output, manifestFilename(start))
		err := protect(func() error { return writeManifest(path, start, end, exported, skipped, records) })
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: could not write manifest: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "manifest written: %s\n", path)
		}
	}

	if exported == 0 {
		os.Exit(1)
	}
}

// protect runs fn and converts any panic into an error, so an unexpected fault
// (a bad syscall, malformed firmware data, and so on) degrades to a skipped item
// instead of crashing the whole program.
func protect(fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return fn()
}

// filterChannels returns the channels whose name contains sub, compared
// case-insensitively. For example sub="defender" keeps every Defender channel.
func filterChannels(channels []string, sub string) []string {
	sub = strings.ToLower(sub)
	var out []string
	for _, ch := range channels {
		if strings.Contains(strings.ToLower(ch), sub) {
			out = append(out, ch)
		}
	}
	return out
}

// sanitize turns a channel name into a safe Windows filename. Channel names
// contain '/' (and may contain other reserved characters), none of which are
// legal in a filename, so each is replaced with '-'.
func sanitize(name string) string {
	mapped := strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|':
			return '-'
		}
		if r < 0x20 {
			return '-'
		}
		return r
	}, name)
	// Windows filenames may not end in a space or a dot.
	mapped = strings.TrimRight(mapped, " .")
	if mapped == "" {
		mapped = "channel"
	}
	return mapped
}
