# exportEventLogs

Version 1.1 — <https://github.com/forensicdave/exportEventLogs>

A rather useful small program that exports **every** (or selected matching - you choose!) Windows event log channel to `.evtx`
files in a directory. It compiles to a single self-contained `.exe` — nothing to
install on the target host (no Python, no runtime).

It calls the **Windows Event Log API** in `wevtapi.dll` directly
(`EvtOpenChannelEnum` to list channels, `EvtExportLog` to export each one) —
the same entry points `wevtutil.exe` wraps. Compared with shelling out to
`wevtutil`, this means it:

- **does not depend on `wevtutil` being present** (works even if it's blocked by
  AppLocker/WDAC/EDR, renamed, or removed);
- **spawns no child processes** — a host has 1000+ channels, so the old
  per-channel `wevtutil` approach created 1000+ process-creation events
  (Sysmon ID 1 / Security 4688). This runs entirely in-process: quieter and
  faster.

Channel names such as `Microsoft-Windows-PowerShell/Operational` are sanitized
into legal filenames (reserved characters → `-`). It is the single-binary
equivalent of exporting every channel with `wevtutil epl` in a loop.

> Still requires a running Windows Event Log service (and `wevtapi.dll`, a core
> OS component). That's a far more fundamental dependency than the `wevtutil`
> binary — if it's missing, event logging itself isn't working.

## Antivirus / VirusTotal false positive

Some antivirus engines on VirusTotal flag the prebuilt `exportEventLogs.exe` as
potentially malicious. **This is a false positive.** Like many digital-forensics
and incident-response tools, it does things that overlap with attacker
behaviour — it bulk-exports every event log channel and reads firmware/registry
identifiers (manufacturer, serial, UUID) for the manifest — and it's an unsigned,
low-prevalence Go binary, all of which trip heuristic and machine-learning
detections.

The entire source is in this repository. If you'd rather not trust the prebuilt
binary, **review the code and compile it yourself** (see [Build](#build)) — the
result is byte-for-byte the same tool. Each release also ships a SHA-256 so you
can verify the download, and you're welcome to report the false positive to your
AV vendor.

> **Coming soon:** `exportEventLogs.exe` will shortly be **code-signed** with an
> Authenticode certificate. That should clear most of the antivirus flags and
> the Windows "unknown publisher" warnings described below.

### Running it when Windows blocks the file

Until the binary is code-signed and has built reputation, Windows may prevent
it from running on first launch. Depending on your security settings you may
need to:

- On the **SmartScreen** warning, click **More info → Run anyway**.
- In the file's **Properties** (right-click → Properties), tick **Unblock** at
  the bottom of the *General* tab — Windows sets this on anything downloaded
  from the internet.
- If **Microsoft Defender** quarantines it, restore it from *Windows Security →
  Virus & threat protection → Protection history*, and optionally allowlist it
  via *Manage settings → Exclusions → Add an exclusion → File*.
- With **Windows 11 Smart App Control (SAC)** enabled, unsigned, low-reputation
  binaries are blocked outright. You'd need to disable SAC under *Windows
  Security → App & browser control → Smart App Control settings*. **Note:** SAC
  is a one-way switch — once turned off it can only be re-enabled by resetting
  Windows. If that's not acceptable, build the tool yourself on the target host
  instead.

## When to fall back to PowerShell

In environments with **strict application control** — WDAC in signed-only mode,
AppLocker with publisher rules, or Smart App Control — an unsigned
`exportEventLogs.exe` is blocked at the EXE layer no matter how legitimate it
is, and the right tool is Microsoft's own signed `wevtutil` driven from
PowerShell:

```powershell
$dest = "C:\export"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
foreach ($log in (wevtutil el)) {
    $file = ($log -replace '[\\/]', '-') + '.evtx'
    wevtutil epl "$log" (Join-Path $dest $file) /ow:true 2>$null
}
```

This survives strict policy because `powershell.exe` and `wevtutil.exe` are both
Microsoft-signed, and the loop works in PowerShell **Constrained Language
Mode** (it's just process invocation). The trade-off is footprint and evidence:
you spawn one `wevtutil` child per channel — typically 1,000+ Security 4688 /
Sysmon 1 events on a normal host — and you don't get the chain-of-custody
manifest. `exportEventLogs` is built for the *complementary* case where you
control or have vetted the box and can pre-stage and hash-allowlist your
toolkit: one quiet process call, plus a hashed, timestamped, SMBIOS-stamped
manifest in the same run. Treat them as a pair in your IR runbook — signed
binary primary, PowerShell loop as the fallback. Once Authenticode signing
lands (see *Coming soon*, above), a WDAC policy that trusts the publishing
cert covers `exportEventLogs` the same way it covers Microsoft's tools, and
this gap narrows substantially.

## Build

The build scripts produce **both** Windows binaries (amd64 + arm64), stripped.
The `-s -w` linker flags drop the symbol table and DWARF debug info (~30%
smaller) and `-trimpath` keeps local build paths out of the binary — using a
script bakes these in so every build is consistent.

From macOS/Linux (or any Unix-like shell):

```bash
./build.sh        # or: make        (make amd64 / make arm64 / make native / make test / make vet)
```

Natively on the Windows host:

```cmd
build.bat
```

The equivalent raw command, if you prefer to build by hand:

```bash
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o exportEventLogs.exe .
```

> A plain `go build` (without these flags) produces a larger, unstripped binary —
> build through the scripts to keep the stripped output.

> Avoid packers such as UPX to shrink it further: packed executables are
> routinely flagged by antivirus/EDR — the last thing you want for a tool run on
> a monitored or potentially compromised host. The ~2 MB floor is mostly the Go
> runtime and is the practical minimum for a normal Go binary.

## Usage

Run from an **elevated (Administrator)** console so restricted logs such as
Security are included:

```cmd
exportEventLogs.exe -o C:\export
```

| Flag | Default | Description |
| --- | --- | --- |
| `-o`, `-output` | `evtx-export` | Directory to write the `.evtx` files to (created if missing). |
| `-match` | (all) | Only export channels whose name contains this substring, matched **case-insensitively** (e.g. `-match defender`). |
| `-manifest` | off | Also write a timestamped manifest (`manifest<UTC-YYYYmmDDHHMMSS>.txt`: export times in UTC, host info, and a SHA-256 of every exported file) to the output directory. |
| `-debug` | off | Verbose per-channel logging on stderr. |
| `-v` | off | Print the version and exit. |
| `-h` | — | Print the version and usage, then exit. |

The version banner (program name, version, and project URL) is printed to
**stderr** on every run, as well as with `-v` and `-h`.

## Behaviour

- Channels that can't be exported (some Analytic/Debug logs, or ones you lack
  rights to) are **skipped and reported** on stderr — one bad channel never
  aborts the run.
- A host typically has **1000+ channels**, many empty, so expect a lot of small
  files.
- An existing target file is removed first, so re-running overwrites previous
  exports.
- On exit it prints `done: exported N, skipped M -> <dir>`; exit code is non-zero
  if nothing was exported (e.g. not run on Windows, or the Event Log API was
  unavailable).

## Selecting which logs to export (`-match`)

By default every channel is exported. Pass `-match <substring>` to export only
the channels whose name contains that substring, compared case-insensitively:

```cmd
:: Just the Microsoft Defender logs
exportEventLogs.exe -o C:\export -match defender

:: Anything security-related
exportEventLogs.exe -o C:\export -match security

:: Combine with a manifest
exportEventLogs.exe -o C:\export -match powershell -manifest
```

If nothing matches, the program reports `no channels matched "<substring>"` and
exits non-zero. To target several unrelated keywords, run it once per keyword
(into the same output directory).

## Manifest (`-manifest`)

With `-manifest`, a `manifest<UTC-YYYYmmDDHHMMSS>.txt` (the timestamp is when the
export started, e.g. `manifest20260526103021.txt`) is written into the output
directory as a basic chain-of-custody record. It contains:

- the export start and finish times in **UTC** (RFC 3339), and the duration;
- **host details** (see below);
- a **SHA-256** and byte size for every exported `.evtx` file.

The host section combines cross-platform basics (hostname, user, OS/arch,
Windows version via `RtlGetVersion`, CPU count) with richer Windows-specific
identity gathered from the **firmware/SMBIOS** (`GetSystemFirmwareTable`) and a
few cheap APIs/registry reads:

- **Firmware / hardware:** BIOS vendor/version/date; system manufacturer, model,
  serial number, and **UUID**; baseboard and chassis serials/asset tag. (On a
  VM these reveal the hypervisor.)
- **Extras:** FQDN, total physical memory, OS product/edition and install date,
  the per-install **Machine GUID**, and the host **time zone** (handy for
  interpreting local timestamps in the logs).

All firmware/registry lookups are best-effort — anything unavailable (or left as
an OEM placeholder) is simply omitted. The values uniquely identify the physical
machine, so treat the manifest as sensitive.

```text
exportEventLogs Version 1.1
For more information, see https://github.com/forensicdave/exportEventLogs

Export commenced (UTC): 2026-05-26T10:00:00Z
Export finished  (UTC): 2026-05-26T10:03:21Z
Duration:               3m21s

Hostname:             WKS-WIN764BITB
User:                 SHIELDBASE\dave
OS:                   windows/amd64
OS version:           Windows 10.0 (Build 19045)
Logical CPUs:         8
FQDN:                 WKS-WIN764BITB.shieldbase.local
BIOS vendor:          LENOVO
BIOS version:         N2HET49W (1.32)
BIOS date:            04/21/2023
System manufacturer:  LENOVO
System product:       20XWCTO1WW
System serial:        PF3ABCDE
System UUID:          33221100-5544-7766-8899-AABBCCDDEEFF
Baseboard serial:     L1HF1A2B3C4
Chassis serial:       PF3ABCDE
Physical memory:      31.69 GiB (34029481984 bytes)
OS product:           Windows 10 Pro 22H2
OS installed (UTC):   2023-09-01T08:14:02Z
Machine GUID:         f0e1d2c3-b4a5-6789-0123-456789abcdef
Time zone:            GMT Standard Time (UTC+00:00)

Files exported: 312 (skipped 901)

SHA-256 of each exported file (sha256  size-in-bytes  filename):
--------------------------------------------------------------------------------
ae087973a5ca93f273081d0367f79953a0e3b8493298ef8ad64e56cf19d408b6  10  Application.evtx
...
```

The hash lines follow a `sha256  size  filename` layout that's easy to grep or
re-verify (e.g. with `Get-FileHash` on Windows or `sha256sum` elsewhere).

Once exported, convert the files with
[**convertEventLogs.py**](https://github.com/forensicdave/convertEventLogs) — a small
Python companion tool that turns `.evtx` files into JSON or CSV.

## More information

<https://github.com/forensicdave/exportEventLogs>
