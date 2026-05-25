#!/usr/bin/env sh
# Build stripped Windows binaries for exportEventLogs (amd64 + arm64).
# The -s -w linker flags strip the symbol table and DWARF debug info (~30%
# smaller); -trimpath keeps local build paths out of the binary.
set -e
cd "$(dirname "$0")"

LDFLAGS="-s -w"

GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="$LDFLAGS" -o exportEventLogs.exe .
GOOS=windows GOARCH=arm64 go build -trimpath -ldflags="$LDFLAGS" -o exportEventLogs_arm64.exe .

echo "built:"
echo "  exportEventLogs.exe        (windows/amd64)"
echo "  exportEventLogs_arm64.exe  (windows/arm64)"
