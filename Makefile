# Build stripped Windows binaries for exportEventLogs.
# -s -w strip the symbol table and DWARF debug info (~30% smaller);
# -trimpath keeps local build paths out of the binary.
# (Targets assume a Unix-like shell; use build.bat on native Windows.)

LDFLAGS := -s -w
BUILD   := go build -trimpath -ldflags="$(LDFLAGS)"

.PHONY: all amd64 arm64 native test vet clean

all: amd64 arm64

amd64:
	GOOS=windows GOARCH=amd64 $(BUILD) -o exportEventLogs.exe .

arm64:
	GOOS=windows GOARCH=arm64 $(BUILD) -o exportEventLogs_arm64.exe .

# Build for the current platform (e.g. when running on the Windows host itself).
native:
	$(BUILD) -o exportEventLogs$(shell go env GOEXE) .

test:
	go test ./...

vet:
	go vet ./...
	GOOS=windows go vet ./...

clean:
	rm -f exportEventLogs.exe exportEventLogs_arm64.exe exportEventLogs
