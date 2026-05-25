@echo off
REM Build stripped Windows binaries for exportEventLogs (amd64 + arm64).
REM The -s -w linker flags strip the symbol table and DWARF debug info (~30%%
REM smaller); -trimpath keeps local build paths out of the binary.
setlocal
cd /d "%~dp0"

set LDFLAGS=-s -w
set GOOS=windows

set GOARCH=amd64
go build -trimpath -ldflags="%LDFLAGS%" -o exportEventLogs.exe .
if errorlevel 1 exit /b 1

set GOARCH=arm64
go build -trimpath -ldflags="%LDFLAGS%" -o exportEventLogs_arm64.exe .
if errorlevel 1 exit /b 1

echo built exportEventLogs.exe (amd64) and exportEventLogs_arm64.exe (arm64)
