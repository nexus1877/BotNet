@echo off
cd /d "%~dp0"
set GOOS=windows
set GOARCH=amd64
set CGO_ENABLED=0
echo [+] Building agent...
go build -ldflags="-s -w -H windowsgui -buildid=" -trimpath -o update.exe .
if %errorlevel% equ 0 (
    echo [+] Built: update.exe (%GOOS%/%GOARCH%)
    certutil -hashfile update.exe SHA256 | find /v "hash"
) else (
    echo [-] Build failed
)
