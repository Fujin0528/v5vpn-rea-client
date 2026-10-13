@echo off
setlocal
echo [1/2] Embedding icon and version info...
set "WINRES=%USERPROFILE%\go\bin\go-winres.exe"
if exist "%WINRES%" (
    "%WINRES%" simply --out internal/cmd/rsrc --icon assets/icon.ico --manifest gui --product-name "V5VPN Client" --product-version "2.0.0" --file-version "2.0.0" --file-description "V5VPN Client (MyGo)" --copyright "Copyright (C) 2026"
) else (
    echo [WARN] go-winres not found, falling back to plain go build ^(no exe icon^)
)

echo [2/2] Compiling v5vpn-rea.exe...
go build -ldflags="-H windowsgui" -o v5vpn-rea.exe ./internal/cmd

if %errorlevel% equ 0 (
    echo [SUCCESS] Build completed successfully: v5vpn-rea.exe
) else (
    echo [ERROR] Build failed!
)
endlocal
