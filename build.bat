@echo off
setlocal
echo [1/2] Embedding icon and version info...
rem Single source of truth: mygo.json "version" (same as GitHub release tag v<version>)
for /f "delims=" %%v in ('powershell -noprofile -command "(Get-Content mygo.json | ConvertFrom-Json).version"') do set "APPVER=%%v"
if not defined APPVER set "APPVER=0.1.0"
echo version: %APPVER%
set "WINRES=%USERPROFILE%\go\bin\go-winres.exe"
if exist "%WINRES%" (
    "%WINRES%" simply --out internal/cmd/rsrc --icon assets/icon.ico --manifest gui --product-name "V5VPN Client" --product-version "%APPVER%" --file-version "%APPVER%" --file-description "V5VPN Client (MyGo)" --copyright "Copyright (C) 2026"
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
