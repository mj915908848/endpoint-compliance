@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0deploy\windows\Scan-LocalDemo.ps1" -PackageRoot "%~dp0."
set "scan_exit=%errorlevel%"
if not "%scan_exit%"=="0" (
    echo.
    echo Local scan failed. Keep this window open and read the error above.
    pause
)
exit /b %scan_exit%
