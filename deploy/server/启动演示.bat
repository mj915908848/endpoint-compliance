@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0deploy\server\Start-Demo.ps1" -PackageRoot "%~dp0."
set "demo_exit=%errorlevel%"
if not "%demo_exit%"=="0" (
    echo.
    echo Demo startup failed. Keep this window open and send the error above to the maintainer.
    pause
)
exit /b %demo_exit%
