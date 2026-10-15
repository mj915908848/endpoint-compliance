@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0deploy\windows\Install-TrialService.ps1" -PackageRoot "%~dp0." -Production
set "exit_code=%errorlevel%"
if not "%exit_code%"=="0" (
    echo.
    echo Install failed. Keep this window open and read the error above.
    pause
)
exit /b %exit_code%
