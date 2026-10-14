@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0deploy\windows\Uninstall-TrialService.ps1"
set "exit_code=%errorlevel%"
if not "%exit_code%"=="0" (
    echo.
    echo Uninstall failed. Keep this window open and read the error above.
    pause
)
exit /b %exit_code%
