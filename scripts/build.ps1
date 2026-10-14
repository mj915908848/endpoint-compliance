#requires -Version 5.1
[CmdletBinding()]
param([string]$Dotnet='dotnet', [string]$NodePackageManager='npm')
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    Push-Location (Join-Path $root 'ui')
    try { & $NodePackageManager ci; if($LASTEXITCODE -ne 0){throw 'npm ci failed'}; & $NodePackageManager test; if($LASTEXITCODE -ne 0){throw 'UI tests failed'}; & $NodePackageManager run build; if($LASTEXITCODE -ne 0){throw 'UI build failed'} } finally { Pop-Location }
    & $Dotnet run --project tests/Compliance.Core.Tests; if($LASTEXITCODE -ne 0){throw 'Core tests failed'}
    & $Dotnet test tests/Compliance.Server.Tests; if($LASTEXITCODE -ne 0){throw 'Server tests failed'}
    & $Dotnet run --project tests/Compliance.Agent.Tests; if($LASTEXITCODE -ne 0){throw 'Agent tests failed'}
    & $Dotnet publish src/Compliance.Server -c Release -r win-x64 --self-contained true -o artifacts/package/server-windows-x64; if($LASTEXITCODE -ne 0){throw 'Server publish failed'}
    & $Dotnet publish src/Compliance.Agent -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o artifacts/package/agent-windows-x64; if($LASTEXITCODE -ne 0){throw 'Agent publish failed'}
    & $Dotnet publish src/Compliance.Tray -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o artifacts/package/tray-windows-x64; if($LASTEXITCODE -ne 0){throw 'Tray publish failed'}
} finally { Pop-Location }
