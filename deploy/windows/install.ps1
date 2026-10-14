param(
    [Parameter(Mandatory=$true)][string]$ServerUrl,
    [Parameter(Mandatory=$true)][string]$PackageDirectory,
    [string]$InstallDirectory = "$env:ProgramFiles\ComplianceAgent",
    [string]$DataDirectory = "$env:ProgramData\ComplianceAgent"
)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator required' }
if (-not $ServerUrl.StartsWith('https://',[StringComparison]::OrdinalIgnoreCase)) { throw 'Production agent requires HTTPS' }
if (Get-Service ComplianceAgent -ErrorAction SilentlyContinue) { throw 'Service exists; use approved upgrade procedure' }
$agent = Join-Path $PackageDirectory 'Compliance.Agent.exe'
$tray = Join-Path $PackageDirectory 'Compliance.Tray.exe'
if (-not (Test-Path $agent) -or -not (Test-Path $tray)) { throw 'Package must include both published executables' }
New-Item -ItemType Directory -Path $InstallDirectory,$DataDirectory -Force | Out-Null
& icacls.exe $InstallDirectory /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' 'Users:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Install ACL failed' }
& icacls.exe $DataDirectory /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Data ACL failed' }
Copy-Item (Join-Path $PackageDirectory '*') $InstallDirectory -Recurse -Force
$configPath = Join-Path $DataDirectory 'agent.json'
if (-not (Test-Path $configPath)) {
    @{ serverUrl=$ServerUrl; dataDirectory=$DataDirectory; deviceId=$null; policyPublicKeyPem=$null; policyKeyId=$null } | ConvertTo-Json -Compress | Set-Content -Path $configPath -Encoding UTF8
}
$binary = '"' + (Join-Path $InstallDirectory 'Compliance.Agent.exe') + '" --config "' + $configPath + '"'
& sc.exe create ComplianceAgent binPath= $binary start= auto obj= LocalSystem DisplayName= 'Compliance Agent' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Service creation failed' }
& sc.exe failure ComplianceAgent reset= 86400 actions= restart/60000/restart/60000/restart/300000 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'SCM recovery configuration failed' }
& sc.exe failureflag ComplianceAgent 1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'SCM failure flag failed' }
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'ComplianceTray' -Value ('"' + (Join-Path $InstallDirectory 'Compliance.Tray.exe') + '"') -PropertyType String -Force | Out-Null
Write-Host 'Installed. Enroll once with: Compliance.Agent.exe --config <ProgramData\ComplianceAgent\agent.json> --enroll --code <one-time-code>. Start service after enrollment.'
