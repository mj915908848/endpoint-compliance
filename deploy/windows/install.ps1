param(
    [Parameter(Mandatory=$true)][string]$ServerUrl,
    [Parameter(Mandatory=$true)][string]$PackageDirectory,
    [string]$InstallDirectory = "$env:ProgramFiles\ComplianceAgent",
    [string]$DataDirectory = "$env:ProgramData\ComplianceAgent",
    # Trial only: allow an HTTP management server on a loopback or private IPv4 address that reports trial mode.
    [switch]$HttpTrial
)
$ErrorActionPreference = 'Stop'
if ($HttpTrial) {
    if ($ServerUrl -notmatch '^http://(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)[0-9.]+:[0-9]{2,5}$') { throw 'HTTP trial needs http://<loopback or private IPv4>:<port> without a path.' }
}
elseif ($ServerUrl.StartsWith('http://',[StringComparison]::OrdinalIgnoreCase)) { throw 'The persistent service requires HTTPS. For an HTTP trial pass -HttpTrial (see Install-TrialService.ps1).' }
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator required' }
if (-not $HttpTrial -and -not $ServerUrl.StartsWith('https://',[StringComparison]::OrdinalIgnoreCase)) { throw 'Production agent requires HTTPS' }
if (Get-Service ComplianceAgent -ErrorAction SilentlyContinue) { throw 'Service exists; use approved upgrade procedure' }
$agent = Join-Path $PackageDirectory 'Compliance.Agent.exe'
$tray = Join-Path $PackageDirectory 'Compliance.Tray.exe'
if (-not (Test-Path $agent) -or -not (Test-Path $tray)) { throw 'Package must include both published executables' }
# Standard users may create folders under ProgramData. A data directory someone else created first could hold an
# agent.json pointing at another server, and its owner can always grant themselves access again; only one left by an
# earlier install (owned by SYSTEM or Administrators, as the service leaves it) is reused. A new one is created with its
# owner and permissions in one step, so no one can create it, or open it, between this check and the ACL change below.
if (-not (Test-Path -LiteralPath $DataDirectory)) {
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule([Security.Principal.SecurityIdentifier]$sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    }
    # Windows PowerShell 5.1 has the overload; PowerShell 7 moved it to FileSystemAclExtensions.
    if ($PSVersionTable.PSEdition -eq 'Desktop') { [IO.Directory]::CreateDirectory($DataDirectory, $security) | Out-Null }
    else { [IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($DataDirectory), $security) }
}
foreach ($item in @(Get-Item -LiteralPath $DataDirectory -Force) + @(Get-ChildItem -LiteralPath $DataDirectory -Force)) {
    $owner = (Get-Acl -LiteralPath $item.FullName).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or @('S-1-5-18', 'S-1-5-32-544') -notcontains $owner) {
        throw "$($item.FullName) is owned by $owner, not SYSTEM or Administrators: someone may have created $DataDirectory before installation. Remove it and install again."
    }
}
New-Item -ItemType Directory -Path $InstallDirectory,$DataDirectory -Force | Out-Null
& icacls.exe $DataDirectory /setowner '*S-1-5-32-544' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Data owner change failed' }
& icacls.exe $InstallDirectory /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' 'Users:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Install ACL failed' }
& icacls.exe $DataDirectory /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Data ACL failed' }
Copy-Item (Join-Path $PackageDirectory '*') $InstallDirectory -Recurse -Force
$configPath = Join-Path $DataDirectory 'agent.json'
if (-not (Test-Path $configPath)) {
    @{ serverUrl=$ServerUrl; dataDirectory=$DataDirectory; deviceId=$null; policyPublicKeyPem=$null; policyKeyId=$null; httpTrial=[bool]$HttpTrial } | ConvertTo-Json -Compress | Set-Content -Path $configPath -Encoding UTF8
}
$binary = '"' + (Join-Path $InstallDirectory 'Compliance.Agent.exe') + '" --config "' + $configPath + '"'
# New-Service passes the quoted binary path straight to the service API; Windows PowerShell 5.1 mangles
# embedded quotes when handing them to sc.exe on the command line.
# The display name is 终端合规客户端, escaped so this file stays ASCII for Windows PowerShell 5.1.
$displayName = [regex]::Unescape('\u7ec8\u7aef\u5408\u89c4\u5ba2\u6237\u7aef')
New-Service -Name ComplianceAgent -BinaryPathName $binary -DisplayName $displayName -StartupType Automatic | Out-Null
$output = & sc.exe failure ComplianceAgent reset= 86400 actions= restart/60000/restart/60000/restart/300000
if ($LASTEXITCODE -ne 0) { throw "SCM recovery configuration failed: $output" }
$output = & sc.exe failureflag ComplianceAgent 1
if ($LASTEXITCODE -ne 0) { throw "SCM failure flag failed: $output" }
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'ComplianceTray' -Value ('"' + (Join-Path $InstallDirectory 'Compliance.Tray.exe') + '"') -PropertyType String -Force | Out-Null
Write-Host 'Installed. Enroll once with: Compliance.Agent.exe --config <ProgramData\ComplianceAgent\agent.json> --enroll --code <one-time-code>. Start service after enrollment.'
