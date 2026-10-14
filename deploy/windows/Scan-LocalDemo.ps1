#requires -Version 5.1
[CmdletBinding()]
param([string]$PackageRoot, [string]$ServerUrl)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This scan requires Windows.' }
if ([string]::IsNullOrWhiteSpace($PackageRoot)) {
    $scriptFile = $MyInvocation.MyCommand.Path
    if ([string]::IsNullOrWhiteSpace($scriptFile)) { throw 'Cannot determine package root; provide -PackageRoot.' }
    $PackageRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $scriptFile))
}
$PackageRoot = (Resolve-Path -LiteralPath $PackageRoot -ErrorAction Stop).ProviderPath
$scriptPath = $MyInvocation.MyCommand.Path
if (-not [string]::IsNullOrWhiteSpace($ServerUrl) -and $ServerUrl -notmatch '^http://[0-9.]+:[0-9]{2,5}/?$') { throw 'Use an explicit HTTP IPv4 address and port.' }
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $arguments = '-NoExit -NoProfile -ExecutionPolicy Bypass -File "' + $scriptPath + '" -PackageRoot "' + $PackageRoot + '"'
    if (-not [string]::IsNullOrWhiteSpace($ServerUrl)) { $arguments += ' -ServerUrl "' + $ServerUrl + '"' }
    Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -ArgumentList $arguments | Out-Null
    Write-Host 'Administrator window opened. Continue the scan there.'
    exit 0
}
if ([string]::IsNullOrWhiteSpace($ServerUrl)) { $ServerUrl = Read-Host 'Management server URL (example: http://192.168.1.15:5080)' }
$ServerUrl = $ServerUrl.Trim().TrimEnd([char]'/')
if (-not ($ServerUrl -match '^http://([0-9]{1,3}(\.[0-9]{1,3}){3}):([0-9]{2,5})$')) { throw 'Use an explicit HTTP loopback or private IPv4 address and port, without a path.' }
$serverAddress = $null
if (-not [System.Net.IPAddress]::TryParse($Matches[1], [ref]$serverAddress)) { throw 'Invalid server IP address.' }
$octets = $serverAddress.GetAddressBytes()
if ($octets.Length -ne 4 -or -not ($octets[0] -eq 127 -or $octets[0] -eq 10 -or ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or ($octets[0] -eq 192 -and $octets[1] -eq 168))) { throw 'HTTP trial allows only loopback or private IPv4 addresses.' }
$parsedUrl = [Uri]$ServerUrl
if ($parsedUrl.Port -lt 1 -or $parsedUrl.Port -gt 65535) { throw 'Invalid server port.' }
$serverUrl = $parsedUrl.GetLeftPart([System.UriPartial]::Authority)
$agent = Join-Path $PackageRoot 'agent-windows-x64\Compliance.Agent.exe'
if (-not (Test-Path -LiteralPath $agent -PathType Leaf)) { throw 'Agent executable missing; extract the complete Windows trial package.' }
try { $status = Invoke-RestMethod -Uri "$serverUrl/api/status" -TimeoutSec 5 -ErrorAction Stop }
catch { throw 'Cannot reach the management server. Check its HTTP URL, listener, and Windows firewall.' }
if ($status.mode -ne 'LoopbackDemo' -and $status.mode -ne 'LanHttpTrial') { throw 'The management server has not enabled HTTP trial mode.' }
$sha = [System.Security.Cryptography.SHA256]::Create()
try { $serverKey = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($serverUrl)))).Replace('-', '').Substring(0, 16) }
finally { $sha.Dispose() }
$data = Join-Path $env:ProgramData ("ComplianceAgentHttpTrial-$serverKey")
$configPath = Join-Path $data 'agent.json'
$enrolled = $false
if (Test-Path -LiteralPath $configPath -PathType Leaf) {
    $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    if ($config.serverUrl -ne $serverUrl) { throw 'Stored trial identity does not match this server URL; inspect it before proceeding.' }
    $enrolled = -not [string]::IsNullOrWhiteSpace($config.deviceId)
}
$arguments = @('--local-demo','--once','--data-dir',$data,'--config',$configPath,'--server',$serverUrl)
if (-not $enrolled) {
    $code = (Read-Host 'Paste a NEW one-time enrollment code from the management page').Trim()
    if ($code -cnotmatch '^[0-9a-f]{64}$') { throw 'Enrollment code must be 64 lowercase hexadecimal characters.' }
    $arguments += @('--enroll','--code',$code)
}
& $agent @arguments
if ($LASTEXITCODE -ne 0) { throw "Local scan failed with exit code $LASTEXITCODE. See the message above." }
Write-Host 'Local scan finished. Refresh the device page to inspect its report and coverage.'
