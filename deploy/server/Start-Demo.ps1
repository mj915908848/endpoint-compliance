#requires -Version 5.1
[CmdletBinding()]
param([string]$PackageRoot, [int]$Port = 5080, [string]$ListenAddress)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This launch script requires Windows. For cross-platform development follow README.' }
if ($Port -lt 1024 -or $Port -gt 65535) { throw 'Port must be 1024..65535' }
if ([string]::IsNullOrWhiteSpace($ListenAddress)) { $ListenAddress = Read-Host 'Server IPv4 address on this computer (Enter for local-only 127.0.0.1)' }
if ([string]::IsNullOrWhiteSpace($ListenAddress)) { $ListenAddress = '127.0.0.1' }
$listenIp = $null
if (-not [System.Net.IPAddress]::TryParse($ListenAddress, [ref]$listenIp)) { throw 'Enter an IPv4 address assigned to this computer.' }
$octets = $listenIp.GetAddressBytes()
if ($octets.Length -ne 4 -or -not ($octets[0] -eq 127 -or $octets[0] -eq 10 -or ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or ($octets[0] -eq 192 -and $octets[1] -eq 168))) { throw 'HTTP trial permits only loopback or private IPv4 listeners.' }
$lanTrial = $octets[0] -ne 127
if ([string]::IsNullOrWhiteSpace($PackageRoot)) {
    $scriptFile = $MyInvocation.MyCommand.Path
    if ([string]::IsNullOrWhiteSpace($scriptFile)) { throw 'Cannot determine demo script location; provide -PackageRoot.' }
    $scriptDirectory = Split-Path -Parent $scriptFile
    $PackageRoot = Split-Path -Parent (Split-Path -Parent $scriptDirectory)
}
$PackageRoot = (Resolve-Path -LiteralPath $PackageRoot -ErrorAction Stop).ProviderPath
$exe = Join-Path $PackageRoot 'server-windows-x64\Compliance.Server.exe'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'Self-contained server executable not found; use the Windows trial package.' }
$state = Join-Path $env:LOCALAPPDATA 'CustomerComplianceDemo'
New-Item -ItemType Directory -Path $state -Force | Out-Null
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $state /inheritance:r /grant:r ("*{0}:(OI)(CI)F" -f $sid) '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot secure demo state directory; not starting.' }
$configPath = Join-Path $state 'demo-accounts.json'
function New-RandomPassword {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return [Convert]::ToBase64String($bytes)
}
if (-not (Test-Path -LiteralPath $configPath)) {
    $accounts = @(
        @{ username='admin'; password=(New-RandomPassword); roles=@('Reader','Operator','Publisher') }
    )
    # -InputObject keeps a one-element array as a JSON array; piping would unwrap it into an object.
    ConvertTo-Json -InputObject $accounts -Depth 5 | Set-Content -LiteralPath $configPath -Encoding UTF8
    $credentialPath = Join-Path $state 'demo-login.txt'
    "Local demo credentials only. Do not share this file.`r`nadmin: $($accounts[0].password)" | Set-Content -LiteralPath $credentialPath -Encoding UTF8
}
$names = @('Compliance__DemoMode','Compliance__DemoHttpLan','Compliance__Storage','Compliance__Database','Compliance__SigningKeyPath','Compliance__BootstrapUsers','ASPNETCORE_URLS')
$prior = @{}
foreach ($name in $names) { $prior[$name] = [Environment]::GetEnvironmentVariable($name,'Process') }
try {
    $env:Compliance__DemoMode = 'true'
    if ($lanTrial) { $env:Compliance__DemoHttpLan = 'true' }
    else { $env:Compliance__DemoHttpLan = 'false' }
    $env:Compliance__Storage = 'Sqlite'
    $env:Compliance__Database = Join-Path $state 'platform.sqlite'
    $env:Compliance__SigningKeyPath = Join-Path $state 'policy-signing.pem'
    $env:Compliance__BootstrapUsers = Get-Content -LiteralPath $configPath -Raw
    $env:ASPNETCORE_URLS = "http://${ListenAddress}:$Port"
    Write-Host "HTTP trial URL: $env:ASPNETCORE_URLS"
    if ($lanTrial) { Write-Warning 'LAN HTTP trial is unencrypted. Use only on a trusted isolated network; login and reports are visible to network observers.' }
    Write-Host "Generated login details: $(Join-Path $state 'demo-login.txt')"
    Write-Host 'Audit trial only. No automatic application or website blocking. Ctrl+C to stop.'
    $server = Start-Process -FilePath $exe -WorkingDirectory (Split-Path -Parent $exe) -NoNewWindow -PassThru
    try {
        $ready = $false
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while ([DateTime]::UtcNow -lt $deadline) {
            if ($server.HasExited) { throw "Demo server exited with code $($server.ExitCode)" }
            try {
                $response = Invoke-WebRequest -Uri "$env:ASPNETCORE_URLS/api/status" -UseBasicParsing -TimeoutSec 2
                if ($response.StatusCode -eq 200) { $ready = $true; break }
            } catch { }
            Start-Sleep -Milliseconds 500
        }
        if (-not $ready) { throw 'Demo server did not become ready within 30 seconds.' }
        try { Start-Process "$env:ASPNETCORE_URLS/" }
        catch { Write-Warning "Browser did not open automatically. Visit $env:ASPNETCORE_URLS/ manually." }
        $server.WaitForExit()
        if ($server.ExitCode -ne 0) { throw "Demo server exited with code $($server.ExitCode)" }
    }
    finally {
        if (-not $server.HasExited) { $server.Kill(); $server.WaitForExit() }
        $server.Dispose()
    }
}
finally { foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name,$prior[$name],'Process') } }
