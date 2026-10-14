param([string]$InstallDirectory="$env:ProgramFiles\ComplianceAgent",[string]$DataDirectory="$env:ProgramData\ComplianceAgent",[switch]$RemoveData)
$ErrorActionPreference='Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator required' }
if (Get-Process 'Compliance.Tray' -ErrorAction SilentlyContinue) { throw 'Exit all user tray instances before uninstalling; files and service retained' }
if (Get-Service ComplianceAgent -ErrorAction SilentlyContinue) {
    & sc.exe stop ComplianceAgent | Out-Null
    $service = Get-Service ComplianceAgent -ErrorAction Stop
    $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
    if ($service.Status -ne 'Stopped') { throw 'Service did not stop; files retained' }
    & sc.exe delete ComplianceAgent | Out-Null
    if($LASTEXITCODE -ne 0) { throw 'Service deletion failed; files retained' }
}
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'ComplianceTray' -ErrorAction SilentlyContinue
Write-Warning 'Review OS application/browser policies and approval records before deleting agent files. This build does not apply native block rules automatically.'
if(Test-Path $InstallDirectory) { Remove-Item $InstallDirectory -Recurse -Force }
if($RemoveData) { Write-Warning 'Removing device identity, signed policy cache, notifications and unsent events'; Remove-Item $DataDirectory -Recurse -Force }
