#requires -Version 5.1
# 试用：把客户端安装为常驻 Windows 服务，连接内网 HTTP 试用管理端。正式部署请用 HTTPS 并直接调用 install.ps1。
[CmdletBinding()]
param([string]$PackageRoot)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw '此脚本只能在 Windows 上运行。' }
$scriptPath = $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($PackageRoot)) { $PackageRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $scriptPath)) }
$PackageRoot = (Resolve-Path -LiteralPath $PackageRoot).ProviderPath
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -ArgumentList ('-NoExit -NoProfile -ExecutionPolicy Bypass -File "' + $scriptPath + '" -PackageRoot "' + $PackageRoot + '"') | Out-Null
    Write-Host '已打开管理员窗口，请在新窗口中继续。'
    exit 0
}

$package = Join-Path $PackageRoot 'agent-windows-x64'
$installDir = Join-Path $env:ProgramFiles 'ComplianceAgent'
$dataDir = Join-Path $env:ProgramData 'ComplianceAgent'
$uninstall = Join-Path $PSScriptRoot 'Uninstall-TrialService.ps1'

if (Get-Service ComplianceAgent -ErrorAction SilentlyContinue) {
    $answer = Read-Host '本机已安装常驻客户端。是否卸载后重新安装？原有登记身份会被清除 (Y/N)'
    if ($answer -notmatch '^[Yy]') { Write-Host '已取消。'; exit 0 }
    & $uninstall -Quiet
}

$serverUrl = (Read-Host '管理端地址（直接回车使用 http://127.0.0.1:5080）').Trim().TrimEnd('/')
if ([string]::IsNullOrWhiteSpace($serverUrl)) { $serverUrl = 'http://127.0.0.1:5080' }
try { $status = Invoke-RestMethod -Uri "$serverUrl/api/status" -TimeoutSec 5 }
catch { throw "无法连接管理端 $serverUrl。请确认管理端正在运行，地址和端口正确，并检查防火墙。" }
if ($status.mode -ne 'LoopbackDemo' -and $status.mode -ne 'LanHttpTrial') { throw '该管理端不是试用模式。正式环境请使用 HTTPS 部署。' }

$code = (Read-Host '请粘贴管理端“终端登记”页面生成的新登记码').Trim()
if ($code -cnotmatch '^[0-9a-f]{64}$') { throw '登记码应为 64 位小写十六进制字符。' }

Write-Host '正在安装服务…'
try { & (Join-Path $PSScriptRoot 'install.ps1') -ServerUrl $serverUrl -PackageDirectory $package -HttpTrial 6>$null | Out-Null }
catch {
    & $uninstall -Quiet
    throw "安装服务失败，已撤销安装：$($_.Exception.Message)"
}

Write-Host '正在登记终端…'
& (Join-Path $installDir 'Compliance.Agent.exe') --config (Join-Path $dataDir 'agent.json') --enroll --code $code
if ($LASTEXITCODE -ne 0) {
    & $uninstall -Quiet
    throw '登记失败，已撤销安装。登记码可能已过期或已被使用，请生成新的登记码后重试。'
}

Start-Service ComplianceAgent
(Get-Service ComplianceAgent).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
# Start the tray for the signed-in user without elevation; later sign-ins start it from the Run key.
Start-Process -FilePath 'explorer.exe' -ArgumentList ('"' + (Join-Path $installDir 'Compliance.Tray.exe') + '"')

Write-Host ''
Write-Host '安装完成。客户端已作为 Windows 服务在后台运行，开机自动启动。' -ForegroundColor Green
Write-Host '- 约 1 分钟内管理端显示该终端在线，并完成首次完整检查。'
Write-Host '- 之后每分钟上报心跳，每 5 分钟检查进程和代理，每小时完整检查一次。'
Write-Host '- 管理端点“请求重新检查”后，客户端会在下一次心跳时执行。'
Write-Host '- 卸载：双击“卸载常驻客户端.bat”。'
