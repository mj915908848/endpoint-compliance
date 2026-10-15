#requires -Version 5.1
# 把客户端安装为常驻 Windows 服务。默认连接内网 HTTP 试用管理端；-Production 连接正式的 HTTPS 管理端。
[CmdletBinding()]
param([string]$PackageRoot, [switch]$Production)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw '此脚本只能在 Windows 上运行。' }
$scriptPath = $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($PackageRoot)) { $PackageRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $scriptPath)) }
$PackageRoot = (Resolve-Path -LiteralPath $PackageRoot).ProviderPath
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -ArgumentList ('-NoExit -NoProfile -ExecutionPolicy Bypass -File "' + $scriptPath + '" -PackageRoot "' + $PackageRoot + '"' + $(if ($Production) { ' -Production' } else { '' })) | Out-Null
    Write-Host '已打开管理员窗口，请在新窗口中继续。'
    exit 0
}

$package = Join-Path $PackageRoot 'agent-windows-x64'
$installDir = Join-Path $env:ProgramFiles 'ComplianceAgent'
$dataDir = Join-Path $env:ProgramData 'ComplianceAgent'
$uninstall = Join-Path $PSScriptRoot 'Uninstall-TrialService.ps1'

$tray = Join-Path $installDir 'Compliance.Tray.exe'
if (Get-Service ComplianceAgent -ErrorAction SilentlyContinue) {
    Write-Host '本机已安装常驻客户端：'
    Write-Host '  1  仅更新程序，保留登记身份和本地数据（推荐）'
    Write-Host '  2  卸载后重新安装，需要新的登记码'
    $choice = Read-Host '请选择 (1/2，其他键取消)'
    if ($choice -eq '1') {
        Get-Process 'Compliance.Tray' -ErrorAction SilentlyContinue | Stop-Process -Force
        Stop-Service ComplianceAgent
        (Get-Service ComplianceAgent).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        Copy-Item (Join-Path $package '*') $installDir -Recurse -Force
        Start-Service ComplianceAgent
        Start-Process -FilePath 'explorer.exe' -ArgumentList ('"' + $tray + '"')
        Write-Host '更新完成，服务已重新启动。约 1 分钟后在管理端刷新即可看到新的检查结果。' -ForegroundColor Green
        exit 0
    }
    if ($choice -ne '2') { Write-Host '已取消。'; exit 0 }
    & $uninstall -Quiet
}

if ($Production) {
    $serverUrl = (Read-Host '管理端地址（如 https://compliance.example.com）').Trim().TrimEnd('/')
    if ($serverUrl -notmatch '^https://[^/]+$') { throw '正式环境的管理端地址必须以 https:// 开头，只写域名（和端口），不带路径。' }
}
else {
    $serverUrl = (Read-Host '管理端地址（直接回车使用 http://127.0.0.1:5080）').Trim().TrimEnd('/')
    if ([string]::IsNullOrWhiteSpace($serverUrl)) { $serverUrl = 'http://127.0.0.1:5080' }
}
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
try { $status = Invoke-RestMethod -Uri "$serverUrl/api/status" -TimeoutSec 10 }
catch { throw "无法连接管理端 $serverUrl：$($_.Exception.Message)`n请确认地址和端口正确、域名能解析到管理端、防火墙放行；HTTPS 证书须被本机信任（用证书覆盖的域名访问，不能用 IP）。" }
if ($Production) {
    if ($status.mode -ne 'Production') { throw '该管理端是试用模式，请使用“安装常驻客户端（试用）.bat”。' }
}
elseif ($status.mode -ne 'LoopbackDemo' -and $status.mode -ne 'LanHttpTrial') { throw '该管理端是正式环境，请使用“安装客户端（正式环境）.bat”。' }

$code = (Read-Host '请粘贴管理端“终端登记”页面生成的新登记码').Trim()
if ($code -cnotmatch '^[0-9a-f]{64}$') { throw '登记码应为 64 位小写十六进制字符。' }

Write-Host '正在安装服务…'
try { & (Join-Path $PSScriptRoot 'install.ps1') -ServerUrl $serverUrl -PackageDirectory $package -HttpTrial:(-not $Production) 6>$null | Out-Null }
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
Start-Process -FilePath 'explorer.exe' -ArgumentList ('"' + $tray + '"')

Write-Host ''
Write-Host '安装完成。客户端已作为 Windows 服务在后台运行，开机自动启动。' -ForegroundColor Green
Write-Host '- 约 1 分钟内管理端显示该终端在线，并完成首次完整检查。'
Write-Host '- 之后每分钟上报心跳，按策略中的检查频率检查（默认每 5 分钟快速检查、每小时完整检查）。'
Write-Host '- 管理端点“请求重新检查”后，客户端会在下一次心跳时执行。'
Write-Host '- 卸载：双击“卸载常驻客户端.bat”。'
