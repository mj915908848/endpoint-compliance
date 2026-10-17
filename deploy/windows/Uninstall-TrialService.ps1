#requires -Version 5.1
# 卸载脚本安装的常驻客户端（Windows 冒烟测试用），并删除登记身份、策略缓存和未上报记录。
[CmdletBinding()]
param([switch]$Quiet)
$ErrorActionPreference = 'Stop'
$scriptPath = $MyInvocation.MyCommand.Path
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -ArgumentList ('-NoExit -NoProfile -ExecutionPolicy Bypass -File "' + $scriptPath + '"') | Out-Null
    Write-Host '已打开管理员窗口，请在新窗口中继续。'
    exit 0
}
if (-not $Quiet) {
    $answer = Read-Host '将卸载常驻客户端并删除其登记身份和本地数据，是否继续 (Y/N)'
    if ($answer -notmatch '^[Yy]') { Write-Host '已取消。'; exit 0 }
}
Get-Process 'Compliance.Tray' -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500
& (Join-Path $PSScriptRoot 'uninstall.ps1') -RemoveData 3>$null
if (-not $Quiet) { Write-Host '已卸载。' -ForegroundColor Green }
