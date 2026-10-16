# Windows agent deployment (pilot)

To try native collection, keep `启动演示.bat` running, create a fresh enrollment code in the management page, and double-click `本机采集试用.bat` in the ZIP root on the Windows device. Accept the administrator prompt, enter the HTTP URL shown by the management server, then paste the code. The URL can use a loopback or private IPv4 address and a chosen port. This runs one real scan with `--local-demo --once`; it stores a separate trial identity per server URL under ProgramData and does not install a service. Refresh the device page and inspect the report. Re-run after changes on the same URL without a new code; changing the server URL needs a new code. Keep the code private and generate another if it expires. LAN HTTP trial traffic is unencrypted; use an isolated trusted network. For a resident trial against the same HTTP server, double-click `安装常驻客户端（试用）.bat` instead: it installs the LocalSystem service and tray through `install.ps1 -HttpTrial`, enrolls with a new code and starts the service, which then heartbeats about every minute, re-checks processes and proxies every 5 minutes and runs a full scan hourly. `agent.json` records `httpTrial: true`, so the service only accepts a loopback or private IPv4 HTTP server that reports trial mode. `卸载常驻客户端.bat` removes the service, tray and its local data. Production deployments omit `-HttpTrial` and require HTTPS.

Build `Compliance.Agent` and `Compliance.Tray` as separate self-contained `win-x64` directories with .NET 10, then place both published file sets in one protected staging directory. Run `install.ps1 -ServerUrl https://internal.example -PackageDirectory C:\staging\compliance` as administrator. The installer creates a LocalSystem service and an all-users Run entry for the ordinary-user tray. It restricts ProgramData to SYSTEM and Administrators. Run `Compliance.Agent.exe --config C:\ProgramData\ComplianceAgent\agent.json --enroll --code <one-time-code>` from an elevated prompt, then `Start-Service ComplianceAgent`. The code is not stored in agent configuration.

`agent.json` fields: `serverUrl` (approved internal HTTPS origin), `dataDirectory` (protected ProgramData path), `deviceId`, `policyPublicKeyPem`, `policyKeyId`, and `httpTrial` (trial installs only; defaults to false). The latter three are filled after enrollment. Service failure returns a nonzero process exit so SCM recovery restarts it. Configure the target HTTPS trust chain on Windows; the agent never disables certificate validation.

This is a pilot ZIP deployment, not a signed MSI. In Enforce mode the service (running as SYSTEM) ends confirmed forbidden processes every 2 seconds and writes the policy's block domains to the Edge and Chrome `URLBlocklist` policies under HKLM, keeping entries it did not write and removing its own when enforcement stops. A pilot must still verify interaction with existing enterprise policy, browser refresh and business allow rules. Firefox, portable browsers and other network access are not covered; block those domains at the customer gateway. Audit mode is the default. `uninstall.ps1` retains device identity, policy cache, queue and notifications unless `-RemoveData` is explicitly supplied; review any separately applied OS controls first.

For a development simulation on macOS, run the agent with `--fixture <snapshot.json> --server http://127.0.0.1:<port> --data-dir <throwaway-dir> --enroll --code <code> --once`. The fixture is forcibly marked `simulated=true`, and the temporary private key is stored unencrypted only in that explicitly selected simulation directory. The simulation cannot establish native Windows coverage or production PASS.

## 日志

常驻服务的运行日志写在 `%ProgramData%\ComplianceAgent\logs\agent.log`，每行带时间；超过 1 MB 时旧内容移到 `agent.log.1`。托盘右键菜单的“运行日志”可直接查看，也可以用 PowerShell：

```powershell
Get-Content "$env:ProgramData\ComplianceAgent\logs\agent.log" -Encoding UTF8 -Tail 50
```

`logs` 文件夹本机所有用户都可以读、不能改；服务每次启动都会重设它的权限。日志里有软件列表和敏感文件扫描命中的路径，多人共用的电脑上其他账户也能看到。登记密钥和配置在上一级 `ComplianceAgent` 文件夹，只有管理员和 SYSTEM 可以访问。早期版本写在 `ComplianceAgent` 文件夹里的日志，升级后会移到 `logs`。
