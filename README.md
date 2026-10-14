# 客户终端合规管控 0.1.0

内网管理平台 + Windows 服务 + 普通用户托盘。客户禁止代理及国外 AI，安装也判违规。检查、在线状态、防护能力与告警确认分别显示；缺失和过期证据不能判通过。

这是首个试运行版本，默认审计模式。Windows 二进制可以用于试点安装，但尚无 Windows 实机、代码签名/MSI及客户网络执行层验收。本版不自动卸载、不自动修改客户应用/浏览器阻断策略；强制发布会拒绝未验证执行层。精确应用哈希和 Edge 规则提供审查工件；通用 API 阻断尚未实现。

## 目录

- `src/Compliance.Core`：协议、签名、判定和九部分固定报告。
- `src/Compliance.Server`：ASP.NET Core、PostgreSQL生产配置、仅本机 SQLite 演示、设备登记、告警、审计与有限任务。
- `src/Compliance.Agent`：Windows 服务、显式用户 SID 采集、SQLite 离线队列、签名策略和 DPAPI 身份。
- `src/Compliance.Tray`：普通用户托盘，读取/确认本用户通知；不提供改策略接口。
- `ui`：React 中文管理页面，静态打包，不访问 CDN。
- `deploy`：安装和部署脚本。`integration/e2e.py`：真实平台 + 实际客户端模拟模式的联调。
- `docs/design-v1.md`：完整设计；`docs/server-api.md`：协议；`docs/capabilities.md`：当前边界。

## 编译与测试

需要 .NET SDK 10.0.401、Node 22或较新受支持版本。目标运行时10.0.12；依赖由 NuGet lock / npm lock 固定。开发时下载依赖；已发布自包含离线包不需要 .NET/Node 或联网安装。

```sh
cd ui
npm ci
npm test
npm run build
cd ..
dotnet run --project tests/Compliance.Core.Tests
dotnet test tests/Compliance.Server.Tests
dotnet run --project tests/Compliance.Agent.Tests
dotnet build src/Compliance.Server -c Release
dotnet build src/Compliance.Agent -c Release
dotnet build src/Compliance.Tray -c Release -p:RuntimeIdentifier=win-x64
python3 integration/e2e.py --dotnet dotnet
```

Windows 构建可在非 Windows 上跨编译；这不能证明原生运行正确。WPF 发布用 win-x64。源码不含服务器密码、设备私钥或登记码。

### 代码格式

C# 和项目文件统一用 CSharpier 排版（版本固定在 `dotnet-tools.json`，行宽见 `.editorconfig`）。提交前运行：

```sh
dotnet tool restore
dotnet csharpier format src tests
```

前端用 Prettier（版本固定在 `ui/package.json`）：在 `ui` 目录运行 `npm run format`，只检查用 `npm run format:check`。

`dotnet csharpier check src tests` 只检查不修改。批量格式化的提交记录在 `.git-blame-ignore-revs`，本地执行一次 `git config blame.ignoreRevsFile .git-blame-ignore-revs`，`git blame` 就会跳过它。

## 先在本机看平台

Windows 自包含包解压后双击根目录的 `启动演示.bat`，或运行 `deploy/server/Start-Demo.ps1`；启动时输入服务器本机的内网 IPv4 地址（直接回车则仅本机），端口可用 `-Port` 指定，启动成功会打开浏览器。脚本首次生成独立随机管理/审核密码并保护本地状态目录。页面使用 SQLite 演示。内网 HTTP 试用传输不加密，只能在可信隔离网络使用。

若要在 Windows 机器试一次真实采集，保持试用服务运行，在管理页面生成新的登记码，双击包根目录的 `本机采集试用.bat`，在管理员窗口输入管理端显示的完整 HTTP 地址。它使用独立受保护目录和 `--local-demo --once` 上报一次；再次运行可复用已登记身份。同机或另一台内网 Windows 均可试用，地址须为回环或私有 IPv4。此入口不安装服务。当前 `install.ps1` 只用于客户内网 HTTPS 常驻服务部署。

生产内网部署用 PostgreSQL、客户信任的 HTTPS 证书、独立维护账户和持久签名密钥。Windows 客户端要求 HTTPS；HTTP 仅限显式本机模拟模式。不能用跳过证书验证解决连接问题。

生产启动参数示例（配置不含真实密码）：

```sh
./Compliance.Server --urls https://0.0.0.0:5443 --contentRoot /opt/compliance
```

按 `deploy/server/README.md` 配置数据库、TLS、账号、存储权限、备份和恢复。管理页面生成一次性登记码，管理员按 `deploy/windows/README.md` 安装服务和托盘。初始策略为版本1审计模式；安装服务不会自动封禁业务程序。

## 验收次序

1. 先用演示包检查平台与报告流程；模拟数据始终标记模拟，不能证明 Windows 通过。
2. 选择5台 Windows 试点：多用户/未登录用户/商店包/npm CLI/IDE插件/代理/离线缓存/本机托盘逐项验收。
3. 采集业务应用基线并审核精确规则，接入可验证的应用/浏览器执行层；保留业务例外和回滚路径。
4. 适配现有客户出口/本机网络过滤系统，验收 API、离开内网及备用出口；此前不能宣称全面禁止访问。
5. 取得代码签名证书与 MSI 安装/升级验收，完成容量、性能、备份恢复后再生产推广。

告警确认只是操作记录。设备恢复需新采集证据；失联只是健康事件，不能据此认定员工违规。离线仍保留已有系统执行策略，但无法立即向失联管理端送达新消息。
