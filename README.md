# 终端合规管控

[![CI](https://github.com/mj915908848/endpoint-compliance/actions/workflows/ci.yml/badge.svg)](https://github.com/mj915908848/endpoint-compliance/actions/workflows/ci.yml)

检查企业内网 Windows 电脑上有没有安装或运行被禁止的代理工具和 AI 应用（如 Clash、v2rayN、ChatGPT、Cursor、Copilot），结果汇总到一个中文管理页面。

默认**审计模式**：只检查、不拦截。对指定终端可启用**强制模式**：结束禁用程序，并拦截 Edge、Chrome 中的禁止网址。

## 能做什么

- **检查**：已安装软件、进程、服务、安装目录、全盘同名文件（含绿色版）、Store 应用、编辑器扩展、命令行工具、系统代理、监听端口、虚拟网卡；按关键词查找敏感文件；可选安全基线检查（杀毒软件、防火墙、系统更新、BitLocker、自动锁屏、来宾账户、本地管理员、远程桌面、SMBv1）。
- **结论保守**：只有策略要求的检查项都成功读取且没有违规才判"通过"；读取失败或数据过期一律"无法判断"。
- **策略**：在页面上编辑禁用产品、禁止域名、检查频率等，发布后终端自动接收；策略经过签名。
- **防篡改**：客户端服务被停止、被改为手动或禁用、进程被强制结束、托盘自启动被删除、客户端被卸载时产生告警，被改动的启动设置自动恢复；策略可设置卸载密码。正常关机的终端显示“已关机”，不报失联。
- **终端分组**：每台终端可归入一个分组（如部门），登记码可带分组让新终端自动归组；策略可按分组适用，终端列表、告警可按分组筛选，导出含分组。
- **资产清单**：客户端在完整检查后上报硬件（厂商型号、序列号、处理器、内存、硬盘）、系统版本和已安装软件；管理端按终端查看，也可跨终端统计每个软件装在几台、哪些版本，并记录软件安装、卸载、升级和系统、硬件变化；硬件和软件清单可导出 Excel。
- **移动存储管控**：策略把 U 盘和移动硬盘设为允许、只读或禁止，可按序列号或型号放行公司发放的设备；强制模式下客户端插入后约 2 秒内停用设备或设为只读，并提示电脑前的用户。插入、拔出和拦截都会上报，被拦截时产生“移动存储拦截”告警。
- **多管理员与两步验证**：每位管理人员一个账号，按只读、操作员、发布人、账号管理员分配权限，离职可停用；登录可要求手机验证器 App 上的 6 位验证码，并可要求所有账号启用。所有操作留审计记录。
- **日志外发**：告警（产生和恢复）和审计记录实时以 Syslog 发到单位的日志服务器或 SIEM / 态势感知平台，支持 UDP、TCP、TLS 加密，JSON 或 CEF 格式；发送失败自动重试。
- **报告与告警**：每台终端一份检查报告；违规、失联、检查失败分别告警。

## 部署

1. **管理端**：在 Linux 服务器上用 Docker 部署，照 [deploy/docker/README.md](deploy/docker/README.md) 下载部署文件，在 `.env` 里填密码、选镜像来源（镜像仓库、Releases 页打包好的镜像或从源码构建），放证书，`docker compose up -d`。
2. **客户端**：从 [Releases](https://github.com/mj915908848/endpoint-compliance/releases) 下载 MSI，在员工电脑上双击安装，填写管理端地址和登记码。见 [客户端安装说明](deploy/windows/客户端安装说明.md)。

升级：服务器上 `./backup.sh && docker compose pull && docker compose up -d`；客户端装新版 MSI，或在管理页面「系统设置」上传 MSI 远程下发。

## 本地预览管理页面

需要 .NET SDK 10.0.401+、Node.js 22+、Python 3：

```sh
python3 scripts/demo.py
```

打开 http://127.0.0.1:5080 ，账号 `demo-admin`，密码在 `data/demo/login.txt`。

## 开发

```sh
cd ui && npm ci && npm test && npm run build && cd ..
dotnet run --project tests/Compliance.Core.Tests
dotnet test tests/Compliance.Server.Tests
dotnet run --project tests/Compliance.Agent.Tests
python3 integration/e2e.py
```

格式化：`dotnet csharpier format src tests`，`cd ui && npm run format`。

发版：手动运行 [Release 流程](.github/workflows/release.yml)，产出客户端 MSI、管理端镜像 `ghcr.io/mj915908848/compliance-server`，以及同一镜像的离线包 `compliance-server-<版本>.tar.gz`。

## 目前不支持

- 代码签名、客户端自动升级、LDAP / AD 登录。
- Firefox 和便携浏览器的网址拦截（建议在出口网关拦截）。
- 改名的便携程序、未知软件不保证能发现。

## 更多文档

- [docs/design-v1.md](docs/design-v1.md)：总体设计
- [docs/capabilities.md](docs/capabilities.md)：能力与验收矩阵
- [docs/server-api.md](docs/server-api.md)：API
- [docs/compatibility.md](docs/compatibility.md)：版本兼容
- [deploy/docker/ADVANCED.md](deploy/docker/ADVANCED.md)：反向代理、密码重置、恢复等
- [deploy/server/README.md](deploy/server/README.md)：不用 Docker 部署
