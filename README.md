# 终端合规管控

[![CI](https://github.com/mj915908848/endpoint-compliance/actions/workflows/ci.yml/badge.svg)](https://github.com/mj915908848/endpoint-compliance/actions/workflows/ci.yml)

面向企业内网的 Windows 终端合规检查系统。它持续检查员工电脑上有没有安装或运行被禁止的代理工具和 AI 应用（如 Clash、v2rayN、ChatGPT、Cursor、Copilot），汇总到一个中文管理页面，给出逐台终端的检查报告和告警。

默认**审计模式**：只检查、不拦截；对指定终端可启用**强制模式**，结束禁用程序并拦截浏览器网址。版本见 [Releases](https://github.com/mj915908848/endpoint-compliance/releases)。

## 能做什么

- **常驻检查**：Windows 客户端以系统服务运行，定期检查并上报；断网时先存在本地，恢复后补报。
- **多处取证**：已安装软件、运行中的进程、系统服务、常见安装目录、全盘同名程序文件（含绿色版）、Microsoft Store 应用、VS Code / JetBrains 扩展、命令行工具（npm、pip/pipx/uv 包）、系统代理和代理环境变量、监听端口、虚拟网卡。每个用户账户单独检查。
- **结论保守**：客户端只执行策略里勾选的检查项；只有这些检查项都成功读取、且没有发现违规，才判"通过"。读取失败、数据过期或模拟数据一律显示"无法判断"，不会被当成通过。
- **线索归属**：本机代理端口和虚拟网卡会写明是哪个程序在用，例如"端口 7897 由 verge-mihomo.exe（Clash / Mihomo）监听"。公司自己的 VPN 网卡（如 aTrust）可加入白名单。
- **敏感文件**：按关键词规则（如项目代号）查找文件名，通过 NTFS 文件表和变更日志扫描整盘，新出现的文件约 1 分钟内上报。可设为只提醒或判为违规。
- **可视化策略**：在页面上编辑禁用产品、禁止访问的域名、网卡白名单、敏感文件规则、检查频率和检查要求，发布前列出变更，发布后终端自动接收。可以建多份策略分别指定终端。策略经过签名，终端只接受管理端签发的版本。
- **强制模式**：「发现即结束进程」每 2 秒检查一次，结束确认的禁用程序（含 Microsoft Store 应用）；「浏览器网址拦截」写入 Edge、Chrome 的网址黑名单。
- **批量登记**：一个登记码可登记多台电脑；下载登记配置放进安装包后，员工双击安装即可，无需输入。
- **报告与告警**：每台终端一份九节检查报告，可下载 Markdown / JSON；违规、失联、检查失败分别告警，确认告警不等于问题已解决。
- **安全边界**：终端请求逐条签名并防重放，管理页面有角色权限和 CSRF 防护，所有操作写入审计记录，报告里不记录代理地址、令牌等敏感值。

## 系统组成

| 组件 | 位置 | 说明 |
| --- | --- | --- |
| 管理端 | `src/Compliance.Server` | ASP.NET Core。生产用 PostgreSQL，演示用 SQLite。提供管理 API、终端 API 和管理页面 |
| 判定核心 | `src/Compliance.Core` | 协议、策略签名、判定规则和报告生成，管理端与客户端共用 |
| Windows 客户端 | `src/Compliance.Agent` | 系统服务（`ComplianceAgent`），各检查项独立超时，离线队列存于本地 SQLite |
| 托盘程序 | `src/Compliance.Tray` | 普通用户查看并确认发给自己的通知，不能修改策略 |
| 管理页面 | `ui` | React + Ant Design 中文界面，随管理端一起发布，不访问外部 CDN |
| 部署脚本 | `deploy` | 管理端演示启动、客户端安装/更新/卸载 |
| 测试 | `tests`、`integration` | 单元测试、端到端测试、Windows 实机采集测试 |

## 快速体验

### 在 macOS / Linux 上看管理页面

需要 .NET SDK 10.0.401+、Node.js 22+、Python 3。

```sh
python3 scripts/demo.py
```

打开 http://127.0.0.1:5080 ，账号 `demo-admin`，密码在 `data/demo/login.txt`。演示会登记两台模拟终端：DEMO-PC-01 有确认违规（Cursor），DEMO-PC-02 没有发现，但因为是模拟数据，结论显示"无法判断"。按 Ctrl+C 停止；数据保留在 `data/demo/`，加 `--reset` 从头开始。

### 在 Windows 上试用

用 Windows 试用包（自包含，不需要安装 .NET）：

1. 双击 `启动演示.bat` 启动管理端，输入本机内网 IPv4 地址（直接回车则仅本机访问）。首次启动会生成管理员密码。
2. 在管理页面"终端登记"生成登记码。
3. 在要检查的电脑上以管理员身份运行 `安装常驻客户端（试用）.bat`，填入管理端地址和登记码。已安装过的电脑选"1 仅更新程序"即可升级。
4. 回到管理页面查看终端和报告。卸载用 `卸载常驻客户端.bat`。

试用包用 `python3 scripts/package.py --trial` 生成。详细步骤见包内的 `使用说明.md`（源文件 `deploy/server/试用说明.md`）。试用模式走内网 HTTP，传输不加密，只能在可信网络使用。

## 管理页面

- **总览 / 终端设备**：每台终端的在线状态、检查结论和违规数。终端详情里有检查报告、全部证据、检查覆盖和防护状态，可以请求重新检查、下载报告或删除终端。删除后该电脑的客户端无法再上报，需要重新登记。
- **告警中心**：违规、失联、检查失败。确认告警只是记录"已处理"，问题是否消失以新的检查结果为准。
- **终端登记**：生成登记码（可登记台数、有效期），下载登记配置，查看每个码已登记几台，撤销。
- **策略管理**：有发布权限的账号直接编辑并发布。默认策略适用于所有未指定的终端，新建策略可指定部分终端。检查频率（默认每 5 分钟快速检查、每小时完整检查）在策略中设置，检查结果有效期自动取检查间隔的 2 倍。每份策略的版本号各自从 v1 起递增，有效期（一年）由管理端设置；「历史版本」可查看并恢复之前发布过的版本。管理端升级后若内置了新规则，页面会提示"载入内置最新规则"。
- **系统**：运行模式、版本、数据库和策略签名密钥。
- **审计记录**：登录、登记、发布、删除等操作。

账号角色：`Reader` 查看，`Operator` 登记终端、请求检查、确认告警、删除终端，`Publisher` 编辑发布策略。

## 判定规则

| 结论 | 条件 |
| --- | --- |
| 不通过 | 发现确认的违规证据：安装了、运行着禁用产品，或启用了代理 |
| 通过 | 策略要求的检查项全部在有效期内成功读取，且没有确认违规 |
| 无法判断 | 有检查项读取失败或过期、终端失联、策略过期，或数据来自模拟 |

"待核查线索"（如常见代理端口被占用、出现隧道网卡）只提示管理员核实，不单独判定违规。

## 开发

### 构建与测试

```sh
# 前端
cd ui && npm ci && npm test && npm run build && cd ..

# 后端与客户端
dotnet run --project tests/Compliance.Core.Tests
dotnet test tests/Compliance.Server.Tests
dotnet run --project tests/Compliance.Agent.Tests
dotnet build src/Compliance.Server -c Release
dotnet build src/Compliance.Agent -c Release

# 端到端（真实管理端 + 模拟数据的客户端）
python3 integration/e2e.py
```

服务端测试默认用 SQLite；设置 `COMPLIANCE_TEST_POSTGRES` 为连接字符串即可在 PostgreSQL 上再跑一遍。客户端可以在 macOS / Linux 上交叉编译和跑模拟测试，但真实采集只能在 Windows 上验证。Windows 上可运行 `python integration/windows_smoke.py` 做一次真实采集测试（会临时修改当前用户的代理设置，结束后恢复）。

### 代码格式

- C#：CSharpier（版本固定在 `dotnet-tools.json`）。`dotnet tool restore` 后运行 `dotnet csharpier format src tests`。
- 前端：Prettier。在 `ui` 目录运行 `npm run format`。
- 批量格式化的提交记录在 `.git-blame-ignore-revs`，执行一次 `git config blame.ignoreRevsFile .git-blame-ignore-revs` 后 `git blame` 会跳过它们。

### 持续集成

每次推送和 Pull Request 都会运行 [GitHub Actions](.github/workflows/ci.yml)，按改动的文件只跑受影响的任务（只改前端时不跑 Windows、Docker 和服务端测试；只改 `.md` 和 `docs/` 时不跑），改动 CI 配置或手动触发时全部运行。任一步失败即标红：

| 任务 | 运行环境 | 内容 |
| --- | --- | --- |
| 格式检查 | Ubuntu | CSharpier、Prettier |
| 前端构建与测试 | Ubuntu | 类型检查、打包、Vitest |
| 服务端与 Core 测试 | Ubuntu + PostgreSQL 17 | Core 测试；服务端测试在 SQLite 和 PostgreSQL 上各跑一遍 |
| 端到端测试 | Ubuntu | 启动真实管理端，客户端用模拟数据完成登记、上报、告警、离线补报 |
| Docker 部署 | Ubuntu | 用自签证书构建并启动 Docker 部署（管理端 + PostgreSQL），检查登录、重启后签名密钥不变和备份脚本 |
| Windows 实机采集 | windows-latest | 客户端测试（含真实端口表）；构建托盘；在本机启动管理端，客户端真实采集一次，核对注册表、PackageManager、端口表、账户名解析和代理归属；再用登记配置双击安装常驻服务，确认登记和上报 |

端到端和 Windows 采集的证据（报告、快照、日志）作为构建产物上传，可在 Actions 页面下载。

### 版本发布

需要发版时手动运行 [Release 流程](.github/workflows/release.yml)（`gh workflow run release.yml`），它把 main 上最新且 CI 已通过的提交发布为一个版本：版本号为 `VERSION` 文件（如 `0.2`）加发布序号，依次为 0.2.0、0.2.1……附带：

- `compliance-client-<版本>-windows.zip`：Windows 客户端安装包；
- `compliance-server-<版本>.tar.gz`：管理端 Docker 镜像（`docker load -i` 加载）。

发布说明自动列出上个版本以来的提交。要升大版本时修改 `VERSION`，序号从 0 重新开始。本地打包用 `python3 scripts/package.py`，生成的版本号带 `-dev` 后缀。

## 生产部署

- 管理端：推荐用 Docker 部署（含 PostgreSQL），可经网关反向代理，见 `deploy/docker/README.md`；不用 Docker 时需要 PostgreSQL、客户信任的 HTTPS 证书、持久的策略签名密钥和独立的管理账号，见 `deploy/server/README.md`。
- 客户端：双击发布的 MSI，装完在弹出的窗口填写管理端地址和登记码（MSI 旁放“终端登记”页下载的登记配置时自动填好），或用 `msiexec /i … SERVERURL=… CODE=… /qn` 批量静默安装；升级直接装新版本 MSI。也可以继续用 zip 包里的 `安装客户端（正式环境）.bat`。正式部署只连接 HTTPS 管理端，不支持跳过证书校验。见 `deploy/windows/客户端安装说明.md` 和 `deploy/windows/README.md`。
- 初始策略为审计模式。强制模式只能发布给新建策略中指定的终端，且这些终端必须先报告所需防护措施「可启用」。

## 当前边界

- 强制模式提供两项防护措施：「发现即结束进程」（每 2 秒检查一次，按程序名和产品名（Store 应用按包名）确认后结束，员工托盘提示，管理端产生拦截告警）和「浏览器网址拦截」（写入 Edge、Chrome 的 URLBlocklist 组策略并读回核对）。Firefox、便携浏览器和其他程序的网络访问不在覆盖范围内，建议在出口网关按策略域名拦截。
- 尚无代码签名和 MSI 安装包，个别杀毒软件可能误报；管理端看不到各终端的客户端版本；登录只支持本地账号，未接入 LDAP / AD。
- 未知软件、改名的便携程序、任意目录中的文件不保证能发现。

完整的能力与验收矩阵见 `docs/capabilities.md`。

## 文档

- `docs/design-v1.md`：总体设计
- `docs/server-api.md`：管理端与终端 API
- `docs/capabilities.md`：已实现能力与待验收项
- `deploy/docker/README.md`：管理端 Docker 部署、反向代理、备份与升级
- `deploy/windows/客户端安装说明.md`：客户端安装、升级、卸载（随客户端包发布）
- `deploy/server/README.md`、`deploy/windows/README.md`：不用 Docker 的部署与客户端细节
