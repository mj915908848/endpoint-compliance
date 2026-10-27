# 内网服务端部署

推荐 Linux x64/ARM64 或 Windows Server，PostgreSQL 18.6 已用隔离本机实例测试；部署到客户环境需复核该环境的补丁和连接。发布包自包含 .NET10.0.12；PostgreSQL由客户管理员预安装，不包含在线拉取安装器。

配置键：

| 键 | 要求 |
| --- | --- |
| Compliance:DemoMode | 生产 false；HTTP 试用 true |
| Compliance:DemoHttpLan | 默认 false；仅隔离内网 HTTP 试用时显式设置 true，监听本机私有 IPv4 地址 |
| Compliance:Storage | 生产 Postgres；Sqlite仅允许演示 |
| Compliance:Database | PostgreSQL完整连接串；推荐SSL Mode=VerifyFull与受信CA；测试的loopback无TLS不能照搬生产 |
| Compliance:SigningKeyPath | 受保护持久密钥路径；不可每次启动随机更换；与数据库一起备份 |
| Compliance:BootstrapUsers | JSON数组，username/password/roles；密码至少16字符，首次插入，数据库已有账号不会被启动配置重置；角色可选 Reader、Operator、Publisher、Admin（账号管理员，同时有 Operator 和 Publisher 的账号自动获得）。其他管理人员的账号建议在页面「系统设置 → 账号」中创建 |
| Compliance:TrustedProxies | 仅实际可信反代IP，默认空；不接受任意Forwarded头 |
| Kestrel:Certificates:Default:Path | 客户信任证书的PFX文件路径 |
| Kestrel:Certificates:Default:Password | 通过受保护配置/环境注入；勿写进脚本仓库 |

角色 Reader/Operator/Publisher：Publisher 在策略页面编辑后直接发布（Reviewer 角色仍可配置，但已不再使用）。默认没有公共账号密码。本版在初始化时创建指定账号，密码轮换/禁用账户管理接口尚未提供，生产前应增加企业身份集成或经过维护流程的数据迁移，不能用默认密码长期运行。

服务进程使用独立无特权账号。安装目录只读，密钥、状态和日志目录只允许维护员和服务账号。反代时HTTPS终止只能来自TrustedProxies；直接Kestrel HTTPS也是支持的。客户端不得跳过证书验证。

Linux可根据 `compliance.service.example` 安装systemd单元；EnvironmentFile建议root:compliance 0640，不提交真实环境配置。Windows自包含服务端暂以进程运行，使用客户现有受管服务容器；不把客户端SCM安装脚本当服务器安装脚本。

备份PostgreSQL + 原签名私钥 + 配置/证书 + 发布包；在隔离环境恢复并验证设备仍识别原签名密钥。旧数据库恢复后的策略版本不得降低客户机持久最低版本。删除密钥会导致已登记设备拒绝新策略。策略、事件、告警、账户都在数据库，不能只备份页面资源。

该版无通用网络过滤适配器、无SMTP/企业聊天通知适配器；通知通道为平台告警中心与本机托盘。若用户不在线或设备断网，通知留存与远程已送达是不同状态。90/180/365天自动留存清理及500台持续压测尚未完成，不应作生产容量保证。
