# 首版实施计划

Spec: docs/design-v1.md。目标：可运行、可构建的内网端到端首版，含 Windows 服务与普通用户托盘、采集、固定报告、离线补报、平台告警、签名策略和可控执行适配。

全局约束：未覆盖、过期、模拟、未验证控制不能当通过；不采集内容和凭据；仅审计默认；不自动卸载；无任意远程命令；不修改当前Mac系统代理/防火墙。所有原生Windows运行、签名MSI和网络网关覆盖在真实验收前明确未验证。

1. 核心协议/判定/签名/报告：父代理所有权 src/Compliance.Core、tests/Compliance.Core.Tests。测试优先：违规优先、缺模块/用户/旧采集UNKNOWN、端口仅线索、策略篡改/降级、主机边界、固定报告脱敏。
2. 服务端：独立实施者所有权 src/Compliance.Server、tests/Compliance.Server.Tests。PostgreSQL生产持久化、SQLite显式演示、账号和权限、一次性登记、设备签名认证、事务去重/乱序不回退、当前结论/离线、告警、报告、签名审计发布和限定任务；HTTP仅本机演示。
3. Windows端：独立实施者所有权 src/Compliance.Agent、src/Compliance.Tray、tests/Compliance.Agent.Tests、deploy/windows。显式SID/Profile枚举；模块失败覆盖；本地SQLite离线队列；DPAPI设备私钥；签名策略缓存；普通用户通知IPC；只批准的固定动作；Edge/AppLocker审计和精确哈希执行适配，默认不生效；降级/重启/验证状态。
4. 管理页面：独立实施者所有权 ui。React/TS中文界面，登录、设备、告警、检查报告、规则、登记码、审计与有限任务。无CDN/模拟数据冒充真实，服务端统一事实判定。
5. 联调/打包：父代理所有权 integration、deploy/server、README、build scripts。实际启动平台，签名模拟终端违规-恢复-离线-补报流程；真实SQLite及可获得的PostgreSQL测试；跨编译Windows二进制；离线包、配置向导、回滚和已知限制。

接口表：1产出Core模型/签名与判定，2/3共同使用；2 REST路由向4提供；3对2仅外连。父代理修改共享接口须通知各实施者。每模块先运行失败测试，再实现并跑全模块测试。完成后独立代码审查，修复重要问题并整体重测。

Ruling: 当前不是已有项目仓库，在work/endpoint-compliance新建独立仓库feature/compliance-v1，不再创建嵌套worktree，避免改动旧skill与报告。
Ruling: 现有环境无Windows/客户网关/签名证书，交付测试ZIP与能力状态，不能宣称生产MSI签名、Windows实机阻断或通用API过滤已验收。
