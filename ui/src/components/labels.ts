import type { ModuleResult, UserAccount, Verdict } from "../types";

const lookup = (table: Record<string, string>) => (key: string) => table[key] ?? key;

export const verdictLabels: Record<Verdict, string> = {
  PASS: "通过",
  FAIL: "不通过",
  UNKNOWN: "无法判断",
};

export const onlineLabel = lookup({
  Online: "在线",
  SuspectedOffline: "疑似失联",
  Offline: "失联",
  Shutdown: "已关机",
});

/** Security baseline checks; keep in sync with Baseline.Checks in src/Compliance.Core/Baseline.cs. */
export const baselineChecks: {
  id: string;
  name: string;
  requirement: string;
  defaultLimit?: number;
  maxLimit?: number;
  unit?: string;
}[] = [
  {
    id: "antivirus",
    name: "杀毒软件",
    requirement: "已安装杀毒软件，实时防护已开启，病毒库为最新",
  },
  { id: "firewall", name: "防火墙", requirement: "防火墙已开启" },
  {
    id: "updates",
    name: "系统更新",
    requirement: "最近 {0} 天内成功安装过系统更新",
    defaultLimit: 30,
    maxLimit: 365,
    unit: "天",
  },
  { id: "bitlocker", name: "BitLocker 加密", requirement: "系统盘已开启 BitLocker 加密保护" },
  {
    id: "screenlock",
    name: "自动锁屏",
    requirement: "无操作 {0} 分钟内锁屏，恢复时需要密码",
    defaultLimit: 15,
    maxLimit: 120,
    unit: "分钟",
  },
  { id: "guest", name: "来宾账户", requirement: "来宾（Guest）账户已停用" },
  { id: "admins", name: "本地管理员", requirement: "本地管理员组中只有内置管理员和允许的账户" },
  { id: "rdp", name: "远程桌面", requirement: "远程桌面已关闭" },
  { id: "smb1", name: "SMBv1 协议", requirement: "SMBv1 文件共享协议已关闭" },
];
export const baselineName = (id: string) => baselineChecks.find((c) => c.id === id)?.name ?? id;

const moduleNames = lookup({
  installed: "已安装软件",
  "installed-paths": "常见安装目录",
  services: "系统服务",
  processes: "运行中的进程",
  proxy: "系统代理",
  "proxy-env": "代理环境变量",
  "proxy-advanced": "代理高级设置",
  extensions: "编辑器扩展",
  appx: "应用商店应用",
  ports: "端口与网络接口",
  users: "用户账户",
  cli: "命令行工具",
  programs: "全盘程序文件",
  "sensitive-files": "敏感文件",
});
export const moduleLabel = (module: string) =>
  module.startsWith("baseline:")
    ? `安全基线：${baselineName(module.slice("baseline:".length))}`
    : moduleNames(module);

export const statusLabel = lookup({
  Complete: "已完成",
  Error: "读取失败",
  Unknown: "未覆盖",
  Truncated: "命中过多，仅列出部分",
});

export const evidenceLabel = lookup({
  Installation: "安装记录",
  Process: "运行进程",
  Extension: "编辑器扩展",
  Proxy: "代理设置",
  Clue: "待核查线索",
  BlockedAttempt: "拦截记录",
  SensitiveFile: "敏感文件",
  Baseline: "安全基线",
});

export const alertTypeLabel = lookup({
  Violation: "违规",
  BlockedAttempt: "已拦截",
  Health: "设备健康",
  Offline: "设备失联",
  Clue: "待核查线索",
  SensitiveFile: "敏感文件",
  Baseline: "安全基线",
  Tamper: "防篡改",
  UsbBlocked: "移动存储拦截",
});

export const auditActionLabel = lookup({
  Login: "登录",
  LoginFailed: "登录失败（密码错误）",
  LoginLocked: "登录失败次数过多，已暂停",
  Logout: "退出登录",
  LoginWrongCode: "登录失败（验证码错误）",
  CreateUser: "创建账号",
  SetUserRoles: "修改账号角色",
  ResetUserPassword: "重置账号密码",
  DisableUser: "停用账号",
  EnableUser: "启用账号",
  EnableTwoFactor: "启用两步验证",
  DisableTwoFactor: "关闭两步验证",
  ResetTwoFactor: "重置两步验证",
  SetRequireTwoFactor: "设置是否要求两步验证",
  SetLogForwarding: "设置日志外发",
  TestLogForwarding: "发送日志外发测试消息",
  CreateEnrollmentCode: "生成登记码",
  RevokeEnrollmentCode: "撤销登记码",
  EnrollDevice: "终端登记",
  RequestScan: "请求重新检查",
  DeleteDevice: "删除终端",
  SetDeviceNote: "修改终端备注",
  SetDeviceGroup: "设置终端分组",
  ScanReply: "终端回复检查请求",
  AcknowledgeAlert: "确认告警",
  CreatePolicyDraft: "创建策略草稿",
  ApprovePolicy: "审核通过策略",
  PublishPolicy: "发布策略",
  CreatePolicy: "新建策略",
  DeletePolicy: "删除策略",
  ReissuePolicy: "重新签发策略",
  RenameDefaultPolicy: "默认策略改名为 Default",
  SeedAuditPolicy: "初始化审计策略",
  Offline: "终端失联",
  OnlineRecovered: "终端恢复在线",
  SnapshotRecovered: "检查结果恢复",
  ChangePassword: "修改密码",
  SetNotifications: "修改告警推送设置",
  TestNotification: "发送测试推送",
  SetAuditRetention: "修改审计记录保留期限",
  PruneAudit: "清理过期审计记录",
  ExportDevices: "导出终端列表",
  ExportAssets: "导出硬件资产",
  ExportSoftware: "导出软件清单",
  ExportUsbEvents: "导出移动存储记录",
  ArchiveDevice: "归档终端",
  RestoreDevice: "取消归档终端",
  SetArchiveDays: "修改自动归档期限",
  RequestUpgrade: "请求升级客户端",
  RolloutUpgrade: "批量升级客户端",
  UpgradeReply: "终端回复升级请求",
  UpgradeSucceeded: "客户端升级成功",
  UpgradeFailed: "客户端升级失败",
});

export const categoryLabel = lookup({
  proxy: "代理工具",
  vpn: "VPN",
  ai: "AI 应用",
  ide_ai: "编程助手",
});

export const controlLabel = lookup({
  process: "发现即结束进程",
  browser: "浏览器网址拦截",
  usb: "移动存储管控",
  application: "应用程序拦截（旧）",
  edge: "Edge 浏览器策略（旧）",
  network: "网络访问拦截（旧）",
});

export const controlStateLabel = lookup({
  Verified: "已验证",
  Ready: "可启用",
  Applied: "已生效",
  AppliedUnverified: "已应用，未验证",
  PendingManualApplication: "待人工部署",
  Uncovered: "未覆盖",
  Error: "出错",
});

/** "整机", "D 盘" for a data drive, or "用户 kaiyu" when the snapshot names the account, else "用户 <SID>". */
export const scopeLabel = (scope: string | null | undefined, users?: UserAccount[]) =>
  !scope || scope === "machine"
    ? "整机"
    : /^drive:[A-Z]$/.test(scope)
      ? `${scope.slice(-1)} 盘`
      : `用户 ${users?.find((u) => u.sid === scope)?.name ?? scope}`;

/** Turns raw collector exceptions into an explanation an administrator can act on. */
export function moduleErrorLabel(result: ModuleResult) {
  const error = result.error ?? "";
  if (/User hive not loaded|offline hive was not mounted/i.test(error))
    return "该用户的注册表未加载。请在该用户登录后重新检查，或由管理员补做离线检查。";
  if (/JsonReaderException|JsonException/i.test(error))
    return `${moduleLabel(result.module)}的配置文件无法解析，本项检查不完整。`;
  if (/UnauthorizedAccessException/i.test(error)) return "没有读取权限，本项检查不完整。";
  if (/Profile path missing|Profile path unavailable/i.test(error))
    return "用户目录不可用，本项检查不完整。";
  return error;
}

export const inventoryChangeLabel = lookup({
  SoftwareInstalled: "安装软件",
  SoftwareRemoved: "卸载软件",
  SoftwareUpdated: "软件更新",
  HardwareChanged: "硬件变化",
  SystemUpdated: "系统更新",
});

export const usbStorageLabel = lookup({
  Allow: "允许使用",
  ReadOnly: "只读",
  Block: "禁止使用",
});

export const usbEventLabel = lookup({
  UsbConnected: "接入",
  UsbRemoved: "拔出",
  UsbBlocked: "已拦截",
});
