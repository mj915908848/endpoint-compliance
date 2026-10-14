import type { ModuleResult } from "../types";

export const reportNames = [
  "基本信息",
  "检查结论",
  "不通过项",
  "软件安装与进程",
  "代理配置",
  "端口与执行层线索",
  "检查覆盖",
  "处理建议",
  "范围与限制",
];

export function moduleLabel(module: string) {
  return ({ installed: "软件安装", "installed-paths": "常见安装目录", services: "服务登记", processes: "运行进程", proxy: "系统代理", "proxy-env": "代理环境变量", "proxy-advanced": "高级代理", extensions: "IDE 扩展", appx: "商店应用", ports: "端口与接口", users: "用户范围", cli: "命令行工具" } as Record<string, string>)[module] ?? module;
}

export function statusLabel(status: string) {
  return ({ Complete: "已完成", Error: "读取失败", Unknown: "未覆盖" } as Record<string, string>)[status] ?? status;
}

export function evidenceLabel(kind: string) {
  return ({ Installation: "已安装", Process: "运行中", Extension: "扩展已安装", Proxy: "代理配置", Clue: "待核线索", BlockedAttempt: "拦截记录" } as Record<string, string>)[kind] ?? kind;
}

export function moduleErrorLabel(result: ModuleResult) {
  const error = result.error ?? "";
  if (/User hive not loaded|offline hive was not mounted/i.test(error)) return "该用户的注册表未加载；需要登录后重新检查，或由管理员补做离线用户检查。";
  if (/JsonReaderException|JsonException/i.test(error)) return `${moduleLabel(result.module)}的配置格式无法解析；本项覆盖不完整。`;
  if (/UnauthorizedAccessException/i.test(error)) return "没有读取权限；本项覆盖不完整。";
  if (/Profile path missing|Profile path unavailable/i.test(error)) return "用户目录不可用；本项覆盖不完整。";
  return error;
}
