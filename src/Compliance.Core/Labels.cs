namespace Compliance.Core;

/// <summary>Chinese display names shared by the report engine and the Markdown report; keep in sync with ui/src/components/labels.ts.</summary>
public static class Labels
{
    public static string Module(string module) =>
        module switch
        {
            "installed" => "已安装软件",
            "installed-paths" => "常见安装目录",
            "services" => "系统服务",
            "processes" => "运行中的进程",
            "proxy" => "系统代理",
            "proxy-env" => "代理环境变量",
            "proxy-advanced" => "代理高级设置",
            "extensions" => "编辑器与浏览器扩展",
            "appx" => "应用商店应用",
            "ports" => "端口与网络接口",
            "users" => "用户账户",
            "cli" => "命令行工具",
            "programs" => "全盘程序文件",
            SensitiveFiles.Module => "敏感文件",
            _ => module,
        };

    public static string Status(string status) =>
        status switch
        {
            "Complete" => "已完成",
            "Error" => "读取失败",
            "Unknown" => "未覆盖",
            "Truncated" => "命中过多，仅列出部分",
            _ => status,
        };

    public static string Scope(string? scope, IReadOnlyDictionary<string, string>? names = null) =>
        scope is null or "machine" ? "整机"
        : SensitiveFiles.IsDriveScope(scope) ? scope[^1] + " 盘"
        : names is not null && names.TryGetValue(scope, out var name) ? "用户 " + name
        : "用户 " + scope;

    public static IReadOnlyDictionary<string, string> AccountNames(ScanSnapshot snapshot) =>
        (snapshot.Users ?? []).DistinctBy(u => u.Sid).ToDictionary(u => u.Sid, u => u.Name);

    public static string Evidence(EvidenceKind kind) =>
        kind switch
        {
            EvidenceKind.Installation => "安装记录",
            EvidenceKind.Process => "运行进程",
            EvidenceKind.Extension => "扩展",
            EvidenceKind.Proxy => "代理设置",
            EvidenceKind.Clue => "待核查线索",
            EvidenceKind.BlockedAttempt => "拦截记录",
            EvidenceKind.SensitiveFile => "敏感文件",
            _ => kind.ToString(),
        };

    public static string Control(string id) =>
        id switch
        {
            "process" => "发现即结束进程",
            "browser" => "浏览器网址拦截",
            "application" => "应用程序拦截（旧）",
            "edge" => "Edge 浏览器策略（旧）",
            "network" => "网络访问拦截（旧）",
            _ => id,
        };

    public static string ControlState(string state) =>
        state switch
        {
            "Verified" => "已验证",
            "Ready" => "可启用",
            "Applied" => "已生效",
            "AppliedUnverified" => "已应用，未验证",
            "PendingManualApplication" => "待人工部署",
            "Uncovered" => "未覆盖",
            "Error" => "读取失败",
            _ => state,
        };

    public static string YesNo(bool value) => value ? "是" : "否";

    public static string Verdict(Verdict verdict) =>
        verdict switch
        {
            Core.Verdict.PASS => "通过",
            Core.Verdict.FAIL => "不通过",
            _ => "无法判断",
        };

    public static string Online(string state) =>
        state switch
        {
            "Online" => "在线",
            "SuspectedOffline" => "疑似失联",
            "Offline" => "失联",
            _ => state,
        };

    public static string AlertType(string type) =>
        type switch
        {
            "Violation" => "确认违规",
            "BlockedAttempt" => "已拦截",
            "Health" => "设备健康",
            "Offline" => "设备失联",
            "Clue" => "待核查线索",
            "SensitiveFile" => "敏感文件",
            _ => type,
        };
}
