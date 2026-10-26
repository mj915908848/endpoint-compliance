namespace Compliance.Core;

/// <summary>A security baseline check the agent knows how to run.</summary>
/// <param name="Requirement">What a passing device meets; "{0}" stands for the rule's limit.</param>
/// <param name="DefaultLimit">The limit used when a rule leaves it at 0; 0 for checks without a limit.</param>
/// <param name="Unit">The limit's unit, e.g. "天".</param>
public sealed record BaselineCheck(
    string Id,
    string Name,
    string Requirement,
    int DefaultLimit = 0,
    int MaxLimit = 0,
    string Unit = ""
);

/// <summary>Checks, limits and naming shared by the agent, the report engine and policy validation.</summary>
public static class Baseline
{
    /// <summary>Each check reports as its own module, e.g. "baseline:firewall", so one unreadable check stays alone.</summary>
    public const string ModulePrefix = "baseline:";

    public static readonly BaselineCheck[] Checks =
    [
        new("antivirus", "杀毒软件", "已安装杀毒软件，实时防护已开启，病毒库为最新"),
        new("firewall", "防火墙", "防火墙已开启"),
        new("updates", "系统更新", "最近 {0} 天内成功安装过系统更新", 30, 365, "天"),
        new("bitlocker", "BitLocker 加密", "系统盘已开启 BitLocker 加密保护"),
        new("screenlock", "自动锁屏", "无操作 {0} 分钟内锁屏，恢复时需要密码", 15, 120, "分钟"),
        new("guest", "来宾账户", "来宾（Guest）账户已停用"),
        new("admins", "本地管理员", "本地管理员组中只有内置管理员和允许的账户"),
        new("rdp", "远程桌面", "远程桌面已关闭"),
        new("smb1", "SMBv1 协议", "SMBv1 文件共享协议已关闭"),
    ];

    public static string Module(string id) => ModulePrefix + id;

    public static bool IsModule(string? module) => module is not null && module.StartsWith(ModulePrefix);

    public static BaselineCheck? Check(string id) => Checks.FirstOrDefault(c => c.Id == id);

    /// <summary>The check's display name; the id itself for checks this version does not know.</summary>
    public static string Name(string id) => Check(id)?.Name ?? id;

    /// <summary>The rules the agent runs: none while baseline checking is off.</summary>
    public static BaselineRule[] Active(PolicyDocument policy) => policy.Baseline is { Enabled: true } b ? b.Rules : [];

    /// <summary>The active rule a module or evidence product id belongs to.</summary>
    public static BaselineRule? Rule(PolicyDocument policy, string idOrModule)
    {
        var id = IsModule(idOrModule) ? idOrModule[ModulePrefix.Length..] : idOrModule;
        return Active(policy).FirstOrDefault(r => r.Id == id);
    }

    public static bool Runs(PolicyDocument policy, string module) =>
        IsModule(module) && Rule(policy, module) is not null;

    public static int Limit(BaselineRule rule) => rule.Limit > 0 ? rule.Limit : Check(rule.Id)?.DefaultLimit ?? 0;

    /// <summary>"最近 30 天内成功安装过系统更新"</summary>
    public static string Requirement(BaselineRule rule) =>
        string.Format(Check(rule.Id)?.Requirement ?? rule.Id, Limit(rule));

    public static bool HasViolationRules(PolicyDocument policy) => Active(policy).Any(r => r.Action == "Violation");

    public static void Validate(BaselinePolicy? policy)
    {
        if (policy is null || policy.Rules is null)
            throw new ArgumentException("安全基线配置不完整");
        foreach (var rule in policy.Rules)
        {
            var check = rule is null || rule.Id is null ? null : Check(rule.Id);
            if (check is null || rule!.Action is not ("Alert" or "Violation"))
                throw new ArgumentException("安全基线规则无效：检查项不受支持，处理方式只能是告警或违规");
            if (rule.Limit < 0 || rule.Limit > 0 && (check.MaxLimit == 0 || rule.Limit > check.MaxLimit))
                throw new ArgumentException(
                    check.MaxLimit == 0
                        ? $"安全基线“{check.Name}”没有可设置的期限"
                        : $"安全基线“{check.Name}”的期限需为 1–{check.MaxLimit} {check.Unit}"
                );
            if (
                rule.Exempt is null
                || rule.Exempt.Length > 50
                || rule.Exempt.Any(n => string.IsNullOrWhiteSpace(n) || n.Trim() != n || n.Length > 64)
            )
                throw new ArgumentException($"安全基线“{check.Name}”的允许账户无效：最多 50 个，每个不超过 64 个字符");
        }
        if (policy.Rules.Select(r => r.Id).Distinct().Count() != policy.Rules.Length)
            throw new ArgumentException("安全基线的检查项不能重复");
        if (policy.Enabled && policy.Rules.Length == 0)
            throw new ArgumentException("启用安全基线需要至少选择一个检查项");
    }
}
