namespace Compliance.Core;

public static class ReportEngine
{
    private static string ModuleGap(ModuleResult m, IReadOnlyDictionary<string, string> names) =>
        $"{Labels.Module(m.Module)}（{Labels.Scope(m.Scope, names)}）：{Labels.Status(m.Status)}"
        + (string.IsNullOrWhiteSpace(m.Error) ? "" : "，" + m.Error);

    public static ComplianceReport Evaluate(PolicyDocument policy, ScanSnapshot snapshot, DateTimeOffset now)
    {
        snapshot = EvidenceSanitizer.Sanitize(snapshot);
        var names = Labels.AccountNames(snapshot);
        var gaps = new List<string>();
        if (policy.SchemaVersion != 1 || snapshot.SchemaVersion != 1)
            gaps.Add("策略或检查数据的格式版本不受支持");
        if (!policy.DenyInstalled || !policy.DenyProxy || policy.RequiredModules.Length == 0)
            gaps.Add("策略未完整定义禁用规则或必需检查项");
        if (policy.Mode is not ("Audit" or "Enforce"))
            gaps.Add("策略模式无法识别");
        if (policy.ExpiresAt < now || policy.IssuedAt > now.AddMinutes(2))
            gaps.Add("策略已过期或签发时间异常");
        if (snapshot.PolicyVersion != policy.Version)
            gaps.Add("终端检查所用的策略版本与当前策略不一致");
        if (snapshot.Simulated)
            gaps.Add("检查数据来自模拟终端，未经 Windows 实机验证");
        if (!snapshot.Platform.Equals("Windows", StringComparison.OrdinalIgnoreCase))
            gaps.Add("终端平台不受支持");
        bool current =
            snapshot.CollectedAt <= now.AddMinutes(2)
            && snapshot.CollectedAt >= now.AddMinutes(-policy.LightweightFreshMinutes);
        if (!current)
            gaps.Add("检查结果已过期或采集时间异常");
        foreach (var module in policy.RequiredModules)
        {
            var entries = snapshot.Modules.Where(m => m.Module == module).ToArray();
            if (entries.Length == 0)
            {
                gaps.Add($"缺少必需检查项：{Labels.Module(module)}");
                continue;
            }
            foreach (var entry in entries)
            {
                if (entry.Status != "Complete")
                    gaps.Add(ModuleGap(entry, names));
                var minutes = module is "installed" or "extensions" or "appx" or "users" or "cli"
                    ? policy.InventoryFreshMinutes
                    : policy.LightweightFreshMinutes;
                if (entry.CollectedAt < now.AddMinutes(-minutes) || entry.CollectedAt > now.AddMinutes(2))
                    gaps.Add($"{Labels.Module(module)}（{Labels.Scope(entry.Scope, names)}）：数据已过期或时间异常");
            }
        }
        foreach (var m in snapshot.Modules.Where(m => m.Status != "Complete"))
            gaps.Add(ModuleGap(m, names));
        var controlsMissing = new List<string>();
        foreach (var id in policy.RequiredControls)
        {
            var c = snapshot.Controls.FirstOrDefault(c => c.Id == id);
            if (
                c is null
                || !c.Verified
                || c.Version != policy.Version
                || c.RebootRequired
                || c.State is not ("Verified" or "Applied")
            )
                controlsMissing.Add($"{id}（{c?.Detail ?? "终端未上报"}）");
        }
        if (policy.Mode == "Enforce")
            gaps.AddRange(controlsMissing);
        string protection =
            policy.Mode == "Audit" ? "审计模式：只检查，不拦截"
            : controlsMissing.Count == 0 ? "所需防护措施均已验证"
            : "以下防护措施尚未验证：" + string.Join("；", controlsMissing);
        var knownIds = policy.Products.Select(x => x.Id).ToHashSet(StringComparer.Ordinal);
        foreach (
            var e in snapshot.Evidence.Where(e =>
                e.Confirmed
                && e.Kind is EvidenceKind.Installation or EvidenceKind.Process or EvidenceKind.Extension
                && !knownIds.Contains(e.ProductId)
            )
        )
            gaps.Add($"发现策略中未定义的产品：{e.ProductId}，请核查规则");
        bool EvidenceFresh(Evidence e)
        {
            var module = e.Kind switch
            {
                EvidenceKind.Installation => "installed",
                EvidenceKind.Extension => "extensions",
                EvidenceKind.Proxy => "proxy",
                _ => "processes",
            };
            var moduleTimes = snapshot
                .Modules.Where(m => m.Module == module && (m.Scope == e.UserSid || m.Scope == "machine"))
                .Select(m => m.CollectedAt)
                .ToArray();
            var time = e.CollectedAt ?? (moduleTimes.Length > 0 ? moduleTimes.Min() : snapshot.CollectedAt);
            var minutes = e.Kind is EvidenceKind.Installation or EvidenceKind.Extension
                ? policy.InventoryFreshMinutes
                : policy.LightweightFreshMinutes;
            return time >= now.AddMinutes(-minutes) && time <= now.AddMinutes(2);
        }
        foreach (var e in snapshot.Evidence.Where(e => e.Confirmed && !EvidenceFresh(e)))
            gaps.Add($"{e.ProductName}：证据已过期或时间异常，需要重新检查");
        var confirmed = snapshot
            .Evidence.Where(e =>
                current
                && EvidenceFresh(e)
                && e.Confirmed
                && e.Kind
                    is EvidenceKind.Installation
                        or EvidenceKind.Process
                        or EvidenceKind.Extension
                        or EvidenceKind.Proxy
                && (e.Kind == EvidenceKind.Proxy || knownIds.Contains(e.ProductId))
            )
            .ToArray();
        var objects = confirmed.GroupBy(e => (e.ProductId, Scope: e.UserSid ?? "machine")).ToArray();
        var reasons = objects
            .Select(group =>
            {
                var kinds = group.Select(e => Labels.Evidence(e.Kind)).Distinct();
                return $"{group.First().ProductName}（{Labels.Scope(group.Key.Scope, names)}）：{string.Join("、", kinds)}，共 {group.Count()} 条证据";
            })
            .ToArray();
        int count = objects.Length;
        var verdict =
            confirmed.Length > 0 ? Verdict.FAIL
            : gaps.Count > 0 ? Verdict.UNKNOWN
            : Verdict.PASS;
        string summary = verdict switch
        {
            Verdict.FAIL => $"不通过：发现 {count} 个违规对象",
            Verdict.UNKNOWN => "无法判断：检查覆盖或防护验证不完整",
            _ => "通过：必需检查项均为有效数据，未发现确认违规",
        };
        return new(
            verdict,
            summary,
            reasons,
            gaps.Distinct().ToArray(),
            count,
            confirmed.Length,
            protection,
            EvidenceSanitizer.Sanitize(snapshot)
        );
    }
}
