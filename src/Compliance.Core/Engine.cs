namespace Compliance.Core;

public static class ReportEngine
{
    private static string ModuleGap(ModuleResult m, IReadOnlyDictionary<string, string> names) =>
        $"{Labels.Module(m.Module)}（{Labels.Scope(m.Scope, names)}）：{Labels.Status(m.Status)}"
        + (string.IsNullOrWhiteSpace(m.Error) ? "" : "，" + m.Error);

    public static ComplianceReport Evaluate(PolicyDocument policy, ScanSnapshot snapshot, DateTimeOffset now)
    {
        snapshot = EvidenceSanitizer.Sanitize(snapshot);
        // Every comparison with "now" goes through Within or Note, which keep the earliest later moment its outcome
        // changes: until then the same inputs give the same report.
        var validUntil = DateTimeOffset.MaxValue;
        // Records the moment "offset" after t, unless it lies outside DateTimeOffset's range (timestamps an agent left
        // unset are MinValue).
        void Note(DateTimeOffset t, TimeSpan offset)
        {
            if (offset > TimeSpan.Zero ? t > DateTimeOffset.MaxValue - offset : t < DateTimeOffset.MinValue - offset)
                return;
            var at = t + offset;
            if (at > now && at < validUntil)
                validUntil = at;
        }
        // Data collected at t counts from two minutes before t (clock skew) until "minutes" after it, inclusive.
        bool Within(DateTimeOffset t, double minutes)
        {
            Note(t, TimeSpan.FromMinutes(-2));
            Note(t, TimeSpan.FromMinutes(minutes) + TimeSpan.FromTicks(1));
            return t >= now.AddMinutes(-minutes) && t <= now.AddMinutes(2);
        }
        var names = Labels.AccountNames(snapshot);
        var gaps = new List<string>();
        if (policy.SchemaVersion != 1 || snapshot.SchemaVersion != 1)
            gaps.Add("策略或检查数据的格式版本不受支持");
        if (!policy.DenyInstalled || !policy.DenyProxy || policy.RequiredModules.Length == 0)
            gaps.Add("策略未完整定义禁用规则或必需检查项");
        if (policy.Mode is not ("Audit" or "Enforce"))
            gaps.Add("策略模式无法识别");
        Note(policy.ExpiresAt, TimeSpan.FromTicks(1));
        Note(policy.IssuedAt, TimeSpan.FromMinutes(-2));
        if (policy.ExpiresAt < now || policy.IssuedAt > now.AddMinutes(2))
            gaps.Add("策略已过期或签发时间异常");
        if (snapshot.PolicyVersion != policy.Serial)
            gaps.Add("终端检查所用的策略版本与当前策略不一致");
        if (snapshot.Simulated)
            gaps.Add("检查数据来自模拟终端，未经 Windows 实机验证");
        if (!snapshot.Platform.Equals("Windows", StringComparison.OrdinalIgnoreCase))
            gaps.Add("终端平台不受支持");
        bool current = Within(snapshot.CollectedAt, policy.LightweightFreshMinutes);
        if (!current)
            gaps.Add("检查结果已过期或采集时间异常");
        foreach (var module in policy.RequiredModules.Where(m => m != SensitiveFiles.Module))
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
                if (!Within(entry.CollectedAt, policy.FreshMinutes(module)))
                    gaps.Add($"{Labels.Module(module)}（{Labels.Scope(entry.Scope, names)}）：数据已过期或时间异常");
            }
        }
        foreach (var m in snapshot.Modules.Where(m => m.Status != "Complete" && m.Module != SensitiveFiles.Module))
            gaps.Add(ModuleGap(m, names));
        // Sensitive file scans only limit the verdict when a rule can make the device fail; otherwise their
        // problems are notes for the administrator.
        var sensitive = policy.SensitiveFiles;
        var sensitiveRules = sensitive.Enabled
            ? sensitive.Rules.ToDictionary(r => r.Id, StringComparer.Ordinal)
            : new Dictionary<string, SensitiveFileRule>();
        var sensitiveIssues = new List<string>();
        if (sensitive.Enabled)
        {
            var entries = snapshot.Modules.Where(m => m.Module == SensitiveFiles.Module).ToArray();
            if (entries.Length == 0)
                sensitiveIssues.Add("敏感文件：终端尚未上报扫描结果，首次扫描可能仍在进行");
            foreach (var entry in entries)
            {
                if (entry.Status != "Complete")
                    sensitiveIssues.Add(ModuleGap(entry, names));
                if (!Within(entry.CollectedAt, SensitiveFiles.FreshMinutes(policy)))
                    sensitiveIssues.Add(
                        $"{Labels.Module(entry.Module)}（{Labels.Scope(entry.Scope, names)}）：数据已过期或时间异常"
                    );
            }
        }
        var controlsMissing = new List<string>();
        foreach (var id in Controls.Normalize(policy.RequiredControls))
        {
            var c = snapshot.Controls.FirstOrDefault(c => c.Id == id);
            if (
                c is null
                || !c.Verified
                || c.Version != policy.Serial
                || c.RebootRequired
                || c.State is not ("Verified" or "Applied")
            )
                controlsMissing.Add($"{Labels.Control(id)}（{c?.Detail ?? "终端未上报"}）");
        }
        if (policy.Mode == "Enforce")
            gaps.AddRange(controlsMissing);
        string protection =
            policy.Mode == "Audit" ? "审计模式：只检查，不拦截"
            : controlsMissing.Count == 0 ? "强制模式：所需防护措施均已生效"
            : "以下防护措施尚未生效：" + string.Join("；", controlsMissing);
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
            if (e.Kind == EvidenceKind.SensitiveFile)
            {
                var at = e.CollectedAt ?? snapshot.CollectedAt;
                return Within(at, SensitiveFiles.FreshMinutes(policy));
            }
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
            return Within(time, minutes);
        }
        foreach (var e in snapshot.Evidence.Where(e => e.Confirmed && !EvidenceFresh(e)))
            if (e.Kind != EvidenceKind.SensitiveFile)
                gaps.Add($"{e.ProductName}：证据已过期或时间异常，需要重新检查");
            else if (sensitive.Enabled)
                sensitiveIssues.Add($"{e.ProductName}：证据已过期或时间异常，需要重新检查");
        bool sensitiveRequired =
            SensitiveFiles.HasViolationRules(policy) || policy.RequiredModules.Contains(SensitiveFiles.Module);
        if (sensitiveRequired)
            gaps.AddRange(sensitiveIssues);
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
                || current
                    && e.Kind == EvidenceKind.SensitiveFile
                    && e.Confirmed
                    && EvidenceFresh(e)
                    && sensitiveRules.TryGetValue(e.ProductId, out var rule)
                    && rule.Action == "Violation"
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
        )
        {
            SensitiveFileNotes = sensitiveRequired ? [] : sensitiveIssues.Distinct().ToArray(),
            PolicyName = policy.PolicyId,
            PolicyVersion = policy.Version,
            ValidUntil = validUntil == DateTimeOffset.MaxValue ? null : validUntil,
        };
    }
}
