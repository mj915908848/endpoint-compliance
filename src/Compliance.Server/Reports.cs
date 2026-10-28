using System.Globalization;
using System.Text;
using Compliance.Core;

namespace Compliance.Server;

/// <summary>Devices by verdict at one moment.</summary>
public sealed record ReportCounts(int Devices, int Pass, int Fail, int Unknown);

/// <summary>One group's devices by verdict at the end of the period; groups as they are now.</summary>
public sealed record ReportGroup(string Group, int Devices, int Pass, int Fail, int Unknown);

/// <summary>A problem alerts were raised for during the period: a product, a baseline check, a file rule, a kind.</summary>
public sealed record ReportIssue(string Type, string Subject, int Devices, int Alerts);

/// <summary>Alerts of one type opened during the period, and on how many devices.</summary>
public sealed record ReportAlertType(string Type, int Opened, int Devices);

/// <summary>A device failing now, since when without a break, and how many violating objects it has now.</summary>
public sealed record LingeringDevice(
    string DeviceId,
    string HostName,
    string Note,
    string Group,
    DateTimeOffset Since,
    int ViolationCount
);

/// <summary>
/// The compliance report for the days <see cref="From"/> to <see cref="To"/> (both included) in the reader's time zone:
/// verdicts at the start and end and on each day, by group, the problems alerts were raised for, and the devices that
/// have been failing longest.
/// </summary>
public sealed record PeriodReport(
    DateOnly From,
    DateOnly To,
    DateTimeOffset GeneratedAt,
    ReportCounts Start,
    ReportCounts End,
    TrendDay[] Days,
    ReportGroup[] Groups,
    ReportIssue[] Issues,
    ReportAlertType[] AlertTypes,
    LingeringDevice[] Lingering
);

public static class Reports
{
    /// <summary>Longest period a report covers; verdict history is kept 400 days.</summary>
    public const int MaxDays = 366;

    /// <summary>Failing this many days or more counts as not dealt with.</summary>
    public const int LingeringDays = 7;

    const int MaxIssues = 20;
    const int MaxLingering = 100;

    /// <summary>Alert types that are problems on the device; going offline and asking for exceptions are not.</summary>
    static readonly string[] IssueTypes =
    [
        "Violation",
        "SensitiveFile",
        "Baseline",
        "Tamper",
        "Health",
        "BlockedAttempt",
        UsbStorage.Blocked,
    ];

    static ReportCounts Count(IEnumerable<Verdict> verdicts)
    {
        var list = verdicts.ToList();
        return new(
            list.Count,
            list.Count(v => v == Verdict.PASS),
            list.Count(v => v == Verdict.FAIL),
            list.Count(v => v == Verdict.UNKNOWN)
        );
    }

    /// <summary>
    /// Builds the report. <paramref name="before"/> holds each device's last verdict change before the period,
    /// <paramref name="changes"/> every change from its start on, <paramref name="latest"/> each device's last change
    /// overall, and <paramref name="alerts"/> the alerts open at some time during the period.
    /// </summary>
    public static PeriodReport Build(
        DateOnly from,
        DateOnly to,
        TimeSpan offset,
        DateTimeOffset now,
        List<DeviceRecord> devices,
        List<VerdictChange> before,
        List<VerdictChange> changes,
        List<VerdictChange> latest,
        List<AlertSummary> alerts,
        IReadOnlyDictionary<string, string> productNames
    )
    {
        var start = new DateTimeOffset(from.ToDateTime(TimeOnly.MinValue), offset);
        var end = new DateTimeOffset(to.AddDays(1).ToDateTime(TimeOnly.MinValue), offset);
        var days = to.DayNumber - from.DayNumber + 1;
        var daily = VerdictTrend.Daily(end.AddTicks(-1), days, offset, before, changes);

        var state = before.ToDictionary(c => c.DeviceId, c => c.Verdict);
        var startCounts = Count(state.Values);
        foreach (var c in changes.Where(c => c.At < end).OrderBy(c => c.At))
            state[c.DeviceId] = c.Verdict;
        var heads = devices.ToDictionary(d => d.Id);

        var groups = state
            .Where(s => heads.ContainsKey(s.Key))
            .GroupBy(s => heads[s.Key].Group)
            .Select(g =>
            {
                var counts = Count(g.Select(x => x.Value));
                return new ReportGroup(g.Key, counts.Devices, counts.Pass, counts.Fail, counts.Unknown);
            })
            // Least compliant first: those are the groups to talk to.
            .OrderBy(g => (double)g.Pass / g.Devices)
            .ThenByDescending(g => g.Devices)
            .ThenBy(g => g.Group, StringComparer.CurrentCulture)
            .ToArray();

        var during = alerts.Where(a => a.FirstSeen < end && (a.State != "Resolved" || a.LastSeen >= start)).ToList();
        var issues = during
            .Where(a => IssueTypes.Contains(a.Type))
            .GroupBy(a => (a.Type, Subject: Subject(a, productNames)))
            .Select(g => new ReportIssue(
                g.Key.Type,
                g.Key.Subject,
                g.Select(a => a.DeviceId).Distinct().Count(),
                g.Count()
            ))
            .OrderByDescending(i => i.Devices)
            .ThenByDescending(i => i.Alerts)
            .ThenBy(i => i.Subject, StringComparer.CurrentCulture)
            .Take(MaxIssues)
            .ToArray();
        var opened = during.Where(a => a.FirstSeen >= start).ToList();
        var alertTypes = opened
            .GroupBy(a => a.Type)
            .Select(g => new ReportAlertType(g.Key, g.Count(), g.Select(a => a.DeviceId).Distinct().Count()))
            .OrderByDescending(t => t.Opened)
            .ThenBy(t => t.Type, StringComparer.Ordinal)
            .ToArray();

        // Failing now by the stored verdict, since the change that made it fail.
        var failedAt = latest.Where(c => c.Verdict == Verdict.FAIL).ToDictionary(c => c.DeviceId, c => c.At);
        var lingering = devices
            .Where(d => d.Verdict?.Current == Verdict.FAIL)
            .Select(d => new LingeringDevice(
                d.Id,
                d.HostName,
                d.Note,
                d.Group,
                failedAt.GetValueOrDefault(d.Id, d.Verdict!.ComputedAt),
                d.Verdict!.ViolationCount
            ))
            .OrderBy(d => d.Since)
            .ThenBy(d => d.HostName, StringComparer.CurrentCulture)
            .Take(MaxLingering)
            .ToArray();

        var last = daily[^1];
        return new(
            from,
            to,
            now,
            startCounts,
            new(last.Pass + last.Fail + last.Unknown, last.Pass, last.Fail, last.Unknown),
            daily,
            groups,
            issues,
            alertTypes,
            lingering
        );
    }

    /// <summary>Reads what the report needs and builds it; <paramref name="to"/> may not be after today.</summary>
    public static async Task<PeriodReport> Load(
        Transaction tx,
        ComplianceService s,
        DateOnly from,
        DateOnly to,
        TimeSpan offset
    )
    {
        var start = new DateTimeOffset(from.ToDateTime(TimeOnly.MinValue), offset);
        var products = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var p in (await s.Policies.All(tx)).SelectMany(p => p.Document.Products))
            products.TryAdd(p.Id, p.Name);
        return Build(
            from,
            to,
            offset,
            s.Now,
            await tx.DeviceHeads(),
            await tx.VerdictsBefore(start),
            await tx.VerdictChangesSince(start),
            await tx.VerdictsBefore(s.Now.AddSeconds(1)),
            await tx.AlertsNewestFirst(start),
            products
        );
    }

    /// <summary>
    /// What an alert is about, for counting alike ones together: the product of a violation found in a snapshot
    /// (object key "product|user"), the check or rule named before "：" in baseline and file alerts, or the type.
    /// </summary>
    static string Subject(AlertSummary a, IReadOnlyDictionary<string, string> productNames)
    {
        var product = a.ObjectKey.Split('|')[0];
        if (productNames.TryGetValue(product, out var name))
            return name;
        if (a.Type is "Violation" or "SensitiveFile" or "Baseline")
        {
            var cut = a.Summary.IndexOf('：');
            var head = cut > 0 ? a.Summary[..cut] : a.Summary;
            return head.Length > 60 ? head[..60] + "…" : head;
        }
        return Labels.AlertType(a.Type);
    }

    public static double Rate(ReportCounts c) => c.Devices == 0 ? 0 : (double)c.Pass / c.Devices;

    static string Percent(ReportCounts c) => c.Devices == 0 ? "—" : $"{Rate(c) * 100:0.#}%";

    static string Device(string host, string note) => note.Length > 0 ? $"{host}（{note}）" : host;

    static string Group(string group) => group.Length > 0 ? group : "未分组";

    static string Escape(string text) => text.Replace("|", "\\|").ReplaceLineEndings(" ");

    public static string Period(PeriodReport r) =>
        r.From == r.To ? $"{r.From:yyyy-MM-dd}" : $"{r.From:yyyy-MM-dd} 至 {r.To:yyyy-MM-dd}";

    /// <summary>The change of the compliance rate from start to end, in percentage points.</summary>
    static string RateChange(PeriodReport r)
    {
        if (r.Start.Devices == 0 || r.End.Devices == 0)
            return "";
        var points = (Rate(r.End) - Rate(r.Start)) * 100;
        return Math.Abs(points) < 0.05
            ? "，与期初持平"
            : $"，较期初{(points > 0 ? "上升" : "下降")} {Math.Abs(points):0.#} 个百分点";
    }

    /// <summary>The report as a Markdown document, for download.</summary>
    public static string Markdown(PeriodReport r, TimeSpan offset)
    {
        var b = new StringBuilder();
        var local = (DateTimeOffset t) => t.ToOffset(offset).ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
        b.AppendLine($"# 终端合规报表（{Period(r)}）");
        b.AppendLine();
        b.AppendLine($"生成于 {local(r.GeneratedAt)}。");
        b.AppendLine();
        b.AppendLine("## 1. 概况");
        b.AppendLine();
        b.AppendLine(
            $"期末在用终端 {r.End.Devices} 台：通过 {r.End.Pass} 台，不通过 {r.End.Fail} 台，无法判断 {r.End.Unknown} 台，合规率（通过占比）{Percent(r.End)}{RateChange(r)}。"
        );
        b.AppendLine();
        b.AppendLine("| | 终端 | 通过 | 不通过 | 无法判断 | 合规率 |");
        b.AppendLine("|---|---|---|---|---|---|");
        b.AppendLine(
            $"| 期初 | {r.Start.Devices} | {r.Start.Pass} | {r.Start.Fail} | {r.Start.Unknown} | {Percent(r.Start)} |"
        );
        b.AppendLine($"| 期末 | {r.End.Devices} | {r.End.Pass} | {r.End.Fail} | {r.End.Unknown} | {Percent(r.End)} |");
        b.AppendLine();
        b.AppendLine("## 2. 每日趋势");
        b.AppendLine();
        b.AppendLine("| 日期 | 通过 | 不通过 | 无法判断 | 合规率 |");
        b.AppendLine("|---|---|---|---|---|");
        foreach (var d in r.Days)
            b.AppendLine(
                $"| {d.Date:yyyy-MM-dd} | {d.Pass} | {d.Fail} | {d.Unknown} | {Percent(new(d.Pass + d.Fail + d.Unknown, d.Pass, d.Fail, d.Unknown))} |"
            );
        b.AppendLine();
        b.AppendLine("## 3. 分组排名");
        b.AppendLine();
        b.AppendLine("按期末合规率从低到高；分组按终端现在所在的分组统计。");
        b.AppendLine();
        b.AppendLine("| 分组 | 终端 | 通过 | 不通过 | 无法判断 | 合规率 |");
        b.AppendLine("|---|---|---|---|---|---|");
        foreach (var g in r.Groups)
            b.AppendLine(
                $"| {Escape(Group(g.Group))} | {g.Devices} | {g.Pass} | {g.Fail} | {g.Unknown} | {Percent(new(g.Devices, g.Pass, g.Fail, g.Unknown))} |"
            );
        b.AppendLine();
        b.AppendLine("## 4. 最常见的问题");
        b.AppendLine();
        if (r.Issues.Length == 0)
            b.AppendLine("期间没有违规、基线、敏感文件、防篡改、设备健康或拦截告警。");
        else
        {
            b.AppendLine("| 类型 | 问题 | 涉及终端 | 告警 |");
            b.AppendLine("|---|---|---|---|");
            foreach (var i in r.Issues)
                b.AppendLine($"| {Labels.AlertType(i.Type)} | {Escape(i.Subject)} | {i.Devices} | {i.Alerts} |");
        }
        b.AppendLine();
        b.AppendLine("## 5. 期间新增告警");
        b.AppendLine();
        if (r.AlertTypes.Length == 0)
            b.AppendLine("期间没有新增告警。");
        else
        {
            b.AppendLine("| 类型 | 新增告警 | 涉及终端 |");
            b.AppendLine("|---|---|---|");
            foreach (var t in r.AlertTypes)
                b.AppendLine($"| {Labels.AlertType(t.Type)} | {t.Opened} | {t.Devices} |");
        }
        b.AppendLine();
        b.AppendLine("## 6. 长期未整改");
        b.AppendLine();
        b.AppendLine(
            $"截至 {local(r.GeneratedAt)} 仍不通过的终端，按开始不通过的时间排列；满 {LingeringDays} 天的标注“超期”。"
        );
        b.AppendLine();
        if (r.Lingering.Length == 0)
            b.AppendLine("没有不通过的终端。");
        else
        {
            b.AppendLine("| 终端 | 分组 | 不通过开始于 | 持续 | 违规对象 |");
            b.AppendLine("|---|---|---|---|---|");
            foreach (var d in r.Lingering)
            {
                var span = (int)(r.GeneratedAt - d.Since).TotalDays;
                b.AppendLine(
                    $"| {Escape(Device(d.HostName, d.Note))} | {Escape(Group(d.Group))} | {local(d.Since)} | {span} 天{(span >= LingeringDays ? "（超期）" : "")} | {d.ViolationCount} |"
                );
            }
        }
        b.AppendLine();
        b.AppendLine("---");
        b.AppendLine();
        b.AppendLine(
            "说明：每日趋势按每天结束时各终端的结论统计；归档的终端不计入。告警统计包含期间内任何时候处于未恢复状态的告警，已超过保留期限被清理的告警不计入。"
        );
        return b.ToString();
    }

    /// <summary>A short summary for a group robot.</summary>
    public static string Summary(PeriodReport r, string title, string consoleUrl)
    {
        var b = new StringBuilder($"【终端合规】{title}（{Period(r)}）");
        b.Append(
            $"\n在用终端 {r.End.Devices} 台：通过 {r.End.Pass}，不通过 {r.End.Fail}，无法判断 {r.End.Unknown}；合规率 {Percent(r.End)}{RateChange(r)}"
        );
        var weakest = r.Groups.Where(g => g.Fail > 0).Take(3).ToArray();
        if (weakest.Length > 0)
            b.Append(
                "\n不通过较多的分组："
                    + string.Join("、", weakest.Select(g => $"{Group(g.Group)} {g.Fail}/{g.Devices} 台"))
            );
        if (r.Issues.Length > 0)
            b.Append(
                "\n最常见的问题：" + string.Join("、", r.Issues.Take(5).Select(i => $"{i.Subject}（{i.Devices} 台）"))
            );
        var overdue = r.Lingering.Count(d => r.GeneratedAt - d.Since >= TimeSpan.FromDays(LingeringDays));
        if (overdue > 0)
            b.Append($"\n不通过超过 {LingeringDays} 天仍未整改：{overdue} 台");
        if (consoleUrl.Length > 0)
            b.Append($"\n\n查看报表：{consoleUrl.TrimEnd('/')}/reports?from={r.From:yyyy-MM-dd}&to={r.To:yyyy-MM-dd}");
        return b.ToString();
    }
}
