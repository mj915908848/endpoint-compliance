using System.Text;
using System.Text.RegularExpressions;

namespace Compliance.Core;

/// <summary>A rule that matched a name, and the keyword that matched first.</summary>
public readonly record struct SensitiveNameMatch(SensitiveFileRule Rule, string Keyword);

/// <summary>Rules, limits and naming shared by the agent scan, the report engine and policy validation.</summary>
public static class SensitiveFiles
{
    public const string Module = "sensitive-files";

    /// <summary>Scope of a fixed drive other than the system drive, e.g. "drive:D".</summary>
    public static string DriveScope(char letter) => "drive:" + char.ToUpperInvariant(letter);

    public static bool IsDriveScope(string? scope) => scope is { Length: 7 } && scope.StartsWith("drive:");

    /// <summary>
    /// Results stay valid for one scan interval plus the time a large drive may take to walk, so a device does not
    /// drop out of coverage while the next scan is still running.
    /// </summary>
    public static int FreshMinutes(PolicyDocument policy) => policy.SensitiveFiles.RescanHours * 60 + 240;

    public static bool HasViolationRules(PolicyDocument policy) =>
        policy.SensitiveFiles.Enabled && policy.SensitiveFiles.Rules.Any(r => r.Action == "Violation");

    /// <summary>Case and full-width/half-width differences are ignored; Chinese text is compared as written.</summary>
    public static string Normalize(string value) => value.Normalize(NormalizationForm.FormKC).ToUpperInvariant();

    public static void Validate(SensitiveFilePolicy? policy)
    {
        if (policy is null || policy.Rules is null || policy.ExcludePaths is null)
            throw new ArgumentException("敏感文件扫描配置不完整");
        if (policy.RescanHours is < 1 or > 168)
            throw new ArgumentException("敏感文件扫描间隔需为 1–168 小时");
        if (policy.MaxHitsPerScope is < 1 or > 1000)
            throw new ArgumentException("每个范围最多上报的敏感文件数需为 1–1000");
        if (
            policy.ExcludePaths.Length > 200
            || policy.ExcludePaths.Any(p => string.IsNullOrWhiteSpace(p) || p.Length > 260)
        )
            throw new ArgumentException("排除目录最多 200 项，每项不能为空且不超过 260 个字符");
        if (policy.Rules.Length > 100)
            throw new ArgumentException("敏感文件规则最多 100 条");
        foreach (var rule in policy.Rules)
        {
            if (
                rule is null
                || rule.Id is null
                || !Regex.IsMatch(rule.Id, "^[a-z0-9][a-z0-9._-]{0,63}$")
                || string.IsNullOrWhiteSpace(rule.Name)
                || rule.Name.Length > 64
                || rule.Action is not ("Alert" or "Violation")
            )
                throw new ArgumentException(
                    "敏感文件规则无效：需要标识（小写字母、数字）、名称，处理方式只能是告警或违规"
                );
            if (
                rule.Keywords is null
                || rule.Keywords.Length is 0 or > 100
                || rule.Keywords.Any(k => k is null || k.Trim() != k || k.Length is < 2 or > 64)
            )
                throw new ArgumentException($"敏感文件规则“{rule.Name}”的关键词无效：需要 1–100 个，每个 2–64 个字符");
            if (
                rule.Extensions is null
                || rule.Extensions.Length > 50
                || rule.Extensions.Any(e => e is null || !Regex.IsMatch(e, @"^\.[A-Za-z0-9_-]{1,16}$"))
            )
                throw new ArgumentException($"敏感文件规则“{rule.Name}”的扩展名无效：格式如 .xlsx，最多 50 个");
        }
        if (policy.Rules.Select(r => r.Id).Distinct().Count() != policy.Rules.Length)
            throw new ArgumentException("敏感文件规则的标识不能重复");
        if (policy.Enabled && (policy.Rules.Length == 0 || !policy.ScanUserProfiles && !policy.ScanOtherFixedDrives))
            throw new ArgumentException("启用敏感文件扫描需要至少一条规则，并选择至少一个扫描范围");
    }

    /// <summary>"文件名包含“机密”（规则：机密文件）", listing every matched rule.</summary>
    public static string Summary(IReadOnlyList<SensitiveNameMatch> matches, bool folder) =>
        (folder ? "文件夹名包含" : "文件名包含")
        + string.Join("、", matches.Select(m => $"“{m.Keyword}”").Distinct())
        + "（规则："
        + string.Join("、", matches.Select(m => m.Rule.Name).Distinct())
        + "）";
}

/// <summary>Matches file and folder names against the enabled rules.</summary>
public sealed class SensitiveNameMatcher
{
    private readonly (SensitiveFileRule Rule, string[] Keywords, HashSet<string> Extensions)[] rules;

    public SensitiveNameMatcher(IEnumerable<SensitiveFileRule> rules) =>
        this.rules = rules
            .Select(r =>
                (
                    r,
                    r.Keywords.Select(SensitiveFiles.Normalize).ToArray(),
                    r.Extensions.Select(e => e.ToLowerInvariant()).ToHashSet(StringComparer.Ordinal)
                )
            )
            .ToArray();

    public bool IsEmpty => rules.Length == 0;

    /// <summary>Every rule the name matches, in rule order. <paramref name="skip"/> leaves out rules already reported.</summary>
    public List<SensitiveNameMatch> Match(string name, bool folder, ISet<string>? skip = null)
    {
        var result = new List<SensitiveNameMatch>();
        string? normalized = null;
        string? extension = null;
        foreach (var (rule, keywords, extensions) in rules)
        {
            if (skip is not null && skip.Contains(rule.Id))
                continue;
            if (folder)
            {
                if (!rule.MatchFolders || extensions.Count > 0)
                    continue;
            }
            else if (
                extensions.Count > 0
                && !extensions.Contains(extension ??= Path.GetExtension(name).ToLowerInvariant())
            )
                continue;
            normalized ??= SensitiveFiles.Normalize(name);
            var index = Array.FindIndex(keywords, k => normalized.Contains(k, StringComparison.Ordinal));
            if (index >= 0)
                result.Add(new(rule, rule.Keywords[index]));
        }
        return result;
    }
}
