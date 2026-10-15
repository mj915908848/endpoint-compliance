using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Compliance.Core;

public static class PolicyCrypto
{
    public static SignedPolicy Sign(PolicyDocument document, ECDsa key, string keyId)
    {
        Validate(document);
        var payload = Wire.Serialize(document);
        return new(
            payload,
            Convert.ToBase64String(key.SignData(Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256)),
            keyId
        );
    }

    public static PolicyDocument Verify(
        SignedPolicy policy,
        string publicKeyPem,
        string deviceId,
        long minimumVersion,
        DateTimeOffset now
    )
    {
        if (policy.Payload.Length > 4 * 1024 * 1024)
            throw new ArgumentException("Policy too large");
        using var key = ECDsa.Create();
        key.ImportFromPem(publicKeyPem);
        try
        {
            if (
                !key.VerifyData(
                    Encoding.UTF8.GetBytes(policy.Payload),
                    Convert.FromBase64String(policy.Signature),
                    HashAlgorithmName.SHA256
                )
            )
                throw new CryptographicException("Invalid policy signature");
        }
        catch (FormatException)
        {
            throw new CryptographicException("Invalid policy signature encoding");
        }
        var doc = Wire.Read<PolicyDocument>(policy.Payload);
        Validate(doc);
        if (doc.Version < minimumVersion)
            throw new ArgumentException("Policy downgrade rejected");
        if (doc.ExpiresAt < now || doc.IssuedAt > now.AddMinutes(2))
            throw new ArgumentException("Policy expired or time invalid");
        if (doc.TargetDeviceIds.Length > 0 && !doc.TargetDeviceIds.Contains(deviceId, StringComparer.Ordinal))
            throw new ArgumentException("Policy target mismatch");
        return doc;
    }

    public static void Validate(PolicyDocument doc)
    {
        if (
            doc.SchemaVersion != 1
            || doc.Version < 1
            || string.IsNullOrWhiteSpace(doc.PolicyId)
            || doc.PolicyId.Length > 64
            || !doc.DenyInstalled
            || !doc.DenyProxy
            || doc.Mode is not ("Audit" or "Enforce")
        )
            throw new ArgumentException("策略基本信息无效：策略名称不能为空，模式只能是审计或强制");
        if (
            doc.RequiredModules is null
            || doc.RequiredModules.Length == 0
            || doc.Products is null
            || doc.BlockDomains is null
            || doc.RequiredControls is null
            || doc.ApplicationRules is null
            || doc.TargetDeviceIds is null
        )
            throw new ArgumentException("策略不完整：至少需要一个必需检查项");
        if (doc.InventoryFreshMinutes is < 1 or > 10080 || doc.LightweightFreshMinutes is < 1 or > 1440)
            throw new ArgumentException("检查时效超出范围：完整检查 1–10080 分钟，快速检查 1–1440 分钟");
        if (doc.QuickCheckMinutes is < 1 or > 60 || doc.FullCheckMinutes is < 10 or > 1440)
            throw new ArgumentException("检查频率超出范围：快速检查每 1–60 分钟，完整检查每 10–1440 分钟");
        if (doc.FullCheckMinutes < doc.QuickCheckMinutes)
            throw new ArgumentException("完整检查的间隔不能短于快速检查");
        if (
            doc.Products.Length > 1000
            || doc.Products.Any(r =>
                string.IsNullOrWhiteSpace(r.Id)
                || r.PackageIds is null
                || r.ExecutableNames is null
                || r.ExtensionIds is null
                || r.Domains is null
                || r.DisplayNames is null
                || r.AdapterNames is null
                || r.NpmPackages is null
                || r.PipPackages is null
                || r.AdapterNames.Any(n => string.IsNullOrWhiteSpace(n) || n.Length > 64)
            )
            || doc.Products.Select(r => r.Id).Distinct().Count() != doc.Products.Length
        )
            throw new ArgumentException("产品规则无效：每个产品需要不重复的标识，网卡名称不能为空且不超过 64 个字符");
        if (
            doc.ApprovedNetworkAdapters is null
            || doc.ApprovedNetworkAdapters.Length > 100
            || doc.ApprovedNetworkAdapters.Any(n => string.IsNullOrWhiteSpace(n) || n.Length < 3 || n.Length > 64)
        )
            throw new ArgumentException("已批准网卡无效：最多 100 项，每项 3–64 个字符");
        SensitiveFiles.Validate(doc.SensitiveFiles);
        DomainRules.CompileEdge(doc.BlockDomains);
        foreach (var rule in doc.ApplicationRules)
            if (
                rule.Type is not ("Exe" or "Msi")
                || !Regex.IsMatch(rule.Sha256, "^[a-fA-F0-9]{64}$")
                || !doc.Products.Any(p => p.Id == rule.ProductId)
            )
                throw new ArgumentException("应用程序拦截规则无效：需要 64 位 SHA-256，并对应已有产品");
    }
}

public static class RequestAuthentication
{
    private static byte[] Canonical(
        string method,
        string path,
        string timestamp,
        string nonce,
        ReadOnlySpan<byte> body
    ) =>
        Encoding.UTF8.GetBytes(
            string.Join(
                '\n',
                method.ToUpperInvariant(),
                path,
                timestamp,
                nonce,
                Convert.ToHexString(SHA256.HashData(body))
            )
        );

    public static string Sign(
        ECDsa key,
        string method,
        string path,
        string timestamp,
        string nonce,
        ReadOnlySpan<byte> body
    ) =>
        Convert.ToBase64String(key.SignData(Canonical(method, path, timestamp, nonce, body), HashAlgorithmName.SHA256));

    public static bool Verify(
        string publicKeyPem,
        string method,
        string path,
        string timestamp,
        string nonce,
        ReadOnlySpan<byte> body,
        string signature
    )
    {
        try
        {
            using var key = ECDsa.Create();
            key.ImportFromPem(publicKeyPem);
            return key.VerifyData(
                Canonical(method, path, timestamp, nonce, body),
                Convert.FromBase64String(signature),
                HashAlgorithmName.SHA256
            );
        }
        catch (Exception e) when (e is CryptographicException or FormatException or ArgumentException)
        {
            return false;
        }
    }
}

public static class DomainRules
{
    public static string Normalize(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain) || domain.Length > 253 || domain != domain.Trim())
            throw new ArgumentException($"域名无效：{domain}");
        domain = domain.TrimEnd('.');
        try
        {
            domain = new IdnMapping().GetAscii(domain).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            throw new ArgumentException($"域名无效：{domain}");
        }
        if (
            !domain.Contains('.')
            || IPAddress.TryParse(domain, out _)
            || domain
                .Split('.')
                .Any(s => s.Length is < 1 or > 63 || !Regex.IsMatch(s, "^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"))
        )
            throw new ArgumentException($"只能填写域名，不能包含路径、通配符或 IP 地址：{domain}");
        return domain;
    }

    public static bool Matches(string host, string domain)
    {
        try
        {
            host = Normalize(host);
            domain = Normalize(domain);
            return host == domain || host.EndsWith('.' + domain, StringComparison.Ordinal);
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    public static string[] CompileEdge(IEnumerable<string> domains)
    {
        var result = domains.Select(Normalize).Distinct(StringComparer.Ordinal).ToArray();
        if (result.Length > 1000)
            throw new ArgumentException("Edge URLBlocklist limit exceeded; no truncation allowed");
        return result;
    }
}

public static class EvidenceSanitizer
{
    public static string Clean(string? value)
    {
        if (value is null)
            return "";
        var text = value.Length > 4096 ? value[..4096] + " [truncated]" : value;
        text = Regex.Replace(
            text,
            @"https?://[^\s<>]+",
            m =>
                Uri.TryCreate(m.Value, UriKind.Absolute, out var u)
                    ? u.Scheme + "://" + u.Host + (u.IsDefaultPort ? "" : ":" + u.Port) + "/[redacted]"
                    : "[redacted-url]",
            RegexOptions.IgnoreCase,
            TimeSpan.FromMilliseconds(100)
        );
        text = Regex.Replace(
            text,
            @"(?i)authorization\s*[:=]\s*[^\r\n]+",
            "Authorization: [redacted]",
            RegexOptions.None,
            TimeSpan.FromMilliseconds(100)
        );
        text = Regex.Replace(
            text,
            @"(?i)\b(password|passwd|token|secret|api[-_]?key)\s*[:=]\s*[^\s;,]+",
            "$1=[redacted]",
            RegexOptions.None,
            TimeSpan.FromMilliseconds(100)
        );
        return text;
    }

    public static ScanSnapshot Sanitize(ScanSnapshot snapshot) =>
        snapshot with
        {
            HostName = Clean(snapshot.HostName),
            Evidence = snapshot
                .Evidence.Select(e =>
                    e with
                    {
                        ProductName = Clean(e.ProductName),
                        ObjectKey = Clean(e.ObjectKey),
                        Source = Clean(e.Source),
                        Summary = Clean(e.Summary),
                    }
                )
                .ToArray(),
            Modules = snapshot
                .Modules.Select(m => m with { Error = m.Error is null ? null : Clean(m.Error), Scope = Clean(m.Scope) })
                .ToArray(),
            Controls = snapshot.Controls.Select(c => c with { Detail = Clean(c.Detail) }).ToArray(),
            Users = (snapshot.Users ?? [])
                .Where(u => !string.IsNullOrWhiteSpace(u.Sid) && !string.IsNullOrWhiteSpace(u.Name))
                .Select(u => new UserAccount(Clean(u.Sid), Clean(u.Name)))
                .DistinctBy(u => u.Sid)
                .Take(200)
                .ToArray(),
        };
}

public static class ReportRenderer
{
    private static string Cell(string? value) =>
        EvidenceSanitizer
            .Clean(value)
            .Replace("\r", " ")
            .Replace("\n", " ")
            .Replace("|", "\\|")
            .Replace("<", "&lt;")
            .Replace(">", "&gt;")
            .Replace("`", "'");

    // Shown in the management server's time zone, with the offset so the moment stays unambiguous.
    private static string Time(DateTimeOffset t)
    {
        var local = t.ToLocalTime();
        return $"{local:yyyy-MM-dd HH:mm:ss}（UTC{local:zzz}）";
    }

    // The advice/limit texts mirror ui/src/components/report.tsx.
    public static string Markdown(ComplianceReport report)
    {
        var s = report.Snapshot;
        var names = Labels.AccountNames(s);
        var b = new StringBuilder("# 终端合规检查报告\n\n");
        b.AppendLine("## 1. 基本信息\n")
            .AppendLine($"- 终端：{Cell(s.HostName)}")
            .AppendLine($"- 设备 ID：{Cell(s.DeviceId)}")
            .AppendLine($"- 平台：{Cell(s.Platform)}")
            .AppendLine($"- 采集时间：{Time(s.CollectedAt)}")
            .AppendLine($"- 策略版本：v{s.PolicyVersion}")
            .AppendLine($"- 数据格式版本：{s.SchemaVersion}")
            .AppendLine($"- 数据来源：{(s.Simulated ? "模拟数据，不能作为实机验收依据" : "终端实机采集")}");
        if (s.Users.Length > 0)
            b.AppendLine("- 用户账户：" + string.Join("；", s.Users.Select(u => $"{Cell(u.Name)}（{Cell(u.Sid)}）")));
        b.AppendLine();
        b.AppendLine("## 2. 检查结论\n")
            .AppendLine($"**{Cell(report.Summary)}**\n")
            .AppendLine($"- 违规对象：{report.ViolationCount}")
            .AppendLine($"- 确认证据：{report.EvidenceCount}")
            .AppendLine($"- 防护状态：{Cell(report.ProtectionStatus)}\n")
            .AppendLine("同一产品在同一用户下的安装、进程和扩展记录合并计为一个违规对象。\n");
        b.AppendLine("## 3. 不通过项\n");
        foreach (var reason in report.Reasons)
            b.AppendLine("- " + Cell(reason));
        if (report.Reasons.Length == 0)
            b.AppendLine("未发现确认违规。结论的完整性以“检查覆盖”一节为准。");
        b.AppendLine("\n## 4. 软件与敏感文件\n");
        Table(
            b,
            s.Evidence.Where(e =>
                e.Kind is EvidenceKind.Installation or EvidenceKind.Process or EvidenceKind.Extension
            ),
            "未发现相关软件的安装或运行记录。",
            names
        );
        SensitiveTable(b, report, names);
        b.AppendLine("\n## 5. 代理设置\n");
        Table(b, s.Evidence.Where(e => e.Kind == EvidenceKind.Proxy), "未发现代理设置。", names);
        b.AppendLine("\n## 6. 网络线索与防护措施\n");
        Table(
            b,
            s.Evidence.Where(e => e.Kind is EvidenceKind.Clue or EvidenceKind.BlockedAttempt),
            "没有网络线索或拦截记录。",
            names
        );
        if (s.Controls.Length == 0)
            b.AppendLine("\n终端未上报防护措施，因此不能认定拦截已经生效。");
        else
        {
            b.AppendLine(
                "\n| 防护措施 | 状态 | 已验证 | 需重启 | 策略版本 | 说明 |\n| --- | --- | --- | --- | --- | --- |"
            );
            foreach (var c in s.Controls)
                b.AppendLine(
                    $"| {Cell(Labels.Control(c.Id))} | {Cell(Labels.ControlState(c.State))} | {Labels.YesNo(c.Verified)} | {Labels.YesNo(c.RebootRequired)} | v{c.Version} | {Cell(c.Detail)} |"
                );
        }
        b.AppendLine("\n## 7. 检查覆盖\n");
        if (report.CoverageGaps.Length > 0)
        {
            b.AppendLine("检查缺口：\n");
            foreach (var gap in report.CoverageGaps)
                b.AppendLine("- " + Cell(gap));
            b.AppendLine();
        }
        b.AppendLine("| 检查项 | 范围 | 状态 | 采集时间 | 说明 |\n| --- | --- | --- | --- | --- |");
        foreach (var m in s.Modules)
            b.AppendLine(
                $"| {Cell(Labels.Module(m.Module))} | {Cell(Labels.Scope(m.Scope, names))} | {Labels.Status(m.Status)} | {Time(m.CollectedAt)} | {Cell(m.Error ?? "—")} |"
            );
        b.AppendLine(
            "\n## 8. 处理建议\n\n"
                + "- 按本单位制度处理已确认的软件和代理配置，补齐检查缺口后重新检查。\n"
                + "- 在管理端确认告警只表示已知悉，不代表问题已解决；问题是否解决以终端新的完整检查为准。\n"
                + "- 启用强制策略前，先在审计模式下试运行，并验证拦截效果和回退方案。\n"
        );
        b.AppendLine(
            "## 9. 适用范围与限制\n\n"
                + "- 结论仅适用于报告所列终端、用户、检查项和采集时间；检查清单并非穷尽。\n"
                + "- 端口、网络接口和名称相似的程序只作为线索，不能单独认定违规；拦截记录也不代表曾经成功使用。\n"
                + "- 浏览器策略只覆盖浏览器访问，不能证明其他程序的网络访问已被阻断。\n"
                + "- 在完成 Windows 实机、安装包签名和网关验收前，不能据此认定生产环境防护已经生效。\n"
                + "- 检查不读取聊天内容、密码或浏览记录，也不会自动卸载软件。\n"
                + "- 敏感文件扫描只比对文件和文件夹名称，不读取、不上传文件内容。\n"
        );
        return b.ToString();
    }

    private static void SensitiveTable(
        StringBuilder b,
        ComplianceReport report,
        IReadOnlyDictionary<string, string> names
    )
    {
        var s = report.Snapshot;
        var rows = s.Evidence.Where(e => e.Kind == EvidenceKind.SensitiveFile).ToArray();
        if (
            rows.Length == 0
            && report.SensitiveFileNotes.Length == 0
            && !s.Modules.Any(m => m.Module == SensitiveFiles.Module)
        )
            return;
        b.AppendLine("\n### 敏感文件\n");
        foreach (var note in report.SensitiveFileNotes)
            b.AppendLine("- " + Cell(note));
        if (report.SensitiveFileNotes.Length > 0)
            b.AppendLine();
        if (rows.Length == 0)
        {
            var complete =
                s.Modules.Where(m => m.Module == SensitiveFiles.Module).ToArray() is { Length: > 0 } scopes
                && scopes.All(m => m.Status == "Complete");
            b.AppendLine(
                complete
                    ? "未发现文件名包含关键词的文件或文件夹。"
                    : "暂无命中记录；扫描尚未完整完成，不能据此认定没有敏感文件。"
            );
            return;
        }
        b.AppendLine("| 路径 | 说明 | 所有者 | 扫描范围 |\n| --- | --- | --- | --- |");
        foreach (var e in rows)
            b.AppendLine(
                $"| {Cell(e.ObjectKey)} | {Cell(e.Summary)} | {Cell(e.UserSid is null ? "未知" : Labels.Scope(e.UserSid, names))} | {Cell(Labels.Scope(e.Source, names))} |"
            );
    }

    private static void Table(
        StringBuilder b,
        IEnumerable<Evidence> records,
        string empty,
        IReadOnlyDictionary<string, string> names
    )
    {
        var rows = records.ToArray();
        if (rows.Length == 0)
        {
            b.AppendLine(empty);
            return;
        }
        b.AppendLine("| 产品 | 类型 | 范围 | 说明 | 来源 |\n| --- | --- | --- | --- | --- |");
        foreach (var e in rows)
            b.AppendLine(
                $"| {Cell(e.ProductName)} | {(e.Confirmed ? "确认" : "线索")} · {Labels.Evidence(e.Kind)} | {Cell(Labels.Scope(e.UserSid, names))} | {Cell(e.Summary)} | {Cell(e.Source)} |"
            );
    }
}
