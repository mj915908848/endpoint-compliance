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
        return new(payload,Convert.ToBase64String(key.SignData(Encoding.UTF8.GetBytes(payload),HashAlgorithmName.SHA256)),keyId);
    }
    public static PolicyDocument Verify(SignedPolicy policy, string publicKeyPem, string deviceId, long minimumVersion, DateTimeOffset now)
    {
        if (policy.Payload.Length > 4*1024*1024) throw new ArgumentException("Policy too large");
        using var key = ECDsa.Create(); key.ImportFromPem(publicKeyPem);
        try { if(!key.VerifyData(Encoding.UTF8.GetBytes(policy.Payload),Convert.FromBase64String(policy.Signature),HashAlgorithmName.SHA256)) throw new CryptographicException("Invalid policy signature"); }
        catch(FormatException) { throw new CryptographicException("Invalid policy signature encoding"); }
        var doc=Wire.Read<PolicyDocument>(policy.Payload); Validate(doc);
        if(doc.Version<minimumVersion) throw new ArgumentException("Policy downgrade rejected");
        if(doc.ExpiresAt<now || doc.IssuedAt>now.AddMinutes(2)) throw new ArgumentException("Policy expired or time invalid");
        if(doc.TargetDeviceIds.Length>0 && !doc.TargetDeviceIds.Contains(deviceId,StringComparer.Ordinal)) throw new ArgumentException("Policy target mismatch");
        return doc;
    }
    public static void Validate(PolicyDocument doc)
    {
        if(doc.SchemaVersion!=1 || doc.Version<1 || string.IsNullOrWhiteSpace(doc.PolicyId) || !doc.DenyInstalled || !doc.DenyProxy || doc.Mode is not ("Audit" or "Enforce")) throw new ArgumentException("Invalid policy");
        if(doc.RequiredModules is null || doc.RequiredModules.Length==0 || doc.Products is null || doc.BlockDomains is null || doc.RequiredControls is null || doc.ApplicationRules is null || doc.TargetDeviceIds is null) throw new ArgumentException("Incomplete policy");
        if(doc.InventoryFreshMinutes is < 1 or > 10080 || doc.LightweightFreshMinutes is < 1 or > 1440) throw new ArgumentException("Invalid freshness");
        if(doc.Products.Length>1000 || doc.Products.Any(r=>string.IsNullOrWhiteSpace(r.Id)||r.PackageIds is null||r.ExecutableNames is null||r.ExtensionIds is null||r.Domains is null||r.DisplayNames is null)||doc.Products.Select(r=>r.Id).Distinct().Count()!=doc.Products.Length) throw new ArgumentException("Invalid product identities");
        DomainRules.CompileEdge(doc.BlockDomains);
        foreach(var rule in doc.ApplicationRules)
            if(rule.Type is not ("Exe" or "Msi") || !Regex.IsMatch(rule.Sha256,"^[a-fA-F0-9]{64}$") || !doc.Products.Any(p=>p.Id==rule.ProductId)) throw new ArgumentException("Invalid application deny identity");
    }
}
public static class RequestAuthentication
{
    private static byte[] Canonical(string method,string path,string timestamp,string nonce,ReadOnlySpan<byte> body)
        => Encoding.UTF8.GetBytes(string.Join('\n',method.ToUpperInvariant(),path,timestamp,nonce,Convert.ToHexString(SHA256.HashData(body))));
    public static string Sign(ECDsa key,string method,string path,string timestamp,string nonce,ReadOnlySpan<byte> body)
        => Convert.ToBase64String(key.SignData(Canonical(method,path,timestamp,nonce,body),HashAlgorithmName.SHA256));
    public static bool Verify(string publicKeyPem,string method,string path,string timestamp,string nonce,ReadOnlySpan<byte> body,string signature)
    {
        try { using var key=ECDsa.Create(); key.ImportFromPem(publicKeyPem); return key.VerifyData(Canonical(method,path,timestamp,nonce,body),Convert.FromBase64String(signature),HashAlgorithmName.SHA256); }
        catch(Exception e) when(e is CryptographicException or FormatException or ArgumentException) { return false; }
    }
}
public static class DomainRules
{
    public static string Normalize(string domain)
    {
        if(string.IsNullOrWhiteSpace(domain) || domain.Length>253 || domain!=domain.Trim()) throw new ArgumentException("Invalid domain");
        domain=domain.TrimEnd('.');
        try { domain=new IdnMapping().GetAscii(domain).ToLowerInvariant(); } catch(ArgumentException) { throw new ArgumentException("Invalid domain"); }
        if(!domain.Contains('.') || IPAddress.TryParse(domain,out _) || domain.Split('.').Any(s=>s.Length is <1 or >63 || !Regex.IsMatch(s,"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"))) throw new ArgumentException("Hostnames only, no paths, wildcards or IP addresses");
        return domain;
    }
    public static bool Matches(string host,string domain)
    {
        try { host=Normalize(host); domain=Normalize(domain); return host==domain || host.EndsWith('.'+domain,StringComparison.Ordinal); } catch(ArgumentException) { return false; }
    }
    public static string[] CompileEdge(IEnumerable<string> domains)
    {
        var result=domains.Select(Normalize).Distinct(StringComparer.Ordinal).ToArray();
        if(result.Length>1000) throw new ArgumentException("Edge URLBlocklist limit exceeded; no truncation allowed");
        return result;
    }
}
public static class EvidenceSanitizer
{
    public static string Clean(string? value)
    {
        if(value is null) return "";
        var text=value.Length>4096?value[..4096]+" [truncated]":value;
        text=Regex.Replace(text,@"https?://[^\s<>]+",m=>Uri.TryCreate(m.Value,UriKind.Absolute,out var u)?u.Scheme+"://"+u.Host+(u.IsDefaultPort?"":":"+u.Port)+"/[redacted]":"[redacted-url]",RegexOptions.IgnoreCase,TimeSpan.FromMilliseconds(100));
        text=Regex.Replace(text,@"(?i)authorization\s*[:=]\s*[^\r\n]+","Authorization: [redacted]",RegexOptions.None,TimeSpan.FromMilliseconds(100));
        text=Regex.Replace(text,@"(?i)\b(password|passwd|token|secret|api[-_]?key)\s*[:=]\s*[^\s;,]+","$1=[redacted]",RegexOptions.None,TimeSpan.FromMilliseconds(100));
        return text;
    }
    public static ScanSnapshot Sanitize(ScanSnapshot snapshot) => snapshot with
    {
        HostName=Clean(snapshot.HostName),
        Evidence=snapshot.Evidence.Select(e=>e with {ProductName=Clean(e.ProductName),ObjectKey=Clean(e.ObjectKey),Source=Clean(e.Source),Summary=Clean(e.Summary)}).ToArray(),
        Modules=snapshot.Modules.Select(m=>m with {Error=m.Error is null?null:Clean(m.Error),Scope=Clean(m.Scope)}).ToArray(),
        Controls=snapshot.Controls.Select(c=>c with {Detail=Clean(c.Detail)}).ToArray()
    };
}
public static class ReportRenderer
{
    private static string Cell(string? value) => EvidenceSanitizer.Clean(value).Replace("\r"," ").Replace("\n"," ").Replace("|","\\|").Replace("<","&lt;").Replace(">","&gt;").Replace("`","'");
    public static string Markdown(ComplianceReport report)
    {
        var s=report.Snapshot;
        var b=new StringBuilder("# 客户终端合规检查报告\n\n");
        b.AppendLine("## 1. 基本信息\n").AppendLine($"- 设备：{Cell(s.HostName)}（{Cell(s.DeviceId)}）\n- 平台：{Cell(s.Platform)}\n- 原始采集时间：{s.CollectedAt:O}\n- 规则版本：{s.PolicyVersion}\n- 数据版本：{s.SchemaVersion}\n- 模拟：{(s.Simulated?"是，不能用于原生验收":"否")}\n");
        b.AppendLine("## 2. 检查结论\n").AppendLine($"**{Cell(report.Summary)}**\n\n- 违规对象：{report.ViolationCount}\n- 确认违规证据：{report.EvidenceCount}\n- 防护状态：{Cell(report.ProtectionStatus)}\n");
        b.AppendLine("## 3. 不通过项\n"); foreach(var reason in report.Reasons) b.AppendLine("- "+Cell(reason)); if(report.Reasons.Length==0) b.AppendLine("未发现当前确认违规；完整性以检查覆盖为准。");
        b.AppendLine("\n## 4. 软件安装与进程\n"); Table(b,s.Evidence.Where(e=>e.Kind is EvidenceKind.Installation or EvidenceKind.Process or EvidenceKind.Extension));
        b.AppendLine("\n## 5. 代理配置\n"); Table(b,s.Evidence.Where(e=>e.Kind==EvidenceKind.Proxy));
        b.AppendLine("\n## 6. 端口与执行层线索\n"); Table(b,s.Evidence.Where(e=>e.Kind is EvidenceKind.Clue or EvidenceKind.BlockedAttempt));
        foreach(var c in s.Controls) b.AppendLine($"- {Cell(c.Id)}：{Cell(c.State)}，版本 {c.Version}；已验证：{c.Verified}；需重启：{c.RebootRequired}；{Cell(c.Detail)}");
        b.AppendLine("\n## 7. 检查覆盖\n\n| 模块 | 范围 | 状态 | 原始时间 | 错误 |\n| --- | --- | --- | --- | --- |"); foreach(var m in s.Modules) b.AppendLine($"| {Cell(m.Module)} | {Cell(m.Scope)} | {Cell(m.Status)} | {m.CollectedAt:O} | {Cell(m.Error)} |");
        foreach(var gap in report.CoverageGaps) b.AppendLine("- 缺口："+Cell(gap));
        b.AppendLine("\n## 8. 处理建议\n\n- 按客户制度处理已确认软件/代理，修复采集缺口后重新检查。\n- 管理员确认告警不代表技术恢复；恢复必须有新的完整采集。\n- 强制策略先审计、试点并验证阻断和回滚。\n");
        b.AppendLine("## 9. 范围与限制\n\n- 此结论只适用于声明的设备、用户、采集范围与原始采集时间；清单不是穷尽清单。\n- 端口/接口和弱名称仅为线索；阻断尝试不证明成功使用。\n- 浏览器策略不证明任意程序 API 已阻断；通用网络过滤需要独立执行层验证。\n- 无 Windows 实机、安装包签名和客户网关验收证据时不能认定生产防护验收通过。\n- 不读取聊天内容、密码或浏览历史，不自动卸载。\n");
        return b.ToString();
    }
    private static void Table(StringBuilder b,IEnumerable<Evidence> records)
    {
        b.AppendLine("| 产品 | 类型 | 用户 | 依据 | 确认 |\n| --- | --- | --- | --- | --- |");
        foreach(var e in records) b.AppendLine($"| {Cell(e.ProductName)} | {e.Kind} | {Cell(e.UserSid??"machine")} | {Cell(e.Source)}: {Cell(e.Summary)} | {e.Confirmed} |");
    }
}
