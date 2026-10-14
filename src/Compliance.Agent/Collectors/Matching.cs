using System.Text;
using System.Text.Json;
using Compliance.Core;

namespace Compliance.Agent;

// Pure matching and parsing helpers; kept free of registry and process access so they are unit-testable.
public sealed partial class WindowsCollector
{
    public static (Evidence[] Evidence, int Errors) ScanVsCodeExtensions(string root, string sid, PolicyDocument policy)
    {
        if (!DirectoryPresent(root))
            return ([], 0);
        var found = new List<Evidence>();
        var errors = 0;
        var host = Path.GetFileName(Path.GetDirectoryName(root));
        var obsolete = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var obsoleteFile = Path.Combine(root, ".obsolete");
        if (FilePresent(obsoleteFile))
        {
            try
            {
                using var state = JsonDocument.Parse(File.ReadAllText(obsoleteFile));
                if (state.RootElement.ValueKind != JsonValueKind.Object)
                    throw new JsonException("Invalid extension removal state");
                foreach (var item in state.RootElement.EnumerateObject())
                {
                    if (item.Value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                        throw new JsonException("Invalid extension removal entry");
                    if (item.Value.GetBoolean())
                        obsolete.Add(item.Name);
                }
            }
            catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
            {
                return ([], 1);
            }
        }
        foreach (var dir in Directory.EnumerateDirectories(root))
        {
            if (
                dir.EndsWith(".obsolete", StringComparison.OrdinalIgnoreCase)
                || obsolete.Contains(Path.GetFileName(dir))
            )
                continue;
            var manifest = Path.Combine(dir, "package.json");
            try
            {
                if ((File.GetAttributes(dir) & FileAttributes.ReparsePoint) != 0 || !FilePresent(manifest))
                    continue;
                using var doc = JsonDocument.Parse(File.ReadAllText(manifest));
                var publisher = doc.RootElement.TryGetProperty("publisher", out var publisherProperty)
                    ? publisherProperty.GetString()
                    : null;
                var name = doc.RootElement.TryGetProperty("name", out var nameProperty)
                    ? nameProperty.GetString()
                    : null;
                if (publisher is null || name is null)
                    continue;
                var id = publisher + "." + name;
                foreach (
                    var rule in policy.Products.Where(r =>
                        r.ExtensionIds.Any(x => string.Equals(x, id, StringComparison.OrdinalIgnoreCase))
                    )
                )
                    found.Add(
                        new(
                            rule.Id,
                            rule.Name,
                            EvidenceKind.Extension,
                            "ide:" + sid + ":" + host + ":" + id,
                            "编辑器扩展清单",
                            "扩展 ID：" + id + "（" + host + "）",
                            sid
                        )
                    );
            }
            catch (JsonException)
            {
                errors++;
            }
            catch (InvalidOperationException)
            {
                errors++;
            }
            catch (IOException)
            {
                errors++;
            }
            catch (UnauthorizedAccessException)
            {
                errors++;
            }
        }
        return (found.ToArray(), errors);
    }

    public static (Evidence[] Evidence, int Errors) ScanKnownExtensionRoots(
        string profilePath,
        string sid,
        PolicyDocument policy
    )
    {
        var found = new List<Evidence>();
        var errors = 0;
        foreach (
            var host in new[] { ".vscode", ".vscode-insiders", ".vscode-oss", ".cursor", ".windsurf", ".windsurf-next" }
        )
        {
            var result = ScanVsCodeExtensions(Path.Combine(profilePath, host, "extensions"), sid, policy);
            found.AddRange(result.Evidence);
            errors += result.Errors;
        }
        return (found.ToArray(), errors);
    }

    public static Evidence? MatchServiceRegistration(string serviceName, string? displayName, PolicyDocument policy)
    {
        var productId = serviceName.ToLowerInvariant() switch
        {
            "clash_verge_service" => "clash",
            "codexsandboxservice.openai.codex" => "codex",
            _ => null,
        };
        if (productId is null)
            return null;
        var rule = policy.Products.FirstOrDefault(r => r.Id == productId);
        return rule is null
            ? null
            : new Evidence(
                rule.Id,
                rule.Name,
                EvidenceKind.Installation,
                "service:" + serviceName,
                "系统服务注册表",
                "已注册服务：" + serviceName
            );
    }

    public static Evidence[] ScanKnownInstallRoot(string root, string? sid, PolicyDocument policy)
    {
        if (!DirectoryPresent(root))
            return [];
        var found = new List<Evidence>();
        foreach (var dir in Directory.EnumerateDirectories(root))
        {
            if ((File.GetAttributes(dir) & FileAttributes.ReparsePoint) != 0)
                continue;
            var folder = Path.GetFileName(dir);
            var matching = policy
                .Products.Where(r =>
                    r.DisplayNames.Any(n => string.Equals(n, folder, StringComparison.OrdinalIgnoreCase))
                )
                .ToArray();
            if (matching.Length == 0)
                continue;
            var executables = Directory
                .EnumerateFiles(dir)
                .Select(Path.GetFileName)
                .Where(n => n is not null)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var rule in matching)
            {
                var executable = rule.ExecutableNames.FirstOrDefault(executables.Contains);
                if (executable is not null)
                    found.Add(
                        new(
                            rule.Id,
                            rule.Name,
                            EvidenceKind.Installation,
                            "install-dir:" + (sid ?? "machine") + ":" + folder,
                            "常见安装目录",
                            "目录 " + folder + " 中存在 " + executable,
                            sid
                        )
                    );
            }
        }
        return found.ToArray();
    }

    public static Evidence[] ScanKnownCliBin(string root, string sid, PolicyDocument policy)
    {
        var found = new List<Evidence>();
        foreach (var (file, id) in new[] { ("claude.exe", "claude"), ("codex.exe", "codex"), ("gemini.exe", "gemini") })
        {
            if (!FilePresent(Path.Combine(root, file)))
                continue;
            var rule = policy.Products.FirstOrDefault(r => r.Id == id);
            if (rule is not null)
                found.Add(
                    new(
                        rule.Id,
                        rule.Name,
                        EvidenceKind.Installation,
                        "cli-file:" + sid + ":" + file,
                        "用户命令行目录",
                        "命令行程序：" + file,
                        sid
                    )
                    {
                        CollectedAt = DateTimeOffset.UtcNow,
                    }
                );
        }
        return found.ToArray();
    }

    public static Evidence? ProxyEnvironmentEvidence(string name, string? value, string? sid)
    {
        if (
            name.ToUpperInvariant() is not ("HTTP_PROXY" or "HTTPS_PROXY" or "ALL_PROXY")
            || string.IsNullOrWhiteSpace(value)
        )
            return null;
        var scope = sid ?? "machine";
        return new(
            "proxy",
            "代理环境变量",
            EvidenceKind.Proxy,
            "env:" + scope + ":" + name.ToUpperInvariant(),
            "持久环境变量",
            "已设置 " + name.ToUpperInvariant() + "（不记录具体值）",
            sid
        );
    }

    public static Evidence? ProcessProxyEnvironmentClue(string name, string? value)
    {
        if (
            name.ToUpperInvariant() is not ("HTTP_PROXY" or "HTTPS_PROXY" or "ALL_PROXY")
            || string.IsNullOrWhiteSpace(value)
        )
            return null;
        return new(
            "proxy-process-clue",
            "检查程序的代理环境变量",
            EvidenceKind.Clue,
            "env:process:" + name.ToUpperInvariant(),
            "检查程序进程环境",
            "检查程序进程中存在 " + name.ToUpperInvariant() + "，无法确认是否为整机设置（不记录具体值）",
            null,
            false
        );
    }

    internal static bool DirectoryPresent(string path)
    {
        try
        {
            return (File.GetAttributes(path) & FileAttributes.Directory) != 0;
        }
        catch (FileNotFoundException)
        {
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            return false;
        }
    }

    internal static bool FilePresent(string path)
    {
        try
        {
            return (File.GetAttributes(path) & FileAttributes.Directory) == 0;
        }
        catch (FileNotFoundException)
        {
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            return false;
        }
    }

    /// <summary>
    /// Matches per-user Store packages. <paramref name="packageFullNames"/> come from
    /// HKLM\...\Appx\AppxAllUserStore\&lt;SID&gt;; a full name is "Name_Version_Arch_Resource_Publisher".
    /// </summary>
    public static Evidence[] ParseAppxPackages(
        IEnumerable<string> packageFullNames,
        string userSid,
        PolicyDocument policy
    )
    {
        if (string.IsNullOrWhiteSpace(userSid))
            throw new ArgumentException("Store package must have an owning user SID");
        var found = new List<Evidence>();
        foreach (var full in packageFullNames)
        {
            var name = full.Split('_', 2)[0];
            if (name.Length == 0)
                continue;
            foreach (
                var rule in policy.Products.Where(r =>
                    r.PackageIds.Any(id => string.Equals(id, name, StringComparison.OrdinalIgnoreCase))
                )
            )
                found.Add(
                    new(
                        rule.Id,
                        rule.Name,
                        EvidenceKind.Installation,
                        "appx:" + userSid + ":" + name,
                        "应用商店应用（按用户）",
                        $"应用包 {name}（{full}）",
                        userSid
                    )
                );
        }
        return found.ToArray();
    }

    /// <summary>
    /// Reads a WinINet DefaultConnectionSettings blob: version, counter, INTERNET_PER_CONN_FLAGS, then
    /// length-prefixed proxy server, bypass list and auto-config URL. Only presence is reported, never addresses.
    /// </summary>
    public static (bool Proxy, bool Pac, bool AutoDetect) ParseConnectionSettings(byte[] blob)
    {
        const int ProxyFlag = 0x2,
            AutoConfigFlag = 0x4,
            AutoDetectFlag = 0x8;
        if (blob.Length < 12)
            throw new InvalidDataException("Connection settings too short");
        var flags = BitConverter.ToInt32(blob, 8);
        var offset = 12;
        string Next()
        {
            if (offset + 4 > blob.Length)
                return "";
            var length = BitConverter.ToInt32(blob, offset);
            offset += 4;
            if (length < 0 || offset + length > blob.Length)
                throw new InvalidDataException("Connection settings field out of range");
            var value = Encoding.ASCII.GetString(blob, offset, length);
            offset += length;
            return value;
        }
        var proxy = Next();
        _ = Next(); // bypass list
        var pac = Next();
        return (
            (flags & ProxyFlag) != 0 && proxy.Length > 0,
            (flags & AutoConfigFlag) != 0 && pac.Length > 0,
            (flags & AutoDetectFlag) != 0
        );
    }
}
