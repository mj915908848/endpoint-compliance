using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Compliance.Core;

namespace Compliance.Agent;

// Pure matching and parsing helpers; kept free of registry and process access so they are unit-testable.
public sealed partial class WindowsCollector
{
    // VS Code reads extension manifests leniently; strict parsing would turn harmless comments or trailing
    // commas into coverage gaps.
    private static readonly JsonDocumentOptions ManifestOptions = new()
    {
        CommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    public static (Evidence[] Evidence, int Errors, string[] Failed) ScanVsCodeExtensions(
        string root,
        string sid,
        PolicyDocument policy
    )
    {
        if (!DirectoryPresent(root))
            return ([], 0, []);
        var found = new List<Evidence>();
        var failed = new List<string>();
        var host = Path.GetFileName(Path.GetDirectoryName(root));
        var obsolete = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var obsoleteFile = Path.Combine(root, ".obsolete");
        if (FilePresent(obsoleteFile))
        {
            try
            {
                using var state = JsonDocument.Parse(File.ReadAllText(obsoleteFile), ManifestOptions);
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
                return ([], 1, [".obsolete"]);
            }
        }
        var read = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var broken = new List<(string Folder, string Reason)>();
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
                using var doc = JsonDocument.Parse(File.ReadAllText(manifest), ManifestOptions);
                var publisher = doc.RootElement.TryGetProperty("publisher", out var publisherProperty)
                    ? publisherProperty.GetString()
                    : null;
                var name = doc.RootElement.TryGetProperty("name", out var nameProperty)
                    ? nameProperty.GetString()
                    : null;
                if (publisher is null || name is null)
                    continue;
                var id = publisher + "." + name;
                read.Add(id);
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
            catch (Exception ex)
                when (ex is JsonException or InvalidOperationException or IOException or UnauthorizedAccessException)
            {
                broken.Add((Path.GetFileName(dir), ManifestFailure(ex, manifest)));
            }
        }
        // VS Code leaves the folders of replaced versions behind until it cleans up. A broken leftover of an
        // extension whose current version was read is not a coverage gap.
        foreach (var (folder, reason) in broken)
            if (!read.Contains(ExtensionIdFromFolder(folder)))
                failed.Add($"{folder}（{reason}）");
        return (found.ToArray(), failed.Count, failed.ToArray());
    }

    /// <summary>"ms-vscode-remote.remote-ssh-0.115.1" -> "ms-vscode-remote.remote-ssh".</summary>
    public static string ExtensionIdFromFolder(string folder) =>
        Regex.Replace(folder, @"-\d+\.\d+\.\d+([-.+][0-9A-Za-z.-]*)?$", "");

    private static string ManifestFailure(Exception ex, string manifest)
    {
        try
        {
            if (ex is JsonException && new FileInfo(manifest).Length == 0)
                return "文件为空";
        }
        catch (IOException) { }
        return ex switch
        {
            JsonException => "JSON 格式错误",
            UnauthorizedAccessException => "没有读取权限",
            IOException => "文件被占用或无法读取",
            _ => "字段格式不符",
        };
    }

    public static (Evidence[] Evidence, int Errors, string[] Failed) ScanKnownExtensionRoots(
        string profilePath,
        string sid,
        PolicyDocument policy
    )
    {
        var found = new List<Evidence>();
        var failed = new List<string>();
        foreach (
            var host in new[] { ".vscode", ".vscode-insiders", ".vscode-oss", ".cursor", ".windsurf", ".windsurf-next" }
        )
        {
            var result = ScanVsCodeExtensions(Path.Combine(profilePath, host, "extensions"), sid, policy);
            found.AddRange(result.Evidence);
            failed.AddRange(result.Failed.Select(f => host + "/" + f));
        }
        return (found.ToArray(), failed.Count, failed.ToArray());
    }

    /// <summary>Chromium browsers' "User Data" folders under AppData\Local, with the name shown in findings.</summary>
    public static readonly (string Path, string Browser)[] ChromiumUserData =
    [
        (@"Google\Chrome\User Data", "Chrome"),
        (@"Google\Chrome Beta\User Data", "Chrome Beta"),
        (@"Microsoft\Edge\User Data", "Edge"),
        (@"BraveSoftware\Brave-Browser\User Data", "Brave"),
        (@"Vivaldi\User Data", "Vivaldi"),
        (@"Chromium\User Data", "Chromium"),
        (@"360Chrome\Chrome\User Data", "360 极速浏览器"),
        (@"360ChromeX\Chrome\User Data", "360 极速浏览器 X"),
        (@"Tencent\QQBrowser\User Data", "QQ 浏览器"),
    ];

    private const string BrowserSource = "浏览器扩展清单";

    /// <summary>
    /// Extensions of every profile in a Chromium "User Data" folder (or a single profile folder, as Opera keeps):
    /// Extensions\&lt;id&gt;\&lt;version&gt;\manifest.json. A rule matches the id or the extension's name; an
    /// extension no rule names that may set the browser's proxy is a clue.
    /// </summary>
    public static (Evidence[] Evidence, string[] Failed) ScanChromiumExtensions(
        string userData,
        string browser,
        string sid,
        PolicyDocument policy
    )
    {
        if (!DirectoryPresent(userData))
            return ([], []);
        var found = new List<Evidence>();
        var failed = new List<string>();
        var profiles = DirectoryPresent(Path.Combine(userData, "Extensions"))
            ? [userData]
            : Directory.EnumerateDirectories(userData).Where(d => DirectoryPresent(Path.Combine(d, "Extensions")));
        foreach (var profile in profiles)
        foreach (var extension in Directory.EnumerateDirectories(Path.Combine(profile, "Extensions")))
        {
            var id = Path.GetFileName(extension);
            if (!Regex.IsMatch(id, "^[a-p]{32}$"))
                continue;
            foreach (var version in Directory.EnumerateDirectories(extension))
            {
                var manifest = Path.Combine(version, "manifest.json");
                if (!FilePresent(manifest))
                    continue;
                try
                {
                    var (name, permissions) = ReadChromiumManifest(version);
                    found.AddRange(BrowserExtensionEvidence(browser, sid, id, name, permissions, policy));
                }
                catch (Exception ex)
                    when (ex is JsonException or InvalidOperationException or IOException or UnauthorizedAccessException
                    )
                {
                    failed.Add($"{browser}/{id}（{ManifestFailure(ex, manifest)}）");
                }
            }
        }
        return (found.DistinctBy(e => e.ProductId + "\n" + e.ObjectKey).ToArray(), failed.ToArray());
    }

    /// <summary>An extension's name, with "__MSG_x__" looked up in its _locales, and the permissions it asks for.</summary>
    public static (string Name, string[] Permissions) ReadChromiumManifest(string folder)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(folder, "manifest.json")), ManifestOptions);
        var root = doc.RootElement;
        var name = root.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString()! : "";
        var match = Regex.Match(name, "^__MSG_(.+)__$");
        if (match.Success)
        {
            var locale =
                root.TryGetProperty("default_locale", out var l) && l.ValueKind == JsonValueKind.String
                    ? l.GetString()!
                    : "en";
            name = LocalizedMessage(folder, [locale, "en", "en_US", "zh_CN"], match.Groups[1].Value) ?? name;
        }
        var permissions = new List<string>();
        foreach (var key in new[] { "permissions", "optional_permissions" })
            if (root.TryGetProperty(key, out var list) && list.ValueKind == JsonValueKind.Array)
                permissions.AddRange(
                    list.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!)
                );
        return (name, permissions.ToArray());
    }

    private static string? LocalizedMessage(string folder, string[] locales, string key)
    {
        foreach (var locale in locales.Distinct())
        {
            var file = Path.Combine(folder, "_locales", locale, "messages.json");
            if (!FilePresent(file))
                continue;
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(file), ManifestOptions);
                foreach (var entry in doc.RootElement.EnumerateObject())
                    if (
                        string.Equals(entry.Name, key, StringComparison.OrdinalIgnoreCase)
                        && entry.Value.ValueKind == JsonValueKind.Object
                        && entry.Value.TryGetProperty("message", out var message)
                        && message.ValueKind == JsonValueKind.String
                    )
                        return message.GetString();
            }
            // A broken translation leaves the placeholder name; the id still identifies the extension.
            catch (Exception ex) when (ex is JsonException or InvalidOperationException or IOException) { }
        }
        return null;
    }

    /// <summary>
    /// Firefox extensions of one profile from its extensions.json. Add-ons that ship with Firefox ("app-builtin" and
    /// "app-system-*" locations) are skipped.
    /// </summary>
    public static Evidence[] ScanFirefoxExtensions(string extensionsJson, string sid, PolicyDocument policy)
    {
        if (!FilePresent(extensionsJson))
            return [];
        using var doc = JsonDocument.Parse(File.ReadAllText(extensionsJson), ManifestOptions);
        if (!doc.RootElement.TryGetProperty("addons", out var addons) || addons.ValueKind != JsonValueKind.Array)
            throw new JsonException("extensions.json has no add-on list");
        var found = new List<Evidence>();
        foreach (var addon in addons.EnumerateArray())
        {
            string? Text(JsonElement e, string key) =>
                e.ValueKind == JsonValueKind.Object
                && e.TryGetProperty(key, out var v)
                && v.ValueKind == JsonValueKind.String
                    ? v.GetString()
                    : null;
            var id = Text(addon, "id");
            var location = Text(addon, "location") ?? "";
            if (
                id is null
                || Text(addon, "type") != "extension"
                || location == "app-builtin"
                || location.StartsWith("app-system", StringComparison.Ordinal)
            )
                continue;
            var name = addon.TryGetProperty("defaultLocale", out var locale) ? Text(locale, "name") ?? "" : "";
            var permissions =
                addon.TryGetProperty("userPermissions", out var user)
                && user.ValueKind == JsonValueKind.Object
                && user.TryGetProperty("permissions", out var list)
                && list.ValueKind == JsonValueKind.Array
                    ? list.EnumerateArray()
                        .Where(x => x.ValueKind == JsonValueKind.String)
                        .Select(x => x.GetString()!)
                        .ToArray()
                    : [];
            found.AddRange(BrowserExtensionEvidence("Firefox", sid, id, name, permissions, policy));
        }
        return found.ToArray();
    }

    private static IEnumerable<Evidence> BrowserExtensionEvidence(
        string browser,
        string sid,
        string id,
        string name,
        string[] permissions,
        PolicyDocument policy
    )
    {
        var key = "browser:" + sid + ":" + browser + ":" + id;
        var label = name.Length > 0 ? $"「{(name.Length > 100 ? name[..100] + "…" : name)}」" : "";
        var matched = policy
            .Products.Where(r =>
                r.BrowserExtensions.Any(x =>
                    string.Equals(x.Trim(), id, StringComparison.OrdinalIgnoreCase)
                    || name.Length > 0 && NameMatches(name, x)
                )
            )
            .ToArray();
        foreach (var rule in matched)
            yield return new(
                rule.Id,
                rule.Name,
                EvidenceKind.Extension,
                key,
                BrowserSource,
                $"{browser} 扩展{label}，ID：{id}",
                sid
            );
        if (matched.Length == 0 && permissions.Contains("proxy", StringComparer.OrdinalIgnoreCase))
            yield return new(
                "browser-proxy-clue",
                "浏览器代理扩展",
                EvidenceKind.Clue,
                key,
                BrowserSource,
                $"{browser} 扩展{label}可以修改浏览器代理，ID：{id}",
                sid,
                false
            );
    }

    /// <summary>
    /// Files anywhere on a volume whose name is one of <paramref name="names"/>, read from the volume's file records
    /// in one pass. The recycle bin and System Volume Information are skipped. At most <paramref name="limit"/> paths
    /// are returned, in path order.
    /// </summary>
    public static List<string> FindProgramFiles(
        IVolumeIndex index,
        IReadOnlySet<string> names,
        int limit,
        CancellationToken ct
    )
    {
        var folders = new Dictionary<ulong, (ulong Parent, string Name)>();
        var candidates = new List<VolumeEntry>();
        foreach (var entry in index.Entries(ct))
        {
            if (entry.Id == index.RootId)
                continue;
            if (entry.IsDirectory)
                folders[entry.Id] = (entry.ParentId, entry.Name);
            else if (names.Contains(entry.Name))
                candidates.Add(entry);
        }
        var paths = new List<string>();
        foreach (var candidate in candidates)
        {
            var parts = new List<string> { candidate.Name };
            var id = candidate.ParentId;
            while (id != index.RootId && folders.TryGetValue(id, out var folder) && parts.Count < 4096)
            {
                parts.Add(folder.Name);
                id = folder.Parent;
            }
            // Records still being written leave the name unplaced.
            if (id != index.RootId)
                continue;
            parts.Reverse();
            if (parts[0] is "$Recycle.Bin" or "System Volume Information")
                continue;
            paths.Add(Path.Join([index.Root, .. parts]));
        }
        return paths.Order(StringComparer.OrdinalIgnoreCase).Take(limit).ToList();
    }

    /// <summary>
    /// A program file found on disk: confirmed when its version information names the product, otherwise a clue,
    /// since a file name alone can be shared by unrelated programs. The finding belongs to the user whose profile
    /// holds the file.
    /// </summary>
    public static IEnumerable<Evidence> ProgramFileEvidence(
        string path,
        string? productName,
        string? description,
        PolicyDocument policy,
        IReadOnlyList<Profile> profiles
    )
    {
        var file = Path.GetFileName(path);
        // Alert details have a size limit; the end of a very long path says the most.
        var shown = path.Length > 300 ? "…" + path[^300..] : path;
        var owner = profiles
            .Where(p =>
                p.Path.Length > 0
                && path.StartsWith(
                    p.Path.TrimEnd('\\', '/') + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase
                )
            )
            .MaxBy(p => p.Path.Length)
            ?.Sid;
        var labels = new[] { productName, description }.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x!);
        foreach (
            var rule in policy.Products.Where(r => r.ExecutableNames.Contains(file, StringComparer.OrdinalIgnoreCase))
        )
        {
            var named = labels.FirstOrDefault(l => rule.DisplayNames.Append(rule.Name).Any(n => NameMatches(l, n)));
            yield return named is not null
                ? new Evidence(
                    rule.Id,
                    rule.Name,
                    EvidenceKind.Installation,
                    "program:" + path.ToLowerInvariant(),
                    "全盘程序文件",
                    $"{shown}（文件信息：{named}）",
                    owner
                )
                {
                    CollectedAt = DateTimeOffset.UtcNow,
                }
                : new Evidence(
                    "program-clue",
                    "同名程序文件",
                    EvidenceKind.Clue,
                    "program:" + path.ToLowerInvariant(),
                    "全盘程序文件",
                    $"{shown} 与 {rule.Name} 的程序同名，文件信息未能确认",
                    owner,
                    false
                );
        }
    }

    // What installers and archives append to a product's name: versions, architectures and edition markers.
    private static readonly Regex NameSuffix = new(
        @"^([\s_-]+\(?(v?\d+(\.\d+)*([-.]?(alpha|beta|rc|preview|stable)\.?\d*)?|x64|x86|amd64|arm64|win64|win32|windows|win|64-?bit|32-?bit|user|machine|portable)\)?)*$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant
    );

    /// <summary>
    /// A name from Apps &amp; Features or an install folder equals a rule's name, ignoring case, or is the rule's name
    /// followed only by versions or architectures: "Clash Verge 2.0.3 (x64)" and "Clash Verge_x64" match "Clash
    /// Verge"; "Zed Attack Proxy" does not match "Zed".
    /// </summary>
    public static bool NameMatches(string candidate, string ruleName)
    {
        candidate = candidate.Trim();
        ruleName = ruleName.Trim();
        return ruleName.Length > 0
            && candidate.StartsWith(ruleName, StringComparison.OrdinalIgnoreCase)
            && NameSuffix.IsMatch(candidate[ruleName.Length..]);
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
            var matching = policy.Products.Where(r => r.DisplayNames.Any(n => NameMatches(folder, n))).ToArray();
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

    // Policies published before rules carried npm package names; their command-line tools are still found.
    private static readonly Dictionary<string, string> LegacyNpmPackages = new()
    {
        ["claude"] = "@anthropic-ai/claude-code",
        ["codex"] = "@openai/codex",
        ["gemini"] = "@google/gemini-cli",
    };

    /// <summary>
    /// npm packages to look for: each rule's own, or for the claude, codex and gemini rules of policies published
    /// before rules named packages, the ones agents always knew.
    /// </summary>
    public static (string Package, ProductRule Rule)[] NpmTargets(PolicyDocument policy) =>
        policy
            .Products.SelectMany(r => (
                    r.NpmPackages.Length > 0 ? r.NpmPackages
                    : LegacyNpmPackages.TryGetValue(r.Id, out var legacy) ? [legacy]
                    : []
                ).Where(IsNpmPackageName).Select(p => (p.Trim().ToLowerInvariant(), r)))
            .ToArray();

    // "name" or "@scope/name"; nothing that could leave node_modules.
    private static bool IsNpmPackageName(string name) =>
        Regex.IsMatch(name.Trim(), @"^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$", RegexOptions.IgnoreCase);

    /// <summary>Global npm packages under a node_modules folder whose package.json names a rule's package.</summary>
    public static Evidence[] ScanNpmRoot(string root, string? sid, PolicyDocument policy)
    {
        if (!DirectoryPresent(root))
            return [];
        var found = new List<Evidence>();
        foreach (var (package, rule) in NpmTargets(policy))
        {
            var manifest = Path.Combine([root, .. package.Split('/'), "package.json"]);
            if (!FilePresent(manifest))
                continue;
            using var doc = JsonDocument.Parse(File.ReadAllText(manifest), ManifestOptions);
            if (
                !doc.RootElement.TryGetProperty("name", out var name)
                || name.ValueKind != JsonValueKind.String
                || !string.Equals(name.GetString(), package, StringComparison.OrdinalIgnoreCase)
            )
                continue;
            found.Add(
                new(
                    rule.Id,
                    rule.Name,
                    EvidenceKind.Installation,
                    "npm:" + (sid ?? "machine") + ":" + package,
                    "npm 包清单",
                    "npm 包名：" + package,
                    sid,
                    true
                )
            );
        }
        return found.ToArray();
    }

    /// <summary>The .cmd launchers npm creates for the programs of rules that name npm packages.</summary>
    public static string[] NpmShimNames(PolicyDocument policy) =>
        NpmTargets(policy)
            .SelectMany(t => t.Rule.ExecutableNames)
            .Where(n => n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            .Select(n => n[..^4].ToLowerInvariant() + ".cmd")
            .Distinct()
            .ToArray();

    /// <summary>PEP 503 normalization: "Aider_Chat" and "aider.chat" are both "aider-chat".</summary>
    public static string PipName(string name) => Regex.Replace(name.Trim(), @"[-_.]+", "-").ToLowerInvariant();

    /// <summary>Python packages in a site-packages folder, read from their "name-version.dist-info" folder names.</summary>
    public static Evidence[] ScanSitePackages(string sitePackages, string? sid, PolicyDocument policy)
    {
        var wanted = policy
            .Products.SelectMany(r => r.PipPackages.Select(p => (Name: PipName(p), Rule: r)))
            .Where(x => x.Name.Length > 0)
            .ToArray();
        if (wanted.Length == 0 || !DirectoryPresent(sitePackages))
            return [];
        var found = new List<Evidence>();
        foreach (var dir in Directory.EnumerateDirectories(sitePackages, "*.dist-info"))
        {
            var folder = Path.GetFileName(dir);
            var dash = folder.IndexOf('-');
            if (dash <= 0)
                continue;
            var name = PipName(folder[..dash]);
            foreach (var (_, rule) in wanted.Where(w => w.Name == name))
                found.Add(
                    new(
                        rule.Id,
                        rule.Name,
                        EvidenceKind.Installation,
                        "pip:" + (sid ?? "machine") + ":" + name,
                        "Python 包清单",
                        "Python 包：" + name + "（" + sitePackages + "）",
                        sid,
                        true
                    )
                );
        }
        return found.ToArray();
    }

    /// <summary>Folders matching a path whose segments may hold wildcards, e.g. ["Python", "Python3*", "site-packages"].</summary>
    public static IEnumerable<string> ExpandFolders(string root, params string[] segments)
    {
        IEnumerable<string> current = DirectoryPresent(root) ? [root] : [];
        foreach (var segment in segments)
            current = current
                .SelectMany(dir =>
                    segment.Contains('*')
                        ? Directory
                            .EnumerateDirectories(dir, segment)
                            .Where(d => (File.GetAttributes(d) & FileAttributes.ReparsePoint) == 0)
                    : DirectoryPresent(Path.Combine(dir, segment)) ? [Path.Combine(dir, segment)]
                    : []
                )
                .ToList();
        return current;
    }

    /// <summary>Programs in a user's command-line folder (e.g. .local\bin) named by any rule.</summary>
    public static Evidence[] ScanKnownCliBin(string root, string sid, PolicyDocument policy)
    {
        if (!DirectoryPresent(root))
            return [];
        var found = new List<Evidence>();
        var files = Directory
            .EnumerateFiles(root)
            .Select(Path.GetFileName)
            .OfType<string>()
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in policy.Products)
        {
            var file = rule.ExecutableNames.FirstOrDefault(files.Contains);
            if (file is null)
                continue;
            found.Add(
                new(
                    rule.Id,
                    rule.Name,
                    EvidenceKind.Installation,
                    "cli-file:" + sid + ":" + file.ToLowerInvariant(),
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
    /// Matches a user's Store packages by package name; a full name is "Name_Version_Arch_Resource_Publisher".
    /// Several installed versions of one app (e.g. framework or staged updates) become a single record.
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
        foreach (
            var app in packageFullNames
                .Select(full => (Full: full, Parts: full.Split('_')))
                .Where(p => p.Parts.Length >= 2 && p.Parts[0].Length > 0)
                .GroupBy(p => p.Parts[0], StringComparer.OrdinalIgnoreCase)
        )
        {
            var rules = policy
                .Products.Where(r =>
                    r.PackageIds.Any(id => string.Equals(id, app.Key, StringComparison.OrdinalIgnoreCase))
                )
                .ToArray();
            if (rules.Length == 0)
                continue;
            var versions = app.Select(p => p.Parts[1]).Distinct().ToArray();
            if (versions.Length == 0)
                continue;
            foreach (var rule in rules)
                found.Add(
                    new(
                        rule.Id,
                        rule.Name,
                        EvidenceKind.Installation,
                        "appx:" + userSid + ":" + app.Key,
                        "应用商店应用（按用户）",
                        $"应用包 {app.Key}，版本 {string.Join("、", versions)}",
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

    /// <summary>
    /// Tunnel adapters worth a clue: TUN/TAP-style virtual adapters used by VPN and proxy tools. Windows'
    /// own tunnels (Teredo, 6to4, ISATAP, IP-HTTPS, WAN Miniport dial-up VPN) are always present and skipped.
    /// </summary>
    public static bool IsTunnelClue(string name, string description, bool tunnelType)
    {
        var text = name + " " + description;
        if (Regex.IsMatch(text, @"(?i)teredo|6to4|isatap|ip-https|wan miniport|kernel debug|loopback"))
            return false;
        return tunnelType || Regex.IsMatch(text, @"(?i)tun|tap|wireguard|mihomo|clash");
    }

    /// <summary>
    /// Clue for a tunnel adapter, or null when it is not a tunnel, is one of Windows' own, or the policy approves
    /// it. Adapters matching a product's <see cref="ProductRule.AdapterNames"/> name that product, but an adapter
    /// name alone never confirms a violation.
    /// </summary>
    public static Evidence? TunnelEvidence(
        string id,
        string name,
        string description,
        bool tunnelType,
        PolicyDocument policy
    )
    {
        if (!IsTunnelClue(name, description, tunnelType))
            return null;
        var text = name + " " + description;
        bool Contains(string pattern) => text.Contains(pattern, StringComparison.OrdinalIgnoreCase);
        if (policy.ApprovedNetworkAdapters.Any(Contains))
            return null;
        var product = policy.Products.FirstOrDefault(p => p.AdapterNames.Any(Contains));
        return new(
            product?.Id ?? "interface-clue",
            product?.Name ?? "隧道网卡",
            EvidenceKind.Clue,
            "nic:" + id,
            "网络接口",
            product is null
                ? $"发现隧道类网卡“{name}”（{description}），归属和用途未核实"
                : $"隧道类网卡“{name}”（{description}）疑似由 {product.Name} 创建，仅凭网卡名称不能确认",
            null,
            false
        );
    }

    /// <summary>Product whose executable names include <paramref name="processName"/>, if any.</summary>
    public static ProductRule? ProductForProcess(string? processName, PolicyDocument policy) =>
        processName is null
            ? null
            : policy.Products.FirstOrDefault(r =>
                r.ExecutableNames.Any(x => string.Equals(x, processName, StringComparison.OrdinalIgnoreCase))
            );

    /// <summary>"clash-verge-service.exe（进程号 123，属于 Clash / Mihomo）"; describes who owns a socket.</summary>
    public static string DescribeOwner(PortListener owner, PolicyDocument policy)
    {
        var name = owner.ProcessName ?? "已退出的进程";
        var product = ProductForProcess(owner.ProcessName, policy);
        return product is null ? $"{name}（进程号 {owner.Pid}）" : $"{name}（进程号 {owner.Pid}，属于 {product.Name}）";
    }

    public static readonly int[] CommonProxyPorts = [1080, 7890, 7891, 7897, 8080, 10808, 10809, 2080];

    /// <summary>
    /// Clue for a listening socket: any port held by a known product's process, or a common proxy port held by
    /// anything else. Listening alone never confirms a violation; the owning process is reported for review.
    /// </summary>
    public static Evidence? PortEvidence(PortListener listener, PolicyDocument policy)
    {
        var product = ProductForProcess(listener.ProcessName, policy);
        if (product is null && !CommonProxyPorts.Contains(listener.Port))
            return null;
        return new(
            product?.Id ?? "port-clue",
            product?.Name ?? "监听端口",
            EvidenceKind.Clue,
            "tcp:" + listener.Address + ":" + listener.Port,
            "TCP 监听",
            product is null
                ? $"本机常见代理端口 {listener.Port} 由 {DescribeOwner(listener, policy)} 监听，用途未核实"
                : $"{DescribeOwner(listener, policy)} 正在监听端口 {listener.Port}",
            null,
            false
        );
    }

    /// <summary>
    /// Port of the first loopback entry in a WinINet/WinHTTP proxy string such as "127.0.0.1:7897" or
    /// "http=127.0.0.1:7890;https=127.0.0.1:7890". Non-loopback servers return null so their address stays private.
    /// </summary>
    public static int? LoopbackProxyPort(string? proxyServer)
    {
        if (string.IsNullOrWhiteSpace(proxyServer))
            return null;
        foreach (var raw in proxyServer.Split([';', ' '], StringSplitOptions.RemoveEmptyEntries))
        {
            var entry = raw.Contains('=') ? raw[(raw.IndexOf('=') + 1)..] : raw;
            if (entry.Contains("://"))
                entry = entry[(entry.IndexOf("://") + 3)..];
            entry = entry.TrimEnd('/');
            var colon = entry.LastIndexOf(':');
            if (colon <= 0 || !int.TryParse(entry[(colon + 1)..], out var port) || port is < 1 or > 65535)
                continue;
            var host = entry[..colon].Trim('[', ']');
            if (
                host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
                || System.Net.IPAddress.TryParse(host, out var ip) && System.Net.IPAddress.IsLoopback(ip)
            )
                return port;
        }
        return null;
    }

    /// <summary>Summary for an enabled proxy: names the local program behind a loopback proxy, withholds other addresses.</summary>
    public static string ProxySummary(
        string prefix,
        string? proxyServer,
        IReadOnlyList<PortListener> listeners,
        PolicyDocument policy
    )
    {
        var port = LoopbackProxyPort(proxyServer);
        if (port is null)
            return prefix + "（不记录地址）";
        var owner =
            listeners.FirstOrDefault(l => l.Port == port && System.Net.IPAddress.IsLoopback(l.Address))
            ?? listeners.FirstOrDefault(l => l.Port == port);
        return owner is null
            ? $"{prefix}，指向本机端口 {port}，当前没有程序监听该端口"
            : $"{prefix}，指向本机端口 {port}，由 {DescribeOwner(owner, policy)} 监听";
    }
}
