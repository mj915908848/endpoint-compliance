using System.Diagnostics;
using System.IO.Compression;
using System.Runtime.Versioning;
using System.Xml;
using System.Xml.Linq;
using Compliance.Core;
using Microsoft.Win32;

namespace Compliance.Agent;

/// <summary>Programs registered for uninstall (Apps &amp; Features), machine-wide and per user.</summary>
[SupportedOSPlatform("windows")]
internal sealed class InstalledCollector : ICollector
{
    public string Module => "installed";
    public bool Inventory => true;

    public IEnumerable<CollectorScope> Scopes(ScanContext context) =>
        [CollectorScope.Machine, .. CollectorScope.Users(context, needsHive: true)];

    public Task CollectAsync(ScanContext context, CollectorScope scope, List<Evidence> evidence, CancellationToken ct)
    {
        var sid = scope.Profile?.Sid;
        var hive = sid is null ? RegistryHive.LocalMachine : RegistryHive.Users;
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var root = RegistryKey.OpenBaseKey(hive, view);
            var relative = (sid is null ? "" : sid + "\\") + @"Software\Microsoft\Windows\CurrentVersion\Uninstall";
            using var uninstall = root.OpenSubKey(relative);
            if (uninstall is null)
                continue;
            foreach (var sub in uninstall.GetSubKeyNames())
            {
                using var entry = uninstall.OpenSubKey(sub);
                var name = entry?.GetValue("DisplayName") as string;
                if (string.IsNullOrWhiteSpace(name))
                    continue;
                foreach (
                    var rule in context.Policy.Products.Where(r =>
                        r.DisplayNames.Any(d => WindowsCollector.NameMatches(name, d))
                    )
                )
                    evidence.Add(
                        new(
                            rule.Id,
                            rule.Name,
                            EvidenceKind.Installation,
                            $"uninstall:{hive}:{view}:{sid}:{sub}",
                            "卸载信息注册表",
                            $"安装程序登记名称：{name}",
                            sid
                        )
                    );
            }
        }
        return Task.CompletedTask;
    }
}

/// <summary>Background services that known products register.</summary>
[SupportedOSPlatform("windows")]
internal sealed class ServicesCollector : ICollector
{
    public string Module => "services";
    public bool Inventory => true;

    public IEnumerable<CollectorScope> Scopes(ScanContext context) => [CollectorScope.Machine];

    public Task CollectAsync(ScanContext context, CollectorScope scope, List<Evidence> evidence, CancellationToken ct)
    {
        using var root =
            Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services")
            ?? throw new IOException("Service registry unreadable");
        foreach (var name in new[] { "clash_verge_service", "CodexSandboxService.OpenAI.Codex" })
        {
            using var service = root.OpenSubKey(name);
            if (service is null)
                continue;
            var match = WindowsCollector.MatchServiceRegistration(
                name,
                service.GetValue("DisplayName") as string,
                context.Policy
            );
            if (match is not null)
                evidence.Add(match);
        }
        return Task.CompletedTask;
    }
}

/// <summary>Known install folders, catching portable or per-user installs that skip the uninstall registry.</summary>
[SupportedOSPlatform("windows")]
internal sealed class InstallPathsCollector : ICollector
{
    public string Module => "installed-paths";
    public bool Inventory => true;

    public IEnumerable<CollectorScope> Scopes(ScanContext context) =>
        [CollectorScope.Machine, .. CollectorScope.Users(context, needsPath: true)];

    public Task CollectAsync(ScanContext context, CollectorScope scope, List<Evidence> evidence, CancellationToken ct)
    {
        if (scope.Profile is { } p)
        {
            evidence.AddRange(
                WindowsCollector.ScanKnownInstallRoot(
                    Path.Combine(p.Path, "AppData", "Local", "Programs"),
                    p.Sid,
                    context.Policy
                )
            );
            return Task.CompletedTask;
        }
        foreach (
            var root in new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            }
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
        )
            evidence.AddRange(WindowsCollector.ScanKnownInstallRoot(root, null, context.Policy));
        return Task.CompletedTask;
    }
}

/// <summary>
/// Program files of known products anywhere on each fixed NTFS drive, found by name in the drive's file table: catches
/// portable and unzipped copies that never registered an install. Drives that are not NTFS are left out.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class ProgramFilesCollector : ICollector
{
    private const int Limit = 50;

    public string Module => "programs";
    public bool Inventory => true;
    public TimeSpan Timeout => TimeSpan.FromMinutes(2);

    public IEnumerable<CollectorScope> Scopes(ScanContext context)
    {
        if (!context.Policy.Products.Any(r => r.ExecutableNames.Length > 0))
            return [];
        var scopes = new List<CollectorScope>();
        foreach (var drive in DriveInfo.GetDrives())
        {
            try
            {
                if (drive.DriveType == DriveType.Fixed && drive.IsReady && drive.DriveFormat == "NTFS")
                    scopes.Add(new(SensitiveFiles.DriveScope(drive.Name[0])));
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
        return scopes;
    }

    public Task CollectAsync(ScanContext context, CollectorScope scope, List<Evidence> evidence, CancellationToken ct)
    {
        var names = context
            .Policy.Products.SelectMany(r => r.ExecutableNames)
            .Where(n => n.Length > 0)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        using var index =
            NtfsVolume.TryOpen(scope.Scope[^1] + @":\") ?? throw new IOException("无法读取该分区的文件表");
        var found = new List<Evidence>();
        foreach (var path in WindowsCollector.FindProgramFiles(index, names, Limit, ct))
        {
            ct.ThrowIfCancellationRequested();
            string? product = null,
                description = null;
            try
            {
                var info = FileVersionInfo.GetVersionInfo(path);
                (product, description) = (info.ProductName, info.FileDescription);
            }
            // Unreadable version information leaves the file judged by its name alone; a deleted one is dropped.
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                if (!File.Exists(path))
                    continue;
            }
            found.AddRange(
                WindowsCollector.ProgramFileEvidence(path, product, description, context.Policy, context.Profiles)
            );
        }
        evidence.AddRange(found.DistinctBy(e => e.ProductId + "\n" + e.ObjectKey));
        return Task.CompletedTask;
    }
}

/// <summary>VS Code family and JetBrains extensions in each user's profile.</summary>
[SupportedOSPlatform("windows")]
internal sealed class ExtensionsCollector : ICollector
{
    public string Module => "extensions";
    public bool Inventory => true;

    public IEnumerable<CollectorScope> Scopes(ScanContext context) => CollectorScope.Users(context, needsPath: true);

    public Task CollectAsync(ScanContext context, CollectorScope scope, List<Evidence> evidence, CancellationToken ct)
    {
        var p = scope.Profile!;
        var extensions = WindowsCollector.ScanKnownExtensionRoots(p.Path, p.Sid, context.Policy);
        evidence.AddRange(extensions.Evidence);
        var jetBrains = Path.Combine(p.Path, "AppData", "Roaming", "JetBrains");
        // One unreadable plugin must not stop the rest from being checked; failures are counted and
        // reported once at the end so the module still shows as incomplete.
        var failed = new List<string>();
        if (WindowsCollector.DirectoryPresent(jetBrains))
        {
            var options = new EnumerationOptions
            {
                RecurseSubdirectories = true,
                AttributesToSkip = FileAttributes.ReparsePoint,
                IgnoreInaccessible = false,
            };
            foreach (var manifest in Directory.EnumerateFiles(jetBrains, "plugin.xml", options))
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var stream = File.OpenRead(manifest);
                    AddJetBrainsPlugin(stream, p.Sid, context.Policy, evidence);
                }
                catch (Exception ex)
                    when (ex is IOException or InvalidDataException or UnauthorizedAccessException or XmlException)
                {
                    failed.Add(Path.GetFileName(Path.GetDirectoryName(manifest)) ?? "plugin.xml");
                }
            }
            foreach (var jar in Directory.EnumerateFiles(jetBrains, "*.jar", options))
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var archive = ZipFile.OpenRead(jar);
                    var entry = archive.GetEntry("META-INF/plugin.xml");
                    if (entry is null)
                        continue;
                    if (entry.Length > 1024 * 1024)
                        throw new InvalidDataException("JetBrains plugin manifest too large");
                    using var stream = entry.Open();
                    AddJetBrainsPlugin(stream, p.Sid, context.Policy, evidence);
                }
                catch (Exception ex)
                    when (ex is IOException or InvalidDataException or UnauthorizedAccessException or XmlException)
                {
                    failed.Add(Path.GetFileName(jar));
                }
            }
        }
        var total = extensions.Errors + failed.Count;
        if (total > 0)
            throw new InvalidDataException(
                $"{total} 个扩展清单无法读取"
                    + (extensions.Errors > 0 ? "，编辑器扩展：" + string.Join("、", extensions.Failed.Take(3)) : "")
                    + (failed.Count > 0 ? "，JetBrains 插件：" + string.Join("、", failed.Take(3)) : "")
            );
        return Task.CompletedTask;
    }

    private static void AddJetBrainsPlugin(Stream stream, string sid, PolicyDocument policy, List<Evidence> evidence)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = 1024 * 1024,
        };
        using var reader = XmlReader.Create(stream, settings);
        var id = XDocument.Load(reader).Root?.Element("id")?.Value;
        if (string.IsNullOrWhiteSpace(id))
            return;
        foreach (
            var rule in policy.Products.Where(r =>
                r.ExtensionIds.Any(x => string.Equals(x, id, StringComparison.OrdinalIgnoreCase))
            )
        )
            evidence.Add(
                new(
                    rule.Id,
                    rule.Name,
                    EvidenceKind.Extension,
                    "jetbrains:" + sid + ":" + id,
                    "JetBrains 插件清单",
                    "插件 ID：" + id,
                    sid
                )
            );
    }
}

/// <summary>
/// Command-line tools installed through npm, pip, pipx or uv, or as standalone programs. Package names come from the
/// policy's rules, so a new tool needs a rule rather than a new agent.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class CliCollector : ICollector
{
    public string Module => "cli";
    public bool Inventory => true;

    public IEnumerable<CollectorScope> Scopes(ScanContext context) =>
        [.. CollectorScope.Users(context, needsPath: true), CollectorScope.Machine];

    public Task CollectAsync(ScanContext context, CollectorScope scope, List<Evidence> evidence, CancellationToken ct)
    {
        var policy = context.Policy;
        var found = new List<Evidence>();
        if (scope.Profile is not { } p)
        {
            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var systemDrive = Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";
            foreach (
                var root in new[]
                {
                    Path.Combine(programFiles, "nodejs", "node_modules"),
                    Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                        "npm",
                        "node_modules"
                    ),
                }
            )
                found.AddRange(WindowsCollector.ScanNpmRoot(root, null, policy));
            if (policy.Products.Any(r => r.PipPackages.Length > 0))
                foreach (
                    var site in WindowsCollector
                        .ExpandFolders(programFiles, "Python3*", "Lib", "site-packages")
                        .Concat(WindowsCollector.ExpandFolders(systemDrive, "Python3*", "Lib", "site-packages"))
                )
                    found.AddRange(WindowsCollector.ScanSitePackages(site, null, policy));
        }
        else
        {
            var roaming = Path.Combine(p.Path, "AppData", "Roaming");
            var local = Path.Combine(p.Path, "AppData", "Local");
            var npm = Path.Combine(roaming, "npm");
            found.AddRange(WindowsCollector.ScanNpmRoot(Path.Combine(npm, "node_modules"), p.Sid, policy));
            foreach (var name in WindowsCollector.NpmShimNames(policy))
                if (WindowsCollector.FilePresent(Path.Combine(npm, name)))
                    found.Add(
                        new(
                            "cli-clue",
                            "命令行启动脚本",
                            EvidenceKind.Clue,
                            "cli-shim:" + p.Sid + ":" + name,
                            "npm 启动脚本",
                            "仅文件名匹配：" + name,
                            p.Sid,
                            false
                        )
                    );
            found.AddRange(WindowsCollector.ScanKnownCliBin(Path.Combine(p.Path, ".local", "bin"), p.Sid, policy));
            if (policy.Products.Any(r => r.PipPackages.Length > 0))
                foreach (
                    var site in new[]
                    {
                        WindowsCollector.ExpandFolders(roaming, "Python", "Python3*", "site-packages"),
                        WindowsCollector.ExpandFolders(local, "Programs", "Python", "Python3*", "Lib", "site-packages"),
                        // pipx keeps one virtual environment per tool; its home moved between versions.
                        WindowsCollector.ExpandFolders(p.Path, "pipx", "venvs", "*", "Lib", "site-packages"),
                        WindowsCollector.ExpandFolders(p.Path, ".local", "pipx", "venvs", "*", "Lib", "site-packages"),
                        WindowsCollector.ExpandFolders(local, "pipx", "pipx", "venvs", "*", "Lib", "site-packages"),
                        WindowsCollector.ExpandFolders(roaming, "uv", "tools", "*", "Lib", "site-packages"),
                    }.SelectMany(x => x)
                )
                    found.AddRange(WindowsCollector.ScanSitePackages(site, p.Sid, policy));
        }
        // The same package can sit in several environments; one finding per package is enough.
        evidence.AddRange(found.DistinctBy(e => e.ProductId + "\n" + e.ObjectKey));
        return Task.CompletedTask;
    }
}

/// <summary>
/// Store (Appx/MSIX) packages per user through <c>PackageManager.FindPackagesForUser</c> (see <see cref="StorePackages"/>),
/// the API behind <c>Get-AppxPackage -User</c>. It needs administrator rights (the service runs as LocalSystem) and also
/// covers users who are not logged on. The AppxAllUserStore registry key is not used: on a real device it
/// listed versions an update had replaced and missed the one actually installed.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class AppxCollector : ICollector
{
    public string Module => "appx";
    public bool Inventory => true;

    public IEnumerable<CollectorScope> Scopes(ScanContext context) =>
        context.Profiles.Count == 0
            ? [new CollectorScope("machine", Unavailable: "未找到可检查的用户账户")]
            : CollectorScope.Users(context);

    public Task CollectAsync(ScanContext context, CollectorScope scope, List<Evidence> evidence, CancellationToken ct)
    {
        var packages = StorePackages.ForUser(scope.Scope);
        evidence.AddRange(WindowsCollector.ParseAppxPackages(packages, scope.Scope, context.Policy));
        return Task.CompletedTask;
    }
}
