using System.Collections.Concurrent;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Compliance.Core;
using Microsoft.Win32;

namespace Compliance.Agent;

/// <summary>A user profile from ProfileList; per-user collectors need its hive, its folder, or both.</summary>
public sealed record Profile(string Sid, string Path, bool HiveLoaded, bool PathAvailable, string? Name = null);

public sealed record ScanContext(PolicyDocument Policy, IReadOnlyList<Profile> Profiles);

/// <summary>One scope a collector covers. When <see cref="Unavailable"/> is set the scope is reported as not covered.</summary>
public readonly record struct CollectorScope(string Scope, Profile? Profile = null, string? Unavailable = null)
{
    public const string HiveNotLoaded = "该用户的注册表未加载，需在该用户登录后重新检查";
    public const string PathUnavailable = "用户目录不可用";

    public static CollectorScope Machine => new("machine");

    public static IEnumerable<CollectorScope> Users(
        ScanContext context,
        bool needsHive = false,
        bool needsPath = false
    ) =>
        context.Profiles.Select(p => new CollectorScope(
            p.Sid,
            p,
            needsHive && !p.HiveLoaded ? HiveNotLoaded
                : needsPath && !p.PathAvailable ? PathUnavailable
                : null
        ));
}

/// <summary>
/// One inspection module. Each scope runs on its own with a timeout; a failure or timeout marks only
/// that module and scope as incomplete and never discards what other collectors found.
/// </summary>
public interface ICollector
{
    /// <summary>Module name reported to the server, e.g. "installed".</summary>
    string Module { get; }

    /// <summary>Inventory modules run on full scans only; light scans reuse their previous results.</summary>
    bool Inventory => PolicyDocument.InventoryModules.Contains(Module);

    TimeSpan Timeout => TimeSpan.FromSeconds(30);

    IEnumerable<CollectorScope> Scopes(ScanContext context);

    Task CollectAsync(ScanContext context, CollectorScope scope, List<Evidence> evidence, CancellationToken ct);
}

/// <summary>
/// Collector runs that timed out and are still going. A timed-out run cannot be stopped (registry, WMI and file
/// calls on a hung share block), so the same module and scope is not started again until it ends; otherwise every
/// cycle would leave one more stuck thread behind.
/// </summary>
public sealed class AbandonedRuns
{
    public const string StillRunning = "上一次检查仍未结束，本项检查不完整";

    private readonly ConcurrentDictionary<string, Task> runs = new();

    public bool Running(string key)
    {
        if (!runs.TryGetValue(key, out var run))
            return false;
        if (!run.IsCompleted)
            return true;
        runs.TryRemove(key, out _);
        return false;
    }

    public void Add(string key, Task run)
    {
        // Nobody awaits it any more; observe a late failure so it is not reported as unobserved.
        _ = run.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);
        runs[key] = run;
    }

    public int Count => runs.Values.Count(r => !r.IsCompleted);
}

public static class FixtureCollector
{
    public static async Task<ScanSnapshot> LoadAsync(string path, CancellationToken ct = default)
    {
        var source = Wire.Read<ScanSnapshot>(await File.ReadAllTextAsync(path, ct));
        return source with { Simulated = true, Platform = "Windows", CollectedAt = DateTimeOffset.UtcNow };
    }
}

[SupportedOSPlatform("windows")]
public sealed partial class WindowsCollector
{
    // One per process: each cycle creates a new collector, and runs abandoned by earlier cycles must stay known.
    private static readonly AbandonedRuns Abandoned = new();

    private static readonly ICollector[] Collectors =
    [
        new InstalledCollector(),
        new ServicesCollector(),
        new InstallPathsCollector(),
        new ExtensionsCollector(),
        new CliCollector(),
        new ProgramFilesCollector(),
        new AppxCollector(),
        new UserProxyCollector(),
        new ProxyEnvironmentCollector(),
        new SystemProxyCollector(),
        new ProcessesCollector(),
        new PortsCollector(),
    ];

    public async Task<ScanSnapshot> CollectAsync(
        string deviceId,
        PolicyDocument policy,
        CancellationToken ct,
        ScanSnapshot? previousInventory = null
    )
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Native collection requires Windows");
        var evidence = new List<Evidence>();
        var modules = new List<ModuleResult>();

        Profile[] profiles = [];
        try
        {
            profiles = Profiles();
            modules.Add(new("users", "machine", "Complete", DateTimeOffset.UtcNow));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            modules.Add(new("users", "machine", "Error", DateTimeOffset.UtcNow, Incomplete(ex)));
        }
        foreach (var p in profiles)
            modules.Add(
                new(
                    "users",
                    p.Sid,
                    p.HiveLoaded && p.PathAvailable ? "Complete" : "Unknown",
                    DateTimeOffset.UtcNow,
                    !p.HiveLoaded ? CollectorScope.HiveNotLoaded
                        : !p.PathAvailable ? CollectorScope.PathUnavailable
                        : null
                )
            );
        if (profiles.Length == 0)
            modules.Add(new("users", "machine", "Unknown", DateTimeOffset.UtcNow, "未找到可检查的用户账户"));

        // Inventory is re-read when the set of users or their availability changed since the last full scan.
        var priorUsers = previousInventory
            ?.Modules.Where(m => m.Module == "users" && m.Scope != "machine")
            .Select(m => m.Scope + ":" + m.Status)
            .Order()
            .ToArray();
        var currentUsers = profiles
            .Select(p => p.Sid + ":" + (p.HiveLoaded && p.PathAvailable ? "Complete" : "Unknown"))
            .Order()
            .ToArray();
        bool full = previousInventory is null || !priorUsers!.SequenceEqual(currentUsers);
        if (!full)
        {
            var inventory = Collectors
                .Where(c => c.Inventory && policy.RequiredModules.Contains(c.Module))
                .Select(c => c.Module)
                .ToHashSet();
            modules.AddRange(previousInventory!.Modules.Where(m => inventory.Contains(m.Module)));
            evidence.AddRange(
                previousInventory.Evidence.Where(e => e.Kind is EvidenceKind.Installation or EvidenceKind.Extension)
            );
        }

        var context = new ScanContext(policy, profiles);
        // Modules the policy leaves out are not run at all.
        foreach (
            var collector in Collectors.Where(c => (full || !c.Inventory) && policy.RequiredModules.Contains(c.Module))
        )
        foreach (var scope in collector.Scopes(context))
        {
            if (scope.Unavailable is not null)
            {
                modules.Add(new(collector.Module, scope.Scope, "Unknown", DateTimeOffset.UtcNow, scope.Unavailable));
                continue;
            }
            var key = collector.Module + "|" + scope.Scope;
            if (Abandoned.Running(key))
            {
                modules.Add(
                    new(collector.Module, scope.Scope, "Error", DateTimeOffset.UtcNow, AbandonedRuns.StillRunning)
                );
                continue;
            }
            // Each scope collects into its own list so a timed-out run, which keeps going in the
            // background, cannot add evidence later. A run that failed has stopped, so whatever it
            // found before the failure is kept: an unreadable file must not hide a confirmed finding.
            var found = new List<Evidence>();
            var run = Task.Run(() => collector.CollectAsync(context, scope, found, ct), ct);
            try
            {
                await run.WaitAsync(collector.Timeout, ct);
                evidence.AddRange(found);
                modules.Add(new(collector.Module, scope.Scope, "Complete", DateTimeOffset.UtcNow));
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                if (run.IsCompleted)
                    evidence.AddRange(found);
                else
                    Abandoned.Add(key, run);
                modules.Add(new(collector.Module, scope.Scope, "Error", DateTimeOffset.UtcNow, Incomplete(ex)));
            }
        }

        return new ScanSnapshot
        {
            DeviceId = deviceId,
            HostName = Environment.MachineName,
            Platform = "Windows",
            Simulated = false,
            CollectedAt = DateTimeOffset.UtcNow,
            PolicyVersion = policy.Serial,
            Evidence = evidence.ToArray(),
            Modules = modules.ToArray(),
            Controls = [],
            Users = profiles.Where(p => p.Name is not null).Select(p => new UserAccount(p.Sid, p.Name!)).ToArray(),
        };
    }

    private static string Incomplete(Exception ex)
    {
        if (ex is TimeoutException)
            return "检查超时，本项检查不完整";
        var detail = EvidenceSanitizer.Clean(ex.Message);
        if (detail.Length > 160)
            detail = detail[..160] + "…";
        return $"{ex.GetType().Name}：{detail}；本项检查不完整";
    }

    internal static Profile[] Profiles()
    {
        using var root =
            Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList")
            ?? throw new IOException("ProfileList unreadable");
        var profiles = new List<Profile>();
        foreach (var sid in root.GetSubKeyNames().Where(IsUserSid))
        {
            using var key = root.OpenSubKey(sid);
            var raw = key?.GetValue("ProfileImagePath") as string;
            var path = string.IsNullOrWhiteSpace(raw) ? "" : Environment.ExpandEnvironmentVariables(raw);
            using var hive = Registry.Users.OpenSubKey(sid);
            profiles.Add(
                new(sid, path, hive is not null, path.Length > 0 && DirectoryPresent(path), AccountName(sid, path))
            );
        }
        return profiles.ToArray();
    }

    private static string? AccountName(string sid, string profilePath)
    {
        string? translated = null;
        try
        {
            translated = new System.Security.Principal.SecurityIdentifier(sid)
                .Translate(typeof(System.Security.Principal.NTAccount))
                .Value;
        }
        catch (Exception ex) when (ex is System.Security.Principal.IdentityNotMappedException or SystemException)
        {
            // Offline Entra ID or deleted accounts cannot be translated; the profile folder name is used instead.
        }
        return DisplayAccountName(translated, profilePath);
    }

    /// <summary>"LAPTOP\\kaiyu" -> "kaiyu"; without a translated account, the profile folder name.</summary>
    public static string? DisplayAccountName(string? translated, string profilePath)
    {
        if (!string.IsNullOrWhiteSpace(translated))
            return translated[(translated.LastIndexOf('\\') + 1)..];
        var folder = Path.GetFileName(profilePath.Replace('\\', '/').TrimEnd('/'));
        return string.IsNullOrWhiteSpace(folder) ? null : folder;
    }

    /// <summary>Local (S-1-5-21) and Entra ID (S-1-12-1) user accounts; service and system accounts are skipped.</summary>
    public static bool IsUserSid(string sid) =>
        Regex.IsMatch(sid, @"^S-1-5-21-(\d+-){3}\d+$") || Regex.IsMatch(sid, @"^S-1-12-1-(\d+-){3}\d+$");
}
