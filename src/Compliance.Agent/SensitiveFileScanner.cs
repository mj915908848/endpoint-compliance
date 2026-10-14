using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Compliance.Core;

namespace Compliance.Agent;

/// <summary>A user profile or a drive to walk. When <see cref="Unavailable"/> is set the scope is reported as not covered.</summary>
public sealed record SensitiveScanTarget(
    string Scope,
    string Root,
    string? UserSid,
    bool DriveRoot,
    string[] SkipPaths,
    string? Unavailable = null
);

/// <summary>Outcome of walking one scope. Status is Complete, Truncated (more hits than listed), Error or Unknown.</summary>
public sealed record SensitiveScopeResult(
    string Scope,
    string Status,
    DateTimeOffset CollectedAt,
    string? Error,
    Evidence[] Evidence
);

public sealed record SensitiveScanState(string ConfigHash, DateTimeOffset? CompletedAt, SensitiveScopeResult[] Scopes);

/// <summary>
/// Walks one folder tree comparing names only: files are never opened, so content, cloud placeholders and locked
/// files are left untouched. Linked folders (junctions, symbolic links, cloud-only folders) are not entered.
/// </summary>
public static class SensitiveFileWalker
{
    /// <summary>Program and system folders at the root of a data drive; they hold no user documents.</summary>
    public static readonly string[] DriveRootSkips =
    [
        "Windows",
        "Program Files",
        "Program Files (x86)",
        "ProgramData",
        "Recovery",
        "Config.Msi",
        "$WinREAgent",
        "$SysReset",
        "$Windows.~BT",
        "$Windows.~WS",
    ];

    public static SensitiveScopeResult Scan(
        SensitiveScanTarget target,
        SensitiveFilePolicy policy,
        Func<string, string?>? ownerOf,
        CancellationToken ct
    )
    {
        var matcher = new SensitiveNameMatcher(policy.Rules);
        var names = policy.ExcludePaths.Where(p => !IsPath(p)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var prefixes = policy.ExcludePaths.Where(IsPath).Concat(target.SkipPaths).Select(Full).ToArray();
        var hits = new List<Evidence>();
        int total = 0,
            unreadable = 0;
        string? firstUnreadable = null;
        var options = new EnumerationOptions
        {
            IgnoreInaccessible = false,
            RecurseSubdirectories = false,
            AttributesToSkip = 0,
        };

        void Hit(string path, List<SensitiveNameMatch> matches, bool folder)
        {
            total++;
            if (hits.Count >= policy.MaxHitsPerScope)
                return;
            // A name matching an alerting and a failing rule is recorded under the failing one.
            var primary = matches.FirstOrDefault(m => m.Rule.Action == "Violation");
            if (primary.Rule is null)
                primary = matches[0];
            hits.Add(
                new Evidence(
                    primary.Rule.Id,
                    string.Join("、", matches.Select(m => m.Rule.Name).Distinct()),
                    EvidenceKind.SensitiveFile,
                    path,
                    target.Scope,
                    SensitiveFiles.Summary(matches, folder),
                    target.UserSid ?? ownerOf?.Invoke(path)
                )
            );
        }

        var pending = new Stack<(string Path, bool Top, HashSet<string> Reported)>();
        pending.Push((target.Root, true, []));
        while (pending.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var (directory, top, reported) = pending.Pop();
            try
            {
                foreach (var entry in new DirectoryInfo(directory).EnumerateFileSystemInfos("*", options))
                {
                    ct.ThrowIfCancellationRequested();
                    if ((entry.Attributes & FileAttributes.Directory) == 0)
                    {
                        var matches = matcher.Match(entry.Name, false, reported);
                        if (matches.Count > 0)
                            Hit(entry.FullName, matches, false);
                        continue;
                    }
                    if (
                        names.Contains(entry.Name)
                        || top
                            && target.DriveRoot
                            && DriveRootSkips.Contains(entry.Name, StringComparer.OrdinalIgnoreCase)
                        || prefixes.Any(p => Under(entry.FullName, p))
                    )
                        continue;
                    var folderMatches = matcher.Match(entry.Name, true, reported);
                    var inner = reported;
                    if (folderMatches.Count > 0)
                    {
                        Hit(entry.FullName, folderMatches, true);
                        inner = [.. reported, .. folderMatches.Select(m => m.Rule.Id)];
                    }
                    if ((entry.Attributes & FileAttributes.ReparsePoint) == 0)
                        pending.Push((entry.FullName, false, inner));
                }
            }
            catch (Exception ex)
                when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
            {
                // One unreadable folder must not hide what the rest of the tree contains.
                unreadable++;
                firstUnreadable ??= directory;
            }
        }

        var done = DateTimeOffset.UtcNow;
        var notes = new List<string>();
        if (unreadable > 0)
            notes.Add($"{unreadable} 个文件夹无法读取（例如 {firstUnreadable}），本项检查不完整");
        if (total > hits.Count)
            notes.Add($"共命中 {total} 项，仅列出前 {hits.Count} 项");
        return new(
            target.Scope,
            unreadable > 0 ? "Error"
                : total > hits.Count ? "Truncated"
                : "Complete",
            done,
            notes.Count == 0 ? null : string.Join("；", notes),
            hits.Select(e => e with { CollectedAt = done }).ToArray()
        );
    }

    private static bool IsPath(string value) => value.Contains('\\') || value.Contains('/');

    private static string Full(string path)
    {
        try
        {
            return Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return path;
        }
    }

    private static bool Under(string path, string prefix) =>
        path.Equals(prefix, StringComparison.OrdinalIgnoreCase)
        || path.Length > prefix.Length
            && path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            && path[prefix.Length] is '\\' or '/';
}

/// <summary>
/// Runs sensitive file scans on a low-priority background thread so walking a large drive never delays the
/// five-minute process and proxy checks. Each snapshot carries the latest finished result of every scope, which is
/// kept on disk across restarts. Changing the rules discards old results and starts again.
/// </summary>
public sealed class SensitiveFileScanner(
    string statePath,
    Func<SensitiveFilePolicy, IReadOnlyList<SensitiveScanTarget>> targets,
    Func<string, string?>? ownerOf = null
) : IDisposable
{
    /// <summary>The server refuses snapshots with more than 5000 evidence records; the rest stays for other modules.</summary>
    public const int MaxEvidence = 2000;

    private readonly Lock gate = new();
    private SensitiveScanState state = Load(statePath);
    private CancellationTokenSource? running;
    private string? runningHash;
    private Task current = Task.CompletedTask;

    /// <summary>The scan in progress, or a completed task when idle.</summary>
    public Task Completion
    {
        get
        {
            lock (gate)
                return current;
        }
    }

    public static string Hash(SensitiveFilePolicy policy) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Wire.Serialize(policy))));

    /// <summary>Starts a scan when none has finished within the rescan interval, the rules changed, or one is forced.</summary>
    public void Update(SensitiveFilePolicy policy, bool force, DateTimeOffset now)
    {
        lock (gate)
        {
            if (!policy.Enabled)
            {
                Stop();
                if (state.Scopes.Length > 0 || state.CompletedAt is not null)
                {
                    state = new("", null, []);
                    Save();
                }
                return;
            }
            var hash = Hash(policy);
            if (running is not null && !current.IsCompleted)
            {
                if (runningHash == hash)
                    return;
                Stop();
            }
            if (state.ConfigHash != hash)
            {
                state = new(hash, null, []);
                Save();
            }
            else if (!force && state.CompletedAt is { } done && done > now.AddHours(-policy.RescanHours))
                return;
            var cts = new CancellationTokenSource();
            running = cts;
            runningHash = hash;
            current = Task.Factory.StartNew(
                () => Run(policy, hash, cts.Token),
                cts.Token,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default
            );
        }
    }

    /// <summary>Evidence and per-scope results for the snapshot; nothing when the rules differ from the last scan.</summary>
    public (Evidence[] Evidence, ModuleResult[] Modules) Results(SensitiveFilePolicy policy, DateTimeOffset now)
    {
        if (!policy.Enabled)
            return ([], []);
        lock (gate)
        {
            if (state.ConfigHash == Hash(policy) && state.Scopes.Length == 0 && state.CompletedAt is { } finished)
                return ([], [new(SensitiveFiles.Module, "machine", "Complete", finished, "本机没有需要扫描的范围")]);
            if (state.ConfigHash != Hash(policy) || state.Scopes.Length == 0)
            {
                var detail =
                    running is not null && !current.IsCompleted
                        ? "敏感文件扫描进行中，尚无结果"
                        : "敏感文件扫描尚未开始";
                return ([], [new(SensitiveFiles.Module, "machine", "Unknown", now, detail)]);
            }
            var evidence = new List<Evidence>();
            var modules = new List<ModuleResult>();
            foreach (var scope in state.Scopes)
            {
                var room = MaxEvidence - evidence.Count;
                if (scope.Evidence.Length > room)
                {
                    evidence.AddRange(scope.Evidence.Take(room));
                    modules.Add(
                        new(
                            SensitiveFiles.Module,
                            scope.Scope,
                            scope.Status == "Complete" ? "Truncated" : scope.Status,
                            scope.CollectedAt,
                            $"本机命中总数超过 {MaxEvidence} 项，此范围仅列出 {room} 项"
                                + (scope.Error is null ? "" : "；" + scope.Error)
                        )
                    );
                    continue;
                }
                evidence.AddRange(scope.Evidence);
                modules.Add(new(SensitiveFiles.Module, scope.Scope, scope.Status, scope.CollectedAt, scope.Error));
            }
            return (evidence.ToArray(), modules.ToArray());
        }
    }

    private void Run(SensitiveFilePolicy policy, string hash, CancellationToken ct)
    {
        try
        {
            Thread.CurrentThread.Priority = ThreadPriority.Lowest;
        }
        catch (Exception ex) when (ex is PlatformNotSupportedException or ThreadStateException) { }
        IReadOnlyList<SensitiveScanTarget> list;
        try
        {
            list = targets(policy);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Left unfinished so the next agent cycle tries again.
            Publish(hash, new("machine", "Error", DateTimeOffset.UtcNow, Failure(ex), []), complete: false, []);
            return;
        }
        foreach (var target in list)
        {
            if (ct.IsCancellationRequested)
                return;
            SensitiveScopeResult result;
            if (target.Unavailable is not null)
                result = new(target.Scope, "Unknown", DateTimeOffset.UtcNow, target.Unavailable, []);
            else
                try
                {
                    result = SensitiveFileWalker.Scan(target, policy, ownerOf, ct);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    result = new(target.Scope, "Error", DateTimeOffset.UtcNow, Failure(ex), []);
                }
            Publish(hash, result, complete: false, []);
        }
        Publish(hash, null, complete: true, list.Select(t => t.Scope).ToHashSet(StringComparer.Ordinal));
    }

    /// <summary>Replaces one scope's result; on completion also drops scopes that no longer exist (a removed drive).</summary>
    private void Publish(string hash, SensitiveScopeResult? result, bool complete, HashSet<string> keep)
    {
        lock (gate)
        {
            if (state.ConfigHash != hash)
                return;
            var scopes = state.Scopes.ToList();
            if (result is not null)
            {
                scopes.RemoveAll(s => s.Scope == result.Scope);
                scopes.Add(result);
            }
            if (complete && result is null)
                scopes.RemoveAll(s => !keep.Contains(s.Scope));
            state = new(hash, complete ? DateTimeOffset.UtcNow : state.CompletedAt, scopes.ToArray());
            Save();
        }
    }

    private static string Failure(Exception ex)
    {
        var detail = EvidenceSanitizer.Clean(ex.Message);
        if (detail.Length > 160)
            detail = detail[..160] + "…";
        return $"{ex.GetType().Name}：{detail}；本项检查不完整";
    }

    private void Stop()
    {
        running?.Cancel();
        running = null;
        runningHash = null;
    }

    private static SensitiveScanState Load(string path)
    {
        try
        {
            if (File.Exists(path))
                return Wire.Read<SensitiveScanState>(File.ReadAllText(path));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            Console.Error.WriteLine("Sensitive file scan state unreadable; scanning again: " + ex.GetType().Name);
        }
        return new("", null, []);
    }

    private void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(statePath))!);
            var temp = statePath + ".tmp";
            File.WriteAllText(temp, Wire.Serialize(state));
            File.Move(temp, statePath, true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Results still reach the server from memory; only a restart would repeat the scan.
            Console.Error.WriteLine("Sensitive file scan state not saved: " + ex.GetType().Name);
        }
    }

    public void Dispose()
    {
        lock (gate)
            Stop();
    }

    /// <summary>User profiles and fixed drives other than the system drive, as the policy selects.</summary>
    [SupportedOSPlatform("windows")]
    public static IReadOnlyList<SensitiveScanTarget> WindowsTargets(SensitiveFilePolicy policy)
    {
        var profiles = WindowsCollector.Profiles();
        var result = new List<SensitiveScanTarget>();
        if (policy.ScanUserProfiles)
            result.AddRange(
                profiles.Select(p => new SensitiveScanTarget(
                    p.Sid,
                    p.Path,
                    p.Sid,
                    false,
                    [],
                    p.PathAvailable ? null : CollectorScope.PathUnavailable
                ))
            );
        if (policy.ScanOtherFixedDrives)
        {
            // Profiles kept on a data drive are scanned once, as the user's own scope.
            string[] skip = policy.ScanUserProfiles
                ? profiles.Where(p => p.PathAvailable).Select(p => p.Path).ToArray()
                : [];
            var system = Path.GetPathRoot(Environment.SystemDirectory);
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.DriveType != DriveType.Fixed || drive.Name.Equals(system, StringComparison.OrdinalIgnoreCase))
                    continue;
                result.Add(
                    new(
                        SensitiveFiles.DriveScope(drive.Name[0]),
                        drive.RootDirectory.FullName,
                        null,
                        true,
                        skip,
                        drive.IsReady ? null : "磁盘未就绪或已被 BitLocker 锁定，无法检查"
                    )
                );
            }
        }
        return result;
    }

    /// <summary>The owning user account of a file on a shared drive; groups such as Administrators are not users.</summary>
    [SupportedOSPlatform("windows")]
    public static string? WindowsOwner(string path)
    {
        try
        {
            FileSystemSecurity security = Directory.Exists(path)
                ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Owner)
                : new FileInfo(path).GetAccessControl(AccessControlSections.Owner);
            var sid = security.GetOwner(typeof(SecurityIdentifier))?.Value;
            return sid is not null && WindowsCollector.IsUserSid(sid) ? sid : null;
        }
        catch (SystemException)
        {
            return null;
        }
    }
}
