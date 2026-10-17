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

/// <summary>
/// Outcome of scanning one scope. Status is Complete, Truncated (more hits than listed), Error or Unknown.
/// <see cref="Volume"/> is set when the result came from a volume index whose change journal is watched.
/// </summary>
public sealed record SensitiveScopeResult(
    string Scope,
    string Status,
    DateTimeOffset CollectedAt,
    string? Error,
    Evidence[] Evidence,
    string? Volume = null
);

public sealed record SensitiveScanState(
    string ConfigHash,
    DateTimeOffset? CompletedAt,
    SensitiveScopeResult[] Scopes,
    VolumeCursor[]? Cursors = null
);

/// <summary>
/// Which folders a scan enters and which names it reports. Shared by the folder walk and the volume index so both
/// report the same paths.
/// </summary>
public sealed class SensitiveScopeRules
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

    private readonly HashSet<string> names;
    private readonly string[] policyPrefixes;
    private readonly (SensitiveScanTarget Target, string Root, string[] Prefixes)[] targets;

    public SensitiveScopeRules(IEnumerable<SensitiveScanTarget> targets, SensitiveFilePolicy policy)
    {
        Matcher = new SensitiveNameMatcher(policy.Rules);
        Policy = policy;
        names = policy.ExcludePaths.Where(p => !IsPath(p)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        policyPrefixes = policy.ExcludePaths.Where(IsPath).Select(Full).ToArray();
        this.targets = targets
            .Select(t => (t, Full(t.Root), policyPrefixes.Concat(t.SkipPaths.Select(Full)).ToArray()))
            .OrderByDescending(t => t.Item2.Length)
            .ToArray();
    }

    public SensitiveNameMatcher Matcher { get; }
    public SensitiveFilePolicy Policy { get; }

    /// <summary>The scan target a path lies in (the innermost one), with its normalized root.</summary>
    public (SensitiveScanTarget Target, string Root)? TargetOf(string path, bool allowRoot = false)
    {
        foreach (var (target, root, _) in targets)
            if (Under(path, root) && (allowRoot || !path.Equals(root, StringComparison.OrdinalIgnoreCase)))
                return (target, root);
        return null;
    }

    /// <summary>A folder the scan does not enter or report. <paramref name="top"/>: the folder sits directly in the target root.</summary>
    public bool Excluded(SensitiveScanTarget target, string name, string path, bool top) =>
        names.Contains(name)
        || top && target.DriveRoot && DriveRootSkips.Contains(name, StringComparer.OrdinalIgnoreCase)
        || targets.First(t => ReferenceEquals(t.Target, target)).Prefixes.Any(p => Under(path, p));

    /// <summary>
    /// The rules a name is reported under, given the folders between the target root and it (outermost first), or
    /// null when it is not reported: a folder on the way is excluded or linked, or every rule it matches was already
    /// reported for a folder above it.
    /// </summary>
    public List<SensitiveNameMatch>? Match(
        SensitiveScanTarget target,
        IReadOnlyList<(string Name, string Path, bool Linked)> folders,
        string name,
        string path,
        bool folder
    )
    {
        var reported = new HashSet<string>();
        for (var i = 0; i < folders.Count; i++)
        {
            var (n, p, linked) = folders[i];
            if (Excluded(target, n, p, i == 0) || linked)
                return null;
            reported.UnionWith(Matcher.Match(n, true, reported).Select(m => m.Rule.Id));
        }
        if (folder && Excluded(target, name, path, folders.Count == 0))
            return null;
        var matches = Matcher.Match(name, folder, reported);
        return matches.Count > 0 ? matches : null;
    }

    /// <summary>Whether a folder is scanned: it lies in a target and nothing on the way to it is excluded or linked.</summary>
    public bool Visible(string path)
    {
        if (TargetOf(path, allowRoot: true) is not var (target, root))
            return false;
        var current = root;
        var top = true;
        foreach (var name in path[root.Length..].Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Join(current, name);
            if (Excluded(target, name, current, top) || Linked(current))
                return false;
            top = false;
        }
        return true;
    }

    private static bool Linked(string path)
    {
        try
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>Evidence for one reported name; a name matching an alerting and a failing rule is filed under the failing one.</summary>
    public static Evidence Hit(
        SensitiveScanTarget target,
        string path,
        List<SensitiveNameMatch> matches,
        bool folder,
        Func<string, string?>? ownerOf
    )
    {
        var primary = matches.FirstOrDefault(m => m.Rule.Action == "Violation");
        if (primary.Rule is null)
            primary = matches[0];
        return new Evidence(
            primary.Rule.Id,
            string.Join("、", matches.Select(m => m.Rule.Name).Distinct()),
            EvidenceKind.SensitiveFile,
            path,
            target.Scope,
            SensitiveFiles.Summary(matches, folder),
            target.UserSid ?? ownerOf?.Invoke(path)
        );
    }

    public static SensitiveScopeResult Result(
        SensitiveScanTarget target,
        List<Evidence> hits,
        int total,
        int unreadable,
        string? firstUnreadable
    )
    {
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

    public static string Full(string path)
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

    /// <summary>The path is the prefix folder or lies inside it; a prefix may be a drive root such as "D:\".</summary>
    public static bool Under(string path, string prefix) =>
        path.Equals(prefix, StringComparison.OrdinalIgnoreCase)
        || path.Length > prefix.Length
            && path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            && (path[prefix.Length] is '\\' or '/' || prefix[^1] is '\\' or '/');
}

/// <summary>
/// Walks one folder tree comparing names only: files are never opened, so content, cloud placeholders and locked
/// files are left untouched. Linked folders (junctions, symbolic links, cloud-only folders) are not entered. Used for
/// volumes without an index (not NTFS, or the volume cannot be opened).
/// </summary>
public static class SensitiveFileWalker
{
    public static SensitiveScopeResult Scan(
        SensitiveScanTarget target,
        SensitiveFilePolicy policy,
        Func<string, string?>? ownerOf,
        CancellationToken ct
    )
    {
        var rules = new SensitiveScopeRules([target], policy);
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
            if (hits.Count < policy.MaxHitsPerScope)
                hits.Add(SensitiveScopeRules.Hit(target, path, matches, folder, ownerOf));
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
                        var matches = rules.Matcher.Match(entry.Name, false, reported);
                        if (matches.Count > 0)
                            Hit(entry.FullName, matches, false);
                        continue;
                    }
                    if (rules.Excluded(target, entry.Name, entry.FullName, top))
                        continue;
                    var folderMatches = rules.Matcher.Match(entry.Name, true, reported);
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
        return SensitiveScopeRules.Result(target, hits, total, unreadable, firstUnreadable);
    }
}

/// <summary>
/// Runs sensitive file scans on a low-priority background thread so a large drive never delays the five-minute
/// process and proxy checks. NTFS volumes are read from their file records (in the service, the shared
/// <see cref="VolumeCatalog"/>, which reads each file table once and follows its change journal); other volumes are
/// walked folder by folder. Between full scans each agent cycle reads the volumes' change journals and rescans a volume only
/// when a matching name appeared, disappeared or moved, so new files are found within minutes. Each snapshot carries
/// the latest result of every scope, which is kept on disk across restarts. Changing the rules starts again.
/// </summary>
public sealed class SensitiveFileScanner(
    string statePath,
    Func<SensitiveFilePolicy, IReadOnlyList<SensitiveScanTarget>> targets,
    Func<string, string?>? ownerOf = null,
    Func<string, IVolumeIndex?>? volumes = null
) : IDisposable
{
    /// <summary>The server refuses snapshots with more than 5000 evidence records; the rest stays for other modules.</summary>
    public const int MaxEvidence = 2000;

    private readonly Lock gate = new();
    private SensitiveScanState state = Load(statePath);
    private CancellationTokenSource? running;
    private string? runningHash;
    private bool runningFull;
    private Task current = Task.CompletedTask;

    private int revision;

    /// <summary>Counts changes to the reported results: a scope rescanned or a full scan finished.</summary>
    public int Revision => Volatile.Read(ref revision);

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

    /// <summary>
    /// Starts a full scan when none has finished within the rescan interval, the rules changed, or one is forced;
    /// otherwise checks for changes since the last scan.
    /// </summary>
    public void Update(SensitiveFilePolicy policy, bool force, DateTimeOffset now)
    {
        Plan(policy, force, now);
        Flush();
    }

    private void Plan(SensitiveFilePolicy policy, bool force, DateTimeOffset now)
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
            var full =
                state.ConfigHash != hash
                || force
                || state.CompletedAt is not { } done
                || done <= now.AddHours(-policy.RescanHours);
            if (running is not null && !current.IsCompleted)
            {
                // A full scan in progress covers anything asked for; a change check gives way to a full scan.
                if (runningHash == hash && (runningFull || !full))
                    return;
                Stop();
            }
            if (state.ConfigHash != hash)
            {
                state = new(hash, null, []);
                Save();
            }
            if (full)
                Start(hash, true, ct => Run(policy, hash, null, ct));
            else
                Start(hash, false, ct => Check(policy, hash, ct));
        }
    }

    private void Start(string hash, bool full, Action<CancellationToken> work)
    {
        var cts = new CancellationTokenSource();
        running = cts;
        runningHash = hash;
        runningFull = full;
        current = Task.Factory.StartNew(
            () =>
            {
                try
                {
                    Thread.CurrentThread.Priority = ThreadPriority.Lowest;
                }
                catch (Exception ex) when (ex is PlatformNotSupportedException or ThreadStateException) { }
                // Disk reads too: a folder walk or a file table read waits behind what the user is doing.
                using (BackgroundIo.Enter())
                    try
                    {
                        work(cts.Token);
                    }
                    finally
                    {
                        Flush();
                    }
            },
            cts.Token,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default
        );
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

    /// <summary>Scans every target, or only the given scopes (with the rest of their volume when it is indexed).</summary>
    private void Run(SensitiveFilePolicy policy, string hash, HashSet<string>? only, CancellationToken ct)
    {
        IReadOnlyList<SensitiveScanTarget> list;
        try
        {
            list = targets(policy);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Left unfinished so the next agent cycle tries again.
            Publish(hash, new("machine", "Error", DateTimeOffset.UtcNow, Failure(ex), []));
            return;
        }
        try
        {
            foreach (var volume in list.GroupBy(t => VolumeOf(t.Root), StringComparer.OrdinalIgnoreCase))
            {
                var todo = volume.Where(t => only is null || only.Contains(t.Scope)).ToList();
                if (todo.Count == 0)
                    continue;
                foreach (var target in todo.Where(t => t.Unavailable is not null))
                    Publish(hash, new(target.Scope, "Unknown", DateTimeOffset.UtcNow, target.Unavailable, []));
                var walk = todo.Where(t => t.Unavailable is null).ToList();
                if (walk.Count == 0)
                    continue;
                // An indexed volume is read whole, so every scope on it is refreshed against the same journal position.
                walk = ScanIndexed(volume.Key, volume.Where(t => t.Unavailable is null).ToList(), policy, hash, ct)
                    is { } rest
                    ? rest.Where(walk.Contains).ToList()
                    : walk;
                foreach (var target in walk)
                {
                    SensitiveScopeResult result;
                    try
                    {
                        result = SensitiveFileWalker.Scan(target, policy, ownerOf, ct);
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        result = new(target.Scope, "Error", DateTimeOffset.UtcNow, Failure(ex), []);
                    }
                    Publish(hash, result);
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return;
        }
        if (only is null)
            Complete(hash, list.Select(t => t.Scope).ToHashSet(StringComparer.Ordinal));
    }

    /// <summary>
    /// Scans the targets on one volume from its index and records the journal position read from. Returns the
    /// targets left to walk (outside the index root), or null when the volume has no usable index.
    /// </summary>
    private List<SensitiveScanTarget>? ScanIndexed(
        string volume,
        List<SensitiveScanTarget> list,
        SensitiveFilePolicy policy,
        string hash,
        CancellationToken ct
    )
    {
        IVolumeIndex? index;
        try
        {
            index = volumes?.Invoke(volume);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Console.Error.WriteLine($"敏感文件扫描：{volume} 无法使用文件表（{ex.GetType().Name}），改为逐个目录扫描");
            index = null;
        }
        if (index is null)
        {
            SetCursor(hash, volume, null);
            return null;
        }
        using (index)
        {
            var indexRoot = SensitiveScopeRules.Full(index.Root);
            var inside = list.Where(t => SensitiveScopeRules.Under(SensitiveScopeRules.Full(t.Root), indexRoot))
                .ToList();
            try
            {
                var started = System.Diagnostics.Stopwatch.StartNew();
                // Taken first: changes made while the table is read are picked up by the next check.
                var cursor = index.Cursor() is { } c ? c with { Volume = volume } : null;
                var results = SensitiveIndexScan.Scan(index, inside, policy, ownerOf, ct, out var names);
                Console.WriteLine(
                    $"敏感文件扫描：{volume} 通过文件索引比对 {names} 个名称，用时 {started.Elapsed.TotalSeconds:F1} 秒"
                );
                foreach (var result in results)
                    Publish(hash, result with { Volume = cursor is null ? null : volume });
                SetCursor(hash, volume, cursor);
                return list.Except(inside).ToList();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Console.Error.WriteLine(
                    $"敏感文件扫描：读取 {volume} 文件表失败（{ex.GetType().Name}：{ex.Message}），改为逐个目录扫描"
                );
                SetCursor(hash, volume, null);
                return null;
            }
        }
    }

    /// <summary>
    /// Between full scans: rescans the volumes whose journal shows a matching name created, deleted or renamed, or a
    /// folder moved into view, and the scopes where a reported path no longer exists (moved away with its folder).
    /// Volumes without changes have their results confirmed as current.
    /// </summary>
    private void Check(SensitiveFilePolicy policy, string hash, CancellationToken ct)
    {
        IReadOnlyList<SensitiveScanTarget> list;
        try
        {
            list = targets(policy);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return;
        }
        SensitiveScanState seen;
        lock (gate)
            seen = state;
        if (!seen.Scopes.Select(s => s.Scope).ToHashSet().SetEquals(list.Select(t => t.Scope)))
        {
            // A user profile or drive was added or removed.
            Run(policy, hash, null, ct);
            return;
        }
        // A drive unlocked or a profile folder restored since the scan, or the reverse.
        var dirty = list.Where(t =>
                (t.Unavailable is null) == (seen.Scopes.First(s => s.Scope == t.Scope).Status == "Unknown")
            )
            .Select(t => t.Scope)
            .ToHashSet(StringComparer.Ordinal);
        var unchanged = new List<VolumeCursor>();
        try
        {
            foreach (var cursor in seen.Cursors ?? [])
            {
                var scopes = seen.Scopes.Where(s => s.Volume == cursor.Volume).Select(s => s.Scope).ToList();
                try
                {
                    using var index = volumes?.Invoke(cursor.Volume) ?? throw new JournalGoneException("磁盘不可用");
                    var (changes, next) = index.ChangesSince(cursor, ct);
                    var rules = new SensitiveScopeRules(
                        SensitiveIndexScan.Spelled(index, list.Where(t => t.Unavailable is null)),
                        policy
                    );
                    var seenBefore = new JournalContext(
                        changes.Where(c => (c.Reason & JournalReasons.Create) != 0).Select(c => c.Id).ToHashSet(),
                        changes
                            .Where(c => (c.Reason & JournalReasons.RenameOldName) != 0)
                            .GroupBy(c => c.Id)
                            .ToDictionary(g => g.Key, g => g.First())
                    );
                    if (changes.FirstOrDefault(c => Relevant(c, index, rules, seenBefore)) is { Name: not null } change)
                    {
                        Console.WriteLine($"敏感文件扫描：{cursor.Volume} 上的“{change.Name}”有变化，重新扫描");
                        dirty.UnionWith(scopes);
                    }
                    else
                        unchanged.Add(next);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    Console.WriteLine($"敏感文件扫描：{cursor.Volume} 的变更日志不可用（{ex.Message}），重新扫描");
                    dirty.UnionWith(scopes);
                }
            }
            foreach (var scope in seen.Scopes)
                if (scope.Evidence.Any(e => !File.Exists(e.ObjectKey) && !Directory.Exists(e.ObjectKey)))
                    dirty.Add(scope.Scope);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return;
        }
        lock (gate)
        {
            if (state.ConfigHash != hash)
                return;
            var now = DateTimeOffset.UtcNow;
            var confirmed = unchanged.Select(c => c.Volume).ToHashSet(StringComparer.OrdinalIgnoreCase);
            state = state with
            {
                Scopes = state
                    .Scopes.Select(s =>
                        s.Volume is { } v && confirmed.Contains(v) && !dirty.Contains(s.Scope)
                            ? s with
                            {
                                CollectedAt = now,
                            }
                            : s
                    )
                    .ToArray(),
                Cursors = (state.Cursors ?? []).Where(c => !confirmed.Contains(c.Volume)).Concat(unchanged).ToArray(),
            };
            Save();
        }
        if (dirty.Count > 0)
            Run(policy, hash, dirty, ct);
    }

    /// <summary>
    /// What the records since the last read say about a renamed folder's past: <see cref="Created"/> holds the ids
    /// created in this window, <see cref="OldNames"/> each renamed id's previous parent and name.
    /// </summary>
    private sealed record JournalContext(HashSet<ulong> Created, Dictionary<ulong, VolumeEntry> OldNames);

    /// <summary>A journal record that can change what the scan reports.</summary>
    private static bool Relevant(VolumeEntry change, IVolumeIndex index, SensitiveScopeRules rules, JournalContext past)
    {
        if ((change.Reason & JournalReasons.Names) == 0)
            return false;
        if (rules.Matcher.Match(change.Name, change.IsDirectory).Count > 0)
            return true;
        // A folder moved or renamed into view may hold matching names that were hidden (e.g. under node_modules).
        // Folders moved out of view are caught by the reported paths no longer existing.
        if (!change.IsDirectory || (change.Reason & JournalReasons.RenameNewName) == 0)
            return false;
        // Installers and updaters fill a new folder and then rename it into place; every name inside it has its own
        // record in this window and was checked above.
        if (past.Created.Contains(change.Id))
            return false;
        // A folder that was already in view (VS Code renames an old extension to "<name>.vsctmp" before deleting it)
        // shows nothing new. Reported paths under it no longer exist and cause a rescan by themselves.
        if (
            past.OldNames.TryGetValue(change.Id, out var old)
            && index.PathOf(old.ParentId) is { } oldParent
            && rules.Visible(Path.Join(oldParent, old.Name))
        )
            return false;
        return index.PathOf(change.ParentId) is { } parent && rules.Visible(Path.Join(parent, change.Name));
    }

    private static string VolumeOf(string root) =>
        Path.GetPathRoot(SensitiveScopeRules.Full(root)) is { Length: > 0 } volume ? volume : root;

    /// <summary>Replaces one scope's result.</summary>
    private void Publish(string hash, SensitiveScopeResult result)
    {
        lock (gate)
        {
            if (state.ConfigHash != hash)
                return;
            var scopes = state.Scopes.Where(s => s.Scope != result.Scope).Append(result).ToArray();
            state = state with { Scopes = scopes };
            Save();
            Interlocked.Increment(ref revision);
        }
        if (Environment.TickCount64 - Volatile.Read(ref savedAt) >= SaveEvery)
            Flush();
    }

    /// <summary>Marks a full scan finished and drops scopes that no longer exist (a removed drive).</summary>
    private void Complete(string hash, HashSet<string> keep)
    {
        lock (gate)
        {
            if (state.ConfigHash != hash)
                return;
            state = state with
            {
                CompletedAt = DateTimeOffset.UtcNow,
                Scopes = state.Scopes.Where(s => keep.Contains(s.Scope)).ToArray(),
            };
            Save();
            Interlocked.Increment(ref revision);
        }
    }

    private void SetCursor(string hash, string volume, VolumeCursor? cursor)
    {
        lock (gate)
        {
            if (state.ConfigHash != hash)
                return;
            var others = (state.Cursors ?? []).Where(c => !c.Volume.Equals(volume, StringComparison.OrdinalIgnoreCase));
            state = state with { Cursors = (cursor is null ? others : others.Append(cursor)).ToArray() };
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

    /// <summary>
    /// Marks the state changed. It is written when a scan or check ends, when the client stops, and at most every
    /// <see cref="SaveEvery"/> milliseconds in between, outside the lock: a power cut loses at most that much, which the
    /// next scan finds again.
    /// </summary>
    private void Save() => changes++;

    private const long SaveEvery = 30_000;
    private long changes;
    private long savedAt = Environment.TickCount64;
    private long written;
    private readonly Lock saving = new();

    private void Flush()
    {
        SensitiveScanState snapshot;
        long version;
        lock (gate)
        {
            if (changes == Volatile.Read(ref written))
                return;
            (snapshot, version) = (state, changes);
        }
        lock (saving)
        {
            // Another flush may have written a later state meanwhile.
            if (version <= written)
                return;
            Volatile.Write(ref savedAt, Environment.TickCount64);
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(statePath))!);
                var temp = statePath + ".tmp";
                File.WriteAllText(temp, Wire.Serialize(snapshot));
                File.Move(temp, statePath, true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Results still reach the server from memory; only a restart would repeat the scan.
                Console.Error.WriteLine("Sensitive file scan state not saved: " + ex.GetType().Name);
            }
            Volatile.Write(ref written, version);
        }
    }

    public void Dispose()
    {
        lock (gate)
            Stop();
        Flush();
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
