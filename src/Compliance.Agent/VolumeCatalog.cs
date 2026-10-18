using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Compliance.Core;

namespace Compliance.Agent;

/// <summary>
/// Which file names a scan needs kept in the <see cref="VolumeCatalog"/>. Folders are always kept; a file is kept when
/// any wanted interest keeps its name. <see cref="Version"/> changes with the rules, and a volume read before an
/// interest's current version is read again, since names it now keeps were passed over.
/// </summary>
public sealed record VolumeInterest(string Version, Func<string, bool> Keep)
{
    public const string SensitiveFiles = "sensitive";
    public const string ProgramFiles = "programs";

    /// <summary>Names the sensitive file rules match; null when the scan is off.</summary>
    public static VolumeInterest? Sensitive(SensitiveFilePolicy policy)
    {
        if (!policy.Enabled || policy.Rules.Length == 0)
            return null;
        var matcher = new SensitiveNameMatcher(policy.Rules);
        return new(Hash(Wire.Serialize(policy.Rules)), name => matcher.Match(name, false).Count > 0);
    }

    /// <summary>The program file names of the product rules; null when none are named.</summary>
    public static VolumeInterest? Programs(PolicyDocument policy)
    {
        var names = policy
            .Products.SelectMany(r => r.ExecutableNames)
            .Where(n => n.Length > 0)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        return names.Count == 0
            ? null
            : new(Hash(string.Join('\n', names.Select(n => n.ToLowerInvariant()).Order())), names.Contains);
    }

    private static string Hash(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)))[..16];
}

/// <summary>
/// The file records of each volume, read once and kept in memory, then brought up to date from the change journal
/// whenever a scan asks for the volume. The program file scan and the sensitive file scan both read from here, so a
/// volume's file table is read when the client starts, when the journal no longer covers the gap, when the rules need
/// names that were passed over, and once a week to catch anything the journal missed; not on every scan.
/// Only folders and the names an interest keeps are held. Nothing is written to disk: sensitive file names stay in
/// memory. A volume without a journal, or with more than <see cref="MaxFolders"/> folders, is not held; scans read
/// it directly as before.
/// </summary>
public sealed class VolumeCatalog(Func<string, IVolumeIndex?> open, TimeProvider? clock = null)
{
    public const int MaxFolders = 2_000_000;
    public static readonly TimeSpan Reread = TimeSpan.FromDays(7);

    private readonly TimeProvider time = clock ?? TimeProvider.System;
    private readonly Lock gate = new();
    private readonly Dictionary<string, VolumeInterest> interests = [];
    private readonly Dictionary<string, Held> volumes = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Full reads of a file table since the client started; the logs and tests use it.</summary>
    public int Reads => Volatile.Read(ref reads);
    private int reads;

    /// <summary>
    /// Sets or (with null) drops what a scan needs kept. Set before scanning so one read serves every scan. Dropping
    /// the last lets go of every volume (up to a few hundred MB on large disks); dropping another keeps what is held,
    /// since the folders are needed anyway and the names only it kept are few.
    /// </summary>
    public void Want(string key, VolumeInterest? interest)
    {
        lock (gate)
        {
            if (interest is not null)
            {
                interests[key] = interest;
                return;
            }
            if (!interests.Remove(key) || interests.Count > 0)
                return;
            foreach (var held in volumes.Values)
                // A volume being scanned right now is let go of the next time nothing wants it.
                if (held.Busy.Wait(0))
                {
                    held.Clear();
                    held.Busy.Release();
                }
        }
    }

    /// <summary>Whether another scan is reading the volume's file table and none has been read yet.</summary>
    public bool FirstReadRunning(string volume)
    {
        lock (gate)
            return volumes.TryGetValue(volume, out var held)
                && held.Busy.CurrentCount == 0
                && held.Cursor is null
                && held.DirectUntil <= time.GetUtcNow();
    }

    /// <summary>
    /// The volume as of now, read from memory, or the volume itself when it cannot be held, or null when it cannot be
    /// opened. The view holds the volume until disposed: other scans of it wait.
    /// </summary>
    public IVolumeIndex? Open(string volume, CancellationToken ct = default)
    {
        Held held;
        Dictionary<string, VolumeInterest> wanted;
        lock (gate)
        {
            if (!volumes.TryGetValue(volume, out held!))
                volumes[volume] = held = new();
            wanted = new(interests);
        }
        held.Busy.Wait(ct);
        IVolumeIndex? index = null;
        try
        {
            index = open(volume);
            if (index is null)
            {
                held.Clear();
                held.Busy.Release();
                return null;
            }
            var now = time.GetUtcNow();
            if (held.DirectUntil > now)
            {
                held.Busy.Release();
                return index;
            }
            var keep = Keep(wanted.Values);
            if (!Refresh(held, index, wanted, keep, now, ct))
            {
                held.Busy.Release();
                return index;
            }
            return new View(index, held);
        }
        catch
        {
            index?.Dispose();
            held.Busy.Release();
            throw;
        }
    }

    private static Func<string, bool> Keep(IReadOnlyCollection<VolumeInterest> wanted)
    {
        var list = wanted.Select(i => i.Keep).ToArray();
        return name => list.Any(k => k(name));
    }

    /// <summary>Brings the held records up to date; false when the volume has to be read directly instead.</summary>
    private bool Refresh(
        Held held,
        IVolumeIndex index,
        Dictionary<string, VolumeInterest> wanted,
        Func<string, bool> keep,
        DateTimeOffset now,
        CancellationToken ct
    )
    {
        var built = wanted.All(w => held.BuiltFor.Contains(w.Key + ":" + w.Value.Version));
        if (held.Cursor is { } cursor && built && held.ReadAt + Reread > now && held.RootId == index.RootId)
        {
            try
            {
                var (changes, next) = index.ChangesSince(cursor, ct);
                Apply(held, changes, keep);
                held.Cursor = next;
                return true;
            }
            catch (JournalGoneException ex)
            {
                Console.WriteLine($"文件索引：{index.Root} 的变更日志不再连续（{ex.Message}），重新读取文件表");
            }
        }
        return Read(held, index, wanted, keep, now, ct);
    }

    private bool Read(
        Held held,
        IVolumeIndex index,
        Dictionary<string, VolumeInterest> wanted,
        Func<string, bool> keep,
        DateTimeOffset now,
        CancellationToken ct
    )
    {
        held.Clear();
        // Taken first: changes made while the table is read are applied from the journal next time.
        var cursor = index.Cursor();
        if (cursor is null)
        {
            Console.WriteLine($"文件索引：{index.Root} 没有变更日志，扫描时直接读取文件表");
            held.DirectUntil = now + Reread;
            return false;
        }
        var started = System.Diagnostics.Stopwatch.StartNew();
        var names = new Dictionary<string, string>(StringComparer.Ordinal);
        var count = 0;
        using (BackgroundIo.Enter())
            foreach (var entry in index.Entries(ct))
            {
                count++;
                if (entry.Id == index.RootId)
                    continue;
                if (entry.IsDirectory)
                {
                    if (held.Folders.Count >= MaxFolders)
                    {
                        held.Clear();
                        Console.WriteLine(
                            $"文件索引：{index.Root} 的文件夹超过 {MaxFolders} 个，不常驻内存，扫描时直接读取文件表"
                        );
                        held.DirectUntil = now + Reread;
                        return false;
                    }
                    held.Folders[entry.Id] = Shared(entry, names);
                }
                else if (keep(entry.Name))
                    held.Files[entry.Id] = Shared(entry, names);
            }
        Interlocked.Increment(ref reads);
        held.Cursor = cursor;
        held.RootId = index.RootId;
        held.ReadAt = now;
        held.BuiltFor = wanted.Select(w => w.Key + ":" + w.Value.Version).ToHashSet();
        Console.WriteLine(
            $"文件索引：读取 {index.Root} 文件表 {count} 条，保留 {held.Folders.Count} 个文件夹、{held.Files.Count} 个文件，用时 {started.Elapsed.TotalSeconds:F1} 秒"
        );
        return true;
    }

    /// <summary>Folder names repeat (src, node_modules, Debug); one copy of each is kept.</summary>
    private static VolumeEntry Shared(VolumeEntry entry, Dictionary<string, string> names)
    {
        if (!names.TryGetValue(entry.Name, out var name))
            names[entry.Name] = name = entry.Name;
        return entry with { Name = name, Reason = 0 };
    }

    /// <summary>
    /// Applies journal records in order. A folder renamed or moved keeps its id, so the names under it follow without
    /// a record of their own. Hard link changes are left to the weekly read: a record names one link of several.
    /// </summary>
    internal static void Apply(Held held, IEnumerable<VolumeEntry> changes, Func<string, bool> keep)
    {
        foreach (var change in changes)
        {
            if ((change.Reason & (JournalReasons.Delete | JournalReasons.RenameOldName)) != 0)
            {
                held.Folders.Remove(change.Id);
                held.Files.Remove(change.Id);
                if ((change.Reason & JournalReasons.Delete) != 0)
                    continue;
            }
            if ((change.Reason & (JournalReasons.Create | JournalReasons.RenameNewName)) == 0)
                continue;
            var entry = change with { Reason = 0 };
            if (entry.IsDirectory)
                held.Folders[entry.Id] = entry;
            else if (keep(entry.Name))
                held.Files[entry.Id] = entry;
            else
                held.Files.Remove(entry.Id);
        }
    }

    internal sealed class Held
    {
        public readonly SemaphoreSlim Busy = new(1, 1);
        public Dictionary<ulong, VolumeEntry> Folders = [];
        public Dictionary<ulong, VolumeEntry> Files = [];
        public VolumeCursor? Cursor;
        public ulong RootId;
        public DateTimeOffset ReadAt;
        public DateTimeOffset DirectUntil;
        public HashSet<string> BuiltFor = [];

        public void Clear()
        {
            Folders = [];
            Files = [];
            Cursor = null;
            BuiltFor = [];
        }
    }

    /// <summary>
    /// The held records of one volume. Names and the journal position come from memory; the journal itself, paths of
    /// folders by id and canonical spellings are asked of the volume, which stays open until the view is disposed.
    /// </summary>
    private sealed class View(IVolumeIndex volume, Held held) : IVolumeIndex
    {
        private int disposed;

        public string Root => volume.Root;
        public ulong RootId => volume.RootId;

        public VolumeCursor? Cursor() => held.Cursor;

        public bool HoldsFolders => true;

        public bool TryFolder(ulong id, out VolumeEntry folder) => held.Folders.TryGetValue(id, out folder);

        public IEnumerable<VolumeEntry> Entries(CancellationToken ct)
        {
            foreach (var folder in held.Folders.Values)
                yield return folder;
            foreach (var file in held.Files.Values)
                yield return file;
        }

        public (List<VolumeEntry> Changes, VolumeCursor Next) ChangesSince(VolumeCursor since, CancellationToken ct) =>
            volume.ChangesSince(since, ct);

        public string? PathOf(ulong id) => volume.PathOf(id);

        public string? Canonical(string path) => volume.Canonical(path);

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) == 1)
                return;
            volume.Dispose();
            held.Busy.Release();
        }
    }
}

/// <summary>
/// Puts the current thread in Windows' background mode, where its disk and memory requests wait behind everyone
/// else's, until disposed. Does nothing elsewhere, or when the thread is already in background mode.
/// </summary>
public static class BackgroundIo
{
    private const int ModeBegin = 0x00010000;
    private const int ModeEnd = 0x00020000;

    public static IDisposable Enter() =>
        OperatingSystem.IsWindows() && SetThreadPriority(GetCurrentThread(), ModeBegin) ? new Mode() : new None();

    private sealed class Mode : IDisposable
    {
        public void Dispose() => SetThreadPriority(GetCurrentThread(), ModeEnd);
    }

    private sealed class None : IDisposable
    {
        public void Dispose() { }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetThreadPriority(IntPtr thread, int priority);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentThread();
}
