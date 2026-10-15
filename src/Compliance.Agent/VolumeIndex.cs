using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Compliance.Core;
using Microsoft.Win32.SafeHandles;

namespace Compliance.Agent;

/// <summary>
/// One file or folder record of a volume: its id, its parent folder's id and its own name. For a change record,
/// <see cref="Reason"/> holds the journal's change flags.
/// </summary>
public readonly record struct VolumeEntry(
    ulong Id,
    ulong ParentId,
    string Name,
    FileAttributes Attributes,
    uint Reason = 0
)
{
    public bool IsDirectory => (Attributes & FileAttributes.Directory) != 0;
}

/// <summary>Position in a volume's change journal; changes after it are read on the next check.</summary>
public sealed record VolumeCursor(string Volume, ulong JournalId, long NextUsn);

/// <summary>The change journal no longer holds every change since a cursor (wrapped, deleted or recreated).</summary>
public sealed class JournalGoneException(string message) : Exception(message);

/// <summary>Change flags of journal records (USN_REASON_*) that can add, remove or move a name.</summary>
public static class JournalReasons
{
    public const uint Create = 0x100;
    public const uint Delete = 0x200;
    public const uint HardLinkChange = 0x10000;
    public const uint RenameOldName = 0x1000;
    public const uint RenameNewName = 0x2000;
    public const uint Names = Create | Delete | HardLinkChange | RenameOldName | RenameNewName;
}

/// <summary>
/// A volume whose file records can be listed without opening folders, and whose changes can be read since a cursor.
/// On Windows this is the NTFS master file table and USN change journal.
/// </summary>
public interface IVolumeIndex : IDisposable
{
    /// <summary>Path of the folder <see cref="RootId"/> names, e.g. "D:\".</summary>
    string Root { get; }
    ulong RootId { get; }

    /// <summary>The current end of the change journal, or null when the volume keeps none.</summary>
    VolumeCursor? Cursor();

    IEnumerable<VolumeEntry> Entries(CancellationToken ct);

    /// <summary>Names created, deleted or renamed since <paramref name="since"/>, and the cursor to continue from.</summary>
    (List<VolumeEntry> Changes, VolumeCursor Next) ChangesSince(VolumeCursor since, CancellationToken ct);

    /// <summary>The current path of a folder, or null when it no longer exists.</summary>
    string? PathOf(ulong id);

    /// <summary>A path as the volume spells it (long names rather than 8.3 short names), or null when it does not exist.</summary>
    string? Canonical(string path);
}

/// <summary>
/// Scans the targets on one volume from its file records instead of walking folders: every name is read in one
/// sequential pass, only folders and matching names are kept, and each match is placed by following its parent ids.
/// Reports the same paths as <see cref="SensitiveFileWalker"/>.
/// </summary>
public static class SensitiveIndexScan
{
    private readonly record struct Folder(ulong Parent, string Name, bool Linked);

    /// <summary>The targets with their folders in the volume's own spelling.</summary>
    public static List<SensitiveScanTarget> Spelled(IVolumeIndex index, IEnumerable<SensitiveScanTarget> targets) =>
        targets
            .Select(t =>
                t with
                {
                    Root = index.Canonical(t.Root) ?? t.Root,
                    SkipPaths = t.SkipPaths.Select(p => index.Canonical(p) ?? p).ToArray(),
                }
            )
            .ToList();

    public static SensitiveScopeResult[] Scan(
        IVolumeIndex index,
        IReadOnlyList<SensitiveScanTarget> targets,
        SensitiveFilePolicy policy,
        Func<string, string?>? ownerOf,
        CancellationToken ct,
        out int names
    )
    {
        // Matched against the volume's own spelling of the target folders; reported in the targets' spelling.
        var spelled = targets.ToDictionary(t => t.Scope, t => t.Root);
        targets = Spelled(index, targets);
        var rules = new SensitiveScopeRules(targets, policy);
        var folders = new Dictionary<ulong, Folder>();
        var candidates = new List<VolumeEntry>();
        names = 0;
        foreach (var entry in index.Entries(ct))
        {
            names++;
            if (entry.Id == index.RootId)
                continue;
            if (entry.IsDirectory)
                folders[entry.Id] = new(
                    entry.ParentId,
                    entry.Name,
                    (entry.Attributes & FileAttributes.ReparsePoint) != 0
                );
            if (rules.Matcher.Match(entry.Name, entry.IsDirectory).Count > 0)
                candidates.Add(entry);
        }

        var paths = new Dictionary<ulong, string?> { [index.RootId] = SensitiveScopeRules.Full(index.Root) };
        string? PathOf(ulong id)
        {
            var chain = new List<ulong>();
            string? path = null;
            while (!paths.TryGetValue(id, out path))
            {
                // Records still being written, or a loop in damaged metadata, leave the name unplaced.
                if (!folders.TryGetValue(id, out var folder) || chain.Count > 4096)
                    break;
                chain.Add(id);
                id = folder.Parent;
            }
            for (var i = chain.Count - 1; i >= 0; i--)
                paths[chain[i]] = path = path is null ? null : Path.Join(path, folders[chain[i]].Name);
            return path;
        }

        var hits = targets.ToDictionary(
            t => t.Scope,
            _ => new List<(string Path, List<SensitiveNameMatch> Matches, bool Folder)>()
        );
        foreach (var candidate in candidates)
        {
            ct.ThrowIfCancellationRequested();
            if (PathOf(candidate.ParentId) is not { } parent)
                continue;
            var path = Path.Join(parent, candidate.Name);
            if (rules.TargetOf(path) is not var (target, root))
                continue;
            var between = new List<(string Name, string Path, bool Linked)>();
            for (
                var id = candidate.ParentId;
                id != index.RootId && folders.TryGetValue(id, out var folder);
                id = folder.Parent
            )
            {
                var folderPath = paths[id]!;
                if (folderPath.Equals(root, StringComparison.OrdinalIgnoreCase))
                    break;
                between.Add((folder.Name, folderPath, folder.Linked));
            }
            between.Reverse();
            if (rules.Match(target, between, candidate.Name, path, candidate.IsDirectory) is { } matches)
                // Reported in the target root's spelling, as the folder walk does.
                hits[target.Scope]
                    .Add(
                        (
                            Path.Join(spelled[target.Scope], path[root.Length..].TrimStart('\\', '/')),
                            matches,
                            candidate.IsDirectory
                        )
                    );
        }

        return targets
            .Select(target =>
            {
                var found = hits[target.Scope].OrderBy(h => h.Path, StringComparer.OrdinalIgnoreCase).ToList();
                var original = target with { Root = spelled[target.Scope] };
                var listed = found
                    .Take(policy.MaxHitsPerScope)
                    .Select(h => SensitiveScopeRules.Hit(original, h.Path, h.Matches, h.Folder, ownerOf))
                    .ToList();
                return SensitiveScopeRules.Result(original, listed, found.Count, 0, null);
            })
            .ToArray();
    }
}

/// <summary>
/// An NTFS volume read through its master file table (FSCTL_ENUM_USN_DATA) and USN change journal
/// (FSCTL_READ_USN_JOURNAL), as desktop search tools do. Needs administrator rights, which the service has.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class NtfsVolume : IVolumeIndex
{
    private const uint FsctlEnumUsnData = 0x000900B3;
    private const uint FsctlReadUsnJournal = 0x000900BB;
    private const uint FsctlQueryUsnJournal = 0x000900F4;
    private const uint FsctlCreateUsnJournal = 0x000900E7;
    private const int ErrorHandleEof = 38;
    private const int ErrorJournalDeleteInProgress = 1178;
    private const int ErrorJournalNotActive = 1179;
    private const int ErrorJournalEntryDeleted = 1181;
    private const uint GenericRead = 0x80000000;
    private const uint FileReadAttributes = 0x80;
    private const uint ShareAll = 7;
    private const uint OpenExisting = 3;
    private const uint BackupSemantics = 0x02000000;

    private readonly SafeFileHandle volume;
    private readonly SafeFileHandle root;

    public string Root { get; }
    public ulong RootId { get; }

    /// <summary>The index of a local NTFS volume, or null (with the reason logged) when it cannot be read this way.</summary>
    public static IVolumeIndex? TryOpen(string volumeRoot)
    {
        try
        {
            var drive = new DriveInfo(volumeRoot);
            if (!drive.IsReady || drive.DriveFormat != "NTFS")
                return null;
            return new NtfsVolume(drive.RootDirectory.FullName);
        }
        catch (Exception ex)
            when (ex is IOException or UnauthorizedAccessException or Win32Exception or ArgumentException)
        {
            Console.Error.WriteLine(
                $"敏感文件扫描：无法打开 {volumeRoot} 的 NTFS 文件表（{ex.GetType().Name}：{ex.Message}）"
            );
            return null;
        }
    }

    private NtfsVolume(string rootPath)
    {
        Root = rootPath;
        volume = Open(@"\\.\" + rootPath.TrimEnd('\\'), GenericRead);
        try
        {
            root = Open(rootPath, FileReadAttributes);
            if (!GetFileInformationByHandle(root, out var info))
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            RootId = (ulong)info.FileIndexHigh << 32 | info.FileIndexLow;
        }
        catch
        {
            volume.Dispose();
            root?.Dispose();
            throw;
        }
    }

    public VolumeCursor? Cursor()
    {
        var data = new byte[80];
        if (!Control(FsctlQueryUsnJournal, null, data, out _))
        {
            var error = Marshal.GetLastPInvokeError();
            if (error is not (ErrorJournalNotActive or ErrorJournalDeleteInProgress))
                throw new Win32Exception(error);
            // Windows keeps a journal on the system drive; data drives may have none. Search indexers create one the
            // same way; Windows manages its size and it holds names only.
            var create = new byte[16];
            BinaryPrimitives.WriteUInt64LittleEndian(create, 32UL << 20);
            BinaryPrimitives.WriteUInt64LittleEndian(create.AsSpan(8), 8UL << 20);
            if (
                !Control(FsctlCreateUsnJournal, create, null, out _)
                || !Control(FsctlQueryUsnJournal, null, data, out _)
            )
                return null;
        }
        return new(
            Root,
            BinaryPrimitives.ReadUInt64LittleEndian(data),
            BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(16))
        );
    }

    public IEnumerable<VolumeEntry> Entries(CancellationToken ct)
    {
        // MFT_ENUM_DATA_V0: start at record 0, every USN.
        var input = new byte[24];
        BinaryPrimitives.WriteInt64LittleEndian(input.AsSpan(16), long.MaxValue);
        var buffer = new byte[1 << 20];
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            if (!Control(FsctlEnumUsnData, input, buffer, out var returned))
            {
                var error = Marshal.GetLastPInvokeError();
                if (error == ErrorHandleEof)
                    yield break;
                throw new Win32Exception(error);
            }
            foreach (var entry in Records(buffer, returned))
                yield return entry;
            Buffer.BlockCopy(buffer, 0, input, 0, 8);
        }
    }

    public (List<VolumeEntry> Changes, VolumeCursor Next) ChangesSince(VolumeCursor since, CancellationToken ct)
    {
        var end = Cursor() ?? throw new JournalGoneException("变更日志未启用");
        if (end.JournalId != since.JournalId)
            throw new JournalGoneException("变更日志已重建");
        var changes = new List<VolumeEntry>();
        // READ_USN_JOURNAL_DATA_V0: no waiting, records for name changes only.
        var input = new byte[40];
        BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(8), JournalReasons.Names);
        BinaryPrimitives.WriteUInt64LittleEndian(input.AsSpan(32), since.JournalId);
        var buffer = new byte[1 << 16];
        var usn = since.NextUsn;
        while (usn < end.NextUsn)
        {
            ct.ThrowIfCancellationRequested();
            BinaryPrimitives.WriteInt64LittleEndian(input, usn);
            if (!Control(FsctlReadUsnJournal, input, buffer, out var returned))
            {
                var error = Marshal.GetLastPInvokeError();
                if (error is ErrorJournalEntryDeleted or ErrorJournalNotActive or ErrorJournalDeleteInProgress)
                    throw new JournalGoneException("变更日志已覆盖上次读取的位置");
                throw new Win32Exception(error);
            }
            var next = BinaryPrimitives.ReadInt64LittleEndian(buffer);
            changes.AddRange(Records(buffer, returned));
            if (next <= usn)
                break;
            usn = next;
        }
        return (changes, since with { NextUsn = usn });
    }

    public string? PathOf(ulong id)
    {
        var descriptor = new FileIdDescriptor { Size = 24, FileId = (long)id };
        using var handle = OpenFileById(
            root,
            ref descriptor,
            FileReadAttributes,
            ShareAll,
            IntPtr.Zero,
            BackupSemantics
        );
        return FinalPath(handle);
    }

    public string? Canonical(string path)
    {
        using var handle = CreateFileW(
            path,
            FileReadAttributes,
            ShareAll,
            IntPtr.Zero,
            OpenExisting,
            BackupSemantics,
            IntPtr.Zero
        );
        return FinalPath(handle) is { } final ? SensitiveScopeRules.Full(final) : null;
    }

    private static string? FinalPath(SafeFileHandle handle)
    {
        if (handle.IsInvalid)
            return null;
        var buffer = new char[1024];
        var length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, 0);
        if (length > buffer.Length)
        {
            buffer = new char[length];
            length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, 0);
        }
        if (length == 0 || length > buffer.Length)
            return null;
        var path = new string(buffer, 0, (int)length);
        return
            path.StartsWith(@"\\?\", StringComparison.Ordinal)
            && !path.StartsWith(@"\\?\UNC\", StringComparison.Ordinal)
            ? path[4..]
            : path;
    }

    /// <summary>USN_RECORD_V2 entries following the 8-byte header of an enumeration or journal read.</summary>
    private static List<VolumeEntry> Records(byte[] buffer, int length)
    {
        var list = new List<VolumeEntry>();
        for (var offset = 8; offset + 60 <= length; )
        {
            var record = buffer.AsSpan(offset, length - offset);
            var size = (int)BinaryPrimitives.ReadUInt32LittleEndian(record);
            if (size < 60 || size > record.Length)
                break;
            if (BinaryPrimitives.ReadUInt16LittleEndian(record[4..]) == 2)
            {
                var nameLength = BinaryPrimitives.ReadUInt16LittleEndian(record[56..]);
                var nameOffset = BinaryPrimitives.ReadUInt16LittleEndian(record[58..]);
                if (nameOffset + nameLength <= size)
                    list.Add(
                        new(
                            BinaryPrimitives.ReadUInt64LittleEndian(record[8..]),
                            BinaryPrimitives.ReadUInt64LittleEndian(record[16..]),
                            Encoding.Unicode.GetString(record.Slice(nameOffset, nameLength)),
                            (FileAttributes)BinaryPrimitives.ReadUInt32LittleEndian(record[52..]),
                            BinaryPrimitives.ReadUInt32LittleEndian(record[40..])
                        )
                    );
            }
            offset += size;
        }
        return list;
    }

    private bool Control(uint code, byte[]? input, byte[]? output, out int returned) =>
        DeviceIoControl(
            volume,
            code,
            input,
            input?.Length ?? 0,
            output,
            output?.Length ?? 0,
            out returned,
            IntPtr.Zero
        );

    private static SafeFileHandle Open(string path, uint access)
    {
        var handle = CreateFileW(path, access, ShareAll, IntPtr.Zero, OpenExisting, BackupSemantics, IntPtr.Zero);
        if (handle.IsInvalid)
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        return handle;
    }

    public void Dispose()
    {
        root.Dispose();
        volume.Dispose();
    }

    // FILETIME members are 4-byte aligned.
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public ulong CreationTime;
        public ulong LastAccessTime;
        public ulong LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Explicit, Size = 24)]
    private struct FileIdDescriptor
    {
        [FieldOffset(0)]
        public uint Size;

        [FieldOffset(4)]
        public uint Type;

        [FieldOffset(8)]
        public long FileId;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFileW(
        string name,
        uint access,
        uint share,
        IntPtr security,
        uint disposition,
        uint flags,
        IntPtr template
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle device,
        uint code,
        byte[]? input,
        int inputSize,
        byte[]? output,
        int outputSize,
        out int returned,
        IntPtr overlapped
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation info);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeFileHandle OpenFileById(
        SafeFileHandle volumeHint,
        ref FileIdDescriptor id,
        uint access,
        uint share,
        IntPtr security,
        uint flags
    );

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, char[] path, uint length, uint flags);
}
