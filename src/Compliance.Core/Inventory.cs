using System.Globalization;

namespace Compliance.Core;

/// <summary>
/// What a device is and what is installed on it. The client sends it after a full check when it changed, and at least
/// once a day; administrators use it to know their hardware and software without walking to each PC.
/// </summary>
/// <param name="Software">Programs registered for uninstall (Apps &amp; Features), machine-wide and per signed-in user.</param>
public record AssetInventory(
    DateTimeOffset CollectedAt,
    HardwareInfo Hardware,
    OperatingSystemInfo OperatingSystem,
    DiskInfo[] Disks,
    VolumeInfo[] Volumes,
    InstalledProgram[] Software
);

/// <param name="MemoryBytes">Installed physical memory.</param>
public record HardwareInfo(
    string Manufacturer,
    string Model,
    string SerialNumber,
    string BiosVersion,
    string Processor,
    int Cores,
    int LogicalProcessors,
    long MemoryBytes
);

/// <param name="Version">The full build, such as 10.0.22631.4317, which changes with each monthly update.</param>
/// <param name="DisplayVersion">The feature release, such as 23H2.</param>
public record OperatingSystemInfo(
    string Name,
    string Version,
    string DisplayVersion,
    string Architecture,
    DateTimeOffset? InstalledAt,
    DateTimeOffset? LastBootAt
);

/// <param name="MediaType">SSD, HDD, or empty when Windows does not say.</param>
public record DiskInfo(string Model, long SizeBytes, string MediaType, string BusType);

/// <param name="Name">The drive, such as C:.</param>
public record VolumeInfo(string Name, string Label, string FileSystem, long SizeBytes, long FreeBytes);

/// <param name="InstalledOn">The install date as the installer recorded it (yyyy-MM-dd), or empty.</param>
/// <param name="Scope">"machine" for every user, otherwise the account the program is installed for.</param>
public record InstalledProgram(string Name, string Version, string Publisher, string InstalledOn, string Scope);

/// <summary>
/// One difference between two inventories of a device.
/// </summary>
/// <param name="Kind">SoftwareInstalled, SoftwareRemoved, SoftwareUpdated, HardwareChanged or SystemUpdated.</param>
/// <param name="Subject">The program, or the part of the device, that changed.</param>
public record InventoryChange(DateTimeOffset At, string Kind, string Subject, string Detail);

public static class Inventory
{
    public const int MaxSoftware = 5000;
    public const int MaxDisks = 64;
    public const int MaxChanges = 300;
    const int MaxText = 256;

    public const string Machine = "machine";

    /// <summary>
    /// Cleaned text, bounded sizes, one entry per program, version and scope, and a fixed order, so the same device
    /// gives the same inventory and differences mean something changed.
    /// </summary>
    public static AssetInventory Normalize(AssetInventory inventory)
    {
        static string T(string? value)
        {
            var text = EvidenceSanitizer.Clean(value).Trim();
            return text.Length > MaxText ? text[..MaxText] : text;
        }
        var h = inventory.Hardware;
        var os = inventory.OperatingSystem;
        return inventory with
        {
            Hardware = new(
                T(h.Manufacturer),
                T(h.Model),
                T(h.SerialNumber),
                T(h.BiosVersion),
                T(h.Processor),
                Math.Max(0, h.Cores),
                Math.Max(0, h.LogicalProcessors),
                Math.Max(0, h.MemoryBytes)
            ),
            OperatingSystem = new(
                T(os.Name),
                T(os.Version),
                T(os.DisplayVersion),
                T(os.Architecture),
                os.InstalledAt,
                os.LastBootAt
            ),
            Disks =
            [
                .. inventory
                    .Disks.Take(MaxDisks)
                    .Select(d => new DiskInfo(T(d.Model), Math.Max(0, d.SizeBytes), T(d.MediaType), T(d.BusType)))
                    .OrderBy(d => d.Model, StringComparer.Ordinal)
                    .ThenBy(d => d.SizeBytes),
            ],
            Volumes =
            [
                .. inventory
                    .Volumes.Take(MaxDisks)
                    .Select(v => new VolumeInfo(
                        T(v.Name),
                        T(v.Label),
                        T(v.FileSystem),
                        Math.Max(0, v.SizeBytes),
                        Math.Clamp(v.FreeBytes, 0, Math.Max(0, v.SizeBytes))
                    ))
                    .OrderBy(v => v.Name, StringComparer.Ordinal),
            ],
            Software =
            [
                .. inventory
                    .Software.Select(p => new InstalledProgram(
                        T(p.Name),
                        T(p.Version),
                        T(p.Publisher),
                        ValidDate(p.InstalledOn),
                        T(p.Scope) is { Length: > 0 } scope ? scope : Machine
                    ))
                    .Where(p => p.Name.Length > 0)
                    .DistinctBy(p => (p.Name, p.Version, p.Scope))
                    .OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(p => p.Scope, StringComparer.Ordinal)
                    .ThenBy(p => p.Version, StringComparer.Ordinal)
                    .Take(MaxSoftware),
            ],
        };
    }

    /// <summary>A yyyy-MM-dd date, from that form or the yyyyMMdd installers record; anything else is dropped.</summary>
    public static string ValidDate(string? value)
    {
        var text = value?.Trim() ?? "";
        foreach (var format in new[] { "yyyy-MM-dd", "yyyyMMdd" })
            if (
                DateTime.TryParseExact(text, format, CultureInfo.InvariantCulture, DateTimeStyles.None, out var date)
                && date.Year >= 1990
            )
                return date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        return "";
    }

    /// <summary>
    /// What changed from <paramref name="before"/> to <paramref name="after"/>, both normalized. Programs are matched by
    /// name and the account they are installed for; at most <see cref="MaxChanges"/> are returned, the last saying how
    /// many more there were.
    /// </summary>
    public static List<InventoryChange> Changes(AssetInventory before, AssetInventory after, DateTimeOffset at)
    {
        var changes = new List<InventoryChange>();
        void Add(string kind, string subject, string detail) => changes.Add(new(at, kind, subject, detail));
        static string Where(string scope) => scope == Machine ? "" : $"（用户 {scope}）";

        var (os1, os2) = (before.OperatingSystem, after.OperatingSystem);
        if (os1.Name != os2.Name || os1.Version != os2.Version)
            Add("SystemUpdated", "操作系统", $"{SystemText(os1)} → {SystemText(os2)}");

        var (h1, h2) = (before.Hardware, after.Hardware);
        void Part(string subject, string a, string b)
        {
            if (a != b)
                Add("HardwareChanged", subject, $"{Or(a)} → {Or(b)}");
        }
        Part("主机型号", $"{h1.Manufacturer} {h1.Model}".Trim(), $"{h2.Manufacturer} {h2.Model}".Trim());
        Part("序列号", h1.SerialNumber, h2.SerialNumber);
        Part("处理器", h1.Processor, h2.Processor);
        Part("内存", Bytes(h1.MemoryBytes), Bytes(h2.MemoryBytes));
        Part("硬盘", DisksText(before.Disks), DisksText(after.Disks));

        static Dictionary<(string, string), InstalledProgram[]> ByProgram(AssetInventory i) =>
            i.Software.GroupBy(p => (p.Name, p.Scope)).ToDictionary(g => g.Key, g => g.ToArray());
        static string Versions(InstalledProgram[] p) =>
            string.Join("、", p.Select(x => x.Version).Where(v => v.Length > 0).Distinct());
        var (old, current) = (ByProgram(before), ByProgram(after));
        foreach (var (key, programs) in current.OrderBy(x => x.Key.Item1, StringComparer.OrdinalIgnoreCase))
        {
            var version = Versions(programs);
            if (!old.TryGetValue(key, out var was))
                Add("SoftwareInstalled", key.Item1, Join(version, Where(key.Item2)));
            else if (Versions(was) != version)
                Add("SoftwareUpdated", key.Item1, $"{Or(Versions(was))} → {Or(version)}{Where(key.Item2)}");
        }
        foreach (
            var (key, programs) in old.Where(x => !current.ContainsKey(x.Key))
                .OrderBy(x => x.Key.Item1, StringComparer.OrdinalIgnoreCase)
        )
            Add("SoftwareRemoved", key.Item1, Join(Versions(programs), Where(key.Item2)));

        if (changes.Count > MaxChanges)
        {
            var more = changes.Count - (MaxChanges - 1);
            changes.RemoveRange(MaxChanges - 1, changes.Count - (MaxChanges - 1));
            Add("SoftwareUpdated", "其他变更", $"另有 {more} 项变更未逐条记录");
        }
        return changes;
    }

    public static string SystemText(OperatingSystemInfo os) =>
        string.Join(" ", new[] { os.Name, os.DisplayVersion, os.Version }.Where(x => x.Length > 0));

    static string DisksText(DiskInfo[] disks) =>
        string.Join(
            "；",
            disks.Select(d => string.Join(" ", new[] { d.Model, Bytes(d.SizeBytes) }.Where(x => x.Length > 0)))
        );

    /// <summary>A size as people say it: 16 GB, 512 GB, 1 TB (powers of 1024, rounded).</summary>
    public static string Bytes(long bytes)
    {
        if (bytes <= 0)
            return "";
        const double GB = 1024d * 1024 * 1024;
        var gb = bytes / GB;
        return gb >= 1000 ? $"{gb / 1024:0.#} TB"
            : gb >= 10 ? $"{gb:0} GB"
            : $"{gb:0.#} GB";
    }

    static string Or(string text) => text.Length > 0 ? text : "无";

    static string Join(string version, string where) => (version.Length > 0 ? "版本 " + version : "") + where;
}
