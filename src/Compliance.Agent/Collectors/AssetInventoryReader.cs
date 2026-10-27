using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Compliance.Core;
using Microsoft.Win32;

namespace Compliance.Agent;

/// <summary>
/// Reads the device's hardware, Windows version, disks and installed programs for the asset inventory (see
/// <see cref="AssetInventory"/>). Each part that cannot be read is left empty rather than failing the rest.
/// </summary>
public static class AssetInventoryReader
{
    /// <summary>One program's entry under an Uninstall registry key, with only the values the inventory looks at.</summary>
    public sealed record UninstallEntry(
        string? DisplayName,
        string? DisplayVersion,
        string? Publisher,
        string? InstallDate,
        bool SystemComponent,
        string? ParentKeyName,
        string? ReleaseType,
        string Scope
    );

    /// <summary>
    /// The programs Apps &amp; Features lists: entries with a name, without Windows' own components and without updates
    /// registered under the program they patch.
    /// </summary>
    public static InstalledProgram[] Programs(IEnumerable<UninstallEntry> entries) =>
        [
            .. entries
                .Where(e =>
                    !string.IsNullOrWhiteSpace(e.DisplayName)
                    && !e.SystemComponent
                    && string.IsNullOrEmpty(e.ParentKeyName)
                    && e.ReleaseType is not ("Update" or "Hotfix" or "Security Update" or "Service Pack")
                )
                .Select(e => new InstalledProgram(
                    e.DisplayName!.Trim(),
                    e.DisplayVersion?.Trim() ?? "",
                    e.Publisher?.Trim() ?? "",
                    Inventory.ValidDate(e.InstallDate),
                    e.Scope
                )),
        ];

    [SupportedOSPlatform("windows")]
    public static AssetInventory Read() =>
        Inventory.Normalize(
            new(DateTimeOffset.UtcNow, Hardware(), OperatingSystem(), Disks(), Volumes(), Programs(Uninstall()))
        );

    [SupportedOSPlatform("windows")]
    static ManagementBaseObject[] Wmi(string query, string scope = @"root\CIMV2")
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(scope, query);
            return [.. searcher.Get().Cast<ManagementBaseObject>()];
        }
        catch (Exception e) when (e is ManagementException or COMException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    static string S(object? value) => value?.ToString()?.Trim() ?? "";

    static long N(object? value) =>
        value switch
        {
            null => 0,
            IConvertible c => Convert.ToInt64(c, System.Globalization.CultureInfo.InvariantCulture),
            _ => 0,
        };

    [SupportedOSPlatform("windows")]
    static HardwareInfo Hardware()
    {
        var system = Wmi("SELECT Manufacturer, Model, TotalPhysicalMemory FROM Win32_ComputerSystem").FirstOrDefault();
        var bios = Wmi("SELECT SerialNumber, SMBIOSBIOSVersion FROM Win32_BIOS").FirstOrDefault();
        var processors = Wmi("SELECT Name, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor");
        // Installed memory, which TotalPhysicalMemory understates by what the firmware and graphics reserve.
        var modules = Wmi("SELECT Capacity FROM Win32_PhysicalMemory").Sum(m => N(m["Capacity"]));
        return new(
            S(system?["Manufacturer"]),
            S(system?["Model"]),
            SerialNumber(S(bios?["SerialNumber"])),
            S(bios?["SMBIOSBIOSVersion"]),
            string.Join("；", processors.Select(p => S(p["Name"])).Where(n => n.Length > 0).Distinct()),
            (int)processors.Sum(p => N(p["NumberOfCores"])),
            (int)processors.Sum(p => N(p["NumberOfLogicalProcessors"])),
            modules > 0 ? modules : N(system?["TotalPhysicalMemory"])
        );
    }

    /// <summary>Firmware placeholders such as "To be filled by O.E.M." or "Default string" are not serial numbers.</summary>
    public static string SerialNumber(string value) =>
        value.Length < 3
        || value.Contains("O.E.M", StringComparison.OrdinalIgnoreCase)
        || value.Equals("Default string", StringComparison.OrdinalIgnoreCase)
        || value.Equals("System Serial Number", StringComparison.OrdinalIgnoreCase)
        || value.All(c => c is '0' or ' ')
            ? ""
            : value;

    [SupportedOSPlatform("windows")]
    static OperatingSystemInfo OperatingSystem()
    {
        var os = Wmi("SELECT Caption, Version, OSArchitecture, InstallDate, LastBootUpTime FROM Win32_OperatingSystem")
            .FirstOrDefault();
        using var current = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
        var version = S(os?["Version"]);
        // The update revision is what changes with each monthly update.
        if (current?.GetValue("UBR") is int ubr && version.Length > 0)
            version += "." + ubr;
        return new(
            S(os?["Caption"]).Replace("Microsoft ", ""),
            version,
            S(current?.GetValue("DisplayVersion") ?? current?.GetValue("ReleaseId")),
            S(os?["OSArchitecture"]),
            WmiTime(os?["InstallDate"]),
            WmiTime(os?["LastBootUpTime"])
        );
    }

    static DateTimeOffset? WmiTime(object? value)
    {
        if (value is not string text || text.Length < 14)
            return null;
        try
        {
            return new DateTimeOffset(ManagementDateTimeConverter.ToDateTime(text)).ToUniversalTime();
        }
        catch (Exception e) when (e is ArgumentException or FormatException)
        {
            return null;
        }
    }

    [SupportedOSPlatform("windows")]
    static DiskInfo[] Disks()
    {
        var disks = Wmi(
            "SELECT FriendlyName, Size, MediaType, BusType FROM MSFT_PhysicalDisk",
            @"root\Microsoft\Windows\Storage"
        );
        if (disks.Length > 0)
            return
            [
                .. disks.Select(d => new DiskInfo(
                    S(d["FriendlyName"]),
                    N(d["Size"]),
                    N(d["MediaType"]) switch
                    {
                        3 => "HDD",
                        4 => "SSD",
                        5 => "SCM",
                        _ => "",
                    },
                    N(d["BusType"]) switch
                    {
                        7 => "USB",
                        11 => "SATA",
                        17 => "NVMe",
                        8 => "RAID",
                        10 => "SAS",
                        _ => "",
                    }
                )),
            ];
        // Windows before 8 has no storage namespace.
        return
        [
            .. Wmi("SELECT Model, Size, InterfaceType FROM Win32_DiskDrive")
                .Select(d => new DiskInfo(S(d["Model"]), N(d["Size"]), "", S(d["InterfaceType"]))),
        ];
    }

    static VolumeInfo[] Volumes()
    {
        var volumes = new List<VolumeInfo>();
        foreach (var drive in DriveInfo.GetDrives())
            try
            {
                if (drive.DriveType == DriveType.Fixed && drive.IsReady)
                    volumes.Add(
                        new(
                            drive.Name.TrimEnd('\\'),
                            drive.VolumeLabel,
                            drive.DriveFormat,
                            drive.TotalSize,
                            drive.AvailableFreeSpace
                        )
                    );
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        return [.. volumes];
    }

    /// <summary>
    /// Uninstall entries machine-wide (64- and 32-bit views) and for each user whose registry hive is loaded, that is
    /// who is signed in or has a service running as them.
    /// </summary>
    [SupportedOSPlatform("windows")]
    static IEnumerable<UninstallEntry> Uninstall()
    {
        const string Path = @"Software\Microsoft\Windows\CurrentVersion\Uninstall";
        var entries = new List<UninstallEntry>();
        void Read(RegistryKey? key, string scope)
        {
            if (key is null)
                return;
            foreach (var name in key.GetSubKeyNames())
                try
                {
                    using var e = key.OpenSubKey(name);
                    if (e is null)
                        continue;
                    entries.Add(
                        new(
                            e.GetValue("DisplayName") as string,
                            e.GetValue("DisplayVersion") as string,
                            e.GetValue("Publisher") as string,
                            e.GetValue("InstallDate") as string,
                            e.GetValue("SystemComponent") is int system && system == 1,
                            e.GetValue("ParentKeyName") as string,
                            e.GetValue("ReleaseType") as string,
                            scope
                        )
                    );
                }
                catch (Exception ex)
                    when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException) { }
        }
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var key = root.OpenSubKey(Path);
            Read(key, Inventory.Machine);
        }
        using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
        foreach (var sid in users.GetSubKeyNames().Where(s => s.StartsWith("S-1-5-21-") && !s.EndsWith("_Classes")))
        {
            using var key = users.OpenSubKey(sid + "\\" + Path);
            Read(key, Account(sid));
        }
        return entries;
    }

    [SupportedOSPlatform("windows")]
    static string Account(string sid)
    {
        try
        {
            var name = new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value;
            // DOMAIN\user reads as the user.
            return name[(name.LastIndexOf('\\') + 1)..];
        }
        catch (Exception e) when (e is IdentityNotMappedException or SystemException)
        {
            return sid;
        }
    }
}
