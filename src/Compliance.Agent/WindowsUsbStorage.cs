using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Compliance.Agent;

/// <summary>
/// USB disks through the Configuration Manager: disk drives (USB sticks, card readers, USB and UAS external drives)
/// whose parent device is on the USB bus. Switching off is Device Manager's "Disable device", until the disk is
/// unplugged or Windows restarts; read-only is the disk's own attribute, not kept across a restart, after which the
/// disk's volumes are dismounted so Windows mounts them again with it.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsUsbStorage : IUsbStorage
{
    const string DiskDriveClass = "{4d36e967-e325-11ce-bfc1-08002be10318}";
    static readonly Guid DiskInterface = new("53f56307-b6bf-11d0-94f2-00a0c91efb8b");

    public bool CanControl { get; } = WindowsIdentity.GetCurrent().IsSystem;

    public IReadOnlyList<UsbDisk> Attached()
    {
        var disks = new List<UsbDisk>();
        foreach (var id in DeviceIds(DiskDriveClass))
        {
            if (CM_Locate_DevNodeW(out var node, id, 0) != Success)
                continue;
            if (CM_Get_Parent(out var parent, node, 0) != Success || DeviceId(parent) is not { } parentId)
                continue;
            if (!parentId.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase))
                continue;
            var disabled =
                CM_Get_DevNode_Status(out var status, out var problem, node, 0) == Success
                && (status & HasProblem) != 0
                && problem == ProblemDisabled;
            long size = 0;
            var readOnly = false;
            if (!disabled && DiskPath(id) is { } path)
            {
                try
                {
                    using var disk = Open(path, GenericRead);
                    size = Length(disk);
                    readOnly = (Attributes(disk) & ReadOnlyAttribute) != 0;
                }
                catch (Win32Exception) { }
            }
            disks.Add(
                new(
                    id,
                    Property(node, FriendlyName) ?? Property(node, DeviceDescription) ?? "",
                    Serial(id, parentId),
                    size,
                    disabled,
                    readOnly
                )
            );
        }
        return disks;
    }

    /// <summary>
    /// The serial number the stick reports: the last part of its USB id, which Windows makes up (with an "&amp;") for
    /// sticks without one.
    /// </summary>
    public static string Serial(string instanceId, string parentId)
    {
        var last = parentId[(parentId.LastIndexOf('\\') + 1)..];
        if (last.Length > 0 && !last.Contains('&'))
            return last;
        last = instanceId[(instanceId.LastIndexOf('\\') + 1)..];
        var cut = last.LastIndexOf('&');
        last = cut > 0 ? last[..cut] : last;
        return last.Contains('&') ? "" : last;
    }

    public void Disable(string instanceId)
    {
        var result = CM_Disable_DevNode(Locate(instanceId), DisableUiNotOk);
        if (result == RemoveVetoed)
            throw new InvalidOperationException("设备正在使用中，关闭其中打开的文件后会再次尝试");
        Check(result, "停用设备");
    }

    public void Enable(string instanceId) => Check(CM_Enable_DevNode(Locate(instanceId), 0), "启用设备");

    public void SetReadOnly(string instanceId, bool readOnly)
    {
        var path = DiskPath(instanceId) ?? throw new InvalidOperationException("找不到该磁盘");
        using var disk = Open(path, GenericRead | GenericWrite);
        var set = new SetDiskAttributes
        {
            Version = (uint)Marshal.SizeOf<SetDiskAttributes>(),
            Persist = 0,
            Attributes = readOnly ? ReadOnlyAttribute : 0,
            AttributesMask = ReadOnlyAttribute,
        };
        if (!DeviceIoControl(disk, SetDiskAttributesIoctl, ref set, set.Version, IntPtr.Zero, 0, out _, IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        // Volumes already mounted keep writing until Windows mounts them again.
        if (Number(disk) is { } number)
            Dismount(number);
    }

    static uint Locate(string instanceId)
    {
        Check(CM_Locate_DevNodeW(out var node, instanceId, 0), "查找设备");
        return node;
    }

    static void Check(int result, string what)
    {
        if (result != Success)
            throw new InvalidOperationException($"{what}失败（CONFIGRET 0x{result:X2}）");
    }

    static List<string> DeviceIds(string classGuid)
    {
        for (var attempt = 0; attempt < 5; attempt++)
        {
            if (CM_Get_Device_ID_List_SizeW(out var length, classGuid, FilterClass | FilterPresent) != Success)
                return [];
            var buffer = new char[length];
            var result = CM_Get_Device_ID_ListW(classGuid, buffer, length, FilterClass | FilterPresent);
            if (result == BufferSmall)
                continue;
            return result == Success ? Split(buffer) : [];
        }
        return [];
    }

    static string? DiskPath(string instanceId)
    {
        var guid = DiskInterface;
        for (var attempt = 0; attempt < 5; attempt++)
        {
            if (CM_Get_Device_Interface_List_SizeW(out var length, ref guid, instanceId, 0) != Success)
                return null;
            var buffer = new char[length];
            var result = CM_Get_Device_Interface_ListW(ref guid, instanceId, buffer, length, 0);
            if (result == BufferSmall)
                continue;
            return result == Success ? Split(buffer).FirstOrDefault() : null;
        }
        return null;
    }

    static List<string> Split(char[] multi) =>
        [.. new string(multi).Split('\0', StringSplitOptions.RemoveEmptyEntries)];

    static string? DeviceId(uint node)
    {
        if (CM_Get_Device_ID_Size(out var length, node, 0) != Success)
            return null;
        var buffer = new char[length + 1];
        return CM_Get_Device_IDW(node, buffer, (uint)buffer.Length, 0) == Success
            ? new string(buffer, 0, (int)length)
            : null;
    }

    static string? Property(uint node, uint property)
    {
        uint length = 0;
        CM_Get_DevNode_Registry_PropertyW(node, property, out _, null, ref length, 0);
        if (length == 0)
            return null;
        var buffer = new byte[length];
        if (CM_Get_DevNode_Registry_PropertyW(node, property, out _, buffer, ref length, 0) != Success)
            return null;
        var text = System.Text.Encoding.Unicode.GetString(buffer, 0, (int)length).TrimEnd('\0').Trim();
        return text.Length > 0 ? text : null;
    }

    static SafeFileHandle Open(string path, uint access)
    {
        var handle = CreateFileW(path, access, ShareReadWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        if (handle.IsInvalid)
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        return handle;
    }

    static long Length(SafeFileHandle disk) =>
        DeviceIoControl(disk, GetLengthInfo, IntPtr.Zero, 0, out long length, 8, out _, IntPtr.Zero) ? length : 0;

    static ulong Attributes(SafeFileHandle disk) =>
        DeviceIoControl(disk, GetDiskAttributesIoctl, IntPtr.Zero, 0, out GetDiskAttributes a, 16, out _, IntPtr.Zero)
            ? a.Attributes
            : 0;

    static uint? Number(SafeFileHandle disk) =>
        DeviceIoControl(disk, GetDeviceNumber, IntPtr.Zero, 0, out StorageDeviceNumber n, 12, out _, IntPtr.Zero)
            ? n.DeviceNumber
            : null;

    /// <summary>Dismounts every volume that lies on the disk; Windows mounts them again on the next access.</summary>
    static void Dismount(uint diskNumber)
    {
        var name = new char[MaxPath];
        using var find = FindFirstVolumeW(name, (uint)name.Length);
        if (find.IsInvalid)
            return;
        do
        {
            var end = Array.IndexOf(name, '\0');
            var volume = new string(name, 0, end < 0 ? name.Length : end).TrimEnd('\\');
            try
            {
                using var handle = Open(volume, GenericRead | GenericWrite);
                var extents = new byte[8 + 24 * 8];
                if (
                    !DeviceIoControl(
                        handle,
                        GetVolumeDiskExtents,
                        IntPtr.Zero,
                        0,
                        extents,
                        (uint)extents.Length,
                        out _,
                        IntPtr.Zero
                    )
                )
                    continue;
                var count = BitConverter.ToUInt32(extents, 0);
                var onDisk = Enumerable
                    .Range(0, (int)Math.Min(count, 8))
                    .Any(i => BitConverter.ToUInt32(extents, 8 + 24 * i) == diskNumber);
                if (onDisk)
                {
                    // A lock lets open files close cleanly; without it the dismount still goes ahead.
                    DeviceIoControl(handle, LockVolume, IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero);
                    DeviceIoControl(handle, DismountVolume, IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero);
                }
            }
            catch (Win32Exception) { }
        } while (FindNextVolumeW(find, name, (uint)name.Length));
    }

    const int Success = 0;
    const int BufferSmall = 0x1A;
    const int RemoveVetoed = 0x17;
    const uint FilterPresent = 0x100;
    const uint FilterClass = 0x200;
    const uint DisableUiNotOk = 0x4;
    const uint HasProblem = 0x400;
    const uint ProblemDisabled = 22;
    const uint DeviceDescription = 0x1;
    const uint FriendlyName = 0xD;
    const uint GenericRead = 0x80000000;
    const uint GenericWrite = 0x40000000;
    const uint ShareReadWrite = 0x3;
    const uint OpenExisting = 3;
    const int MaxPath = 260;
    const ulong ReadOnlyAttribute = 0x2;
    const uint GetLengthInfo = 0x7405C;
    const uint GetDiskAttributesIoctl = 0x700F0;
    const uint SetDiskAttributesIoctl = 0x7C0F4;
    const uint GetDeviceNumber = 0x2D1080;
    const uint GetVolumeDiskExtents = 0x560000;
    const uint LockVolume = 0x90018;
    const uint DismountVolume = 0x90020;

    [StructLayout(LayoutKind.Sequential)]
    struct GetDiskAttributes
    {
        public uint Version;
        public uint Reserved;
        public ulong Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SetDiskAttributes
    {
        public uint Version;
        public byte Persist;
        public byte Reserved1a;
        public byte Reserved1b;
        public byte Reserved1c;
        public ulong Attributes;
        public ulong AttributesMask;
        public uint Reserved2a;
        public uint Reserved2b;
        public uint Reserved2c;
        public uint Reserved2d;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct StorageDeviceNumber
    {
        public uint DeviceType;
        public uint DeviceNumber;
        public uint PartitionNumber;
    }

    sealed class SafeFindVolumeHandle() : SafeHandleZeroOrMinusOneIsInvalid(true)
    {
        protected override bool ReleaseHandle() => FindVolumeClose(handle);
    }

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    static extern int CM_Get_Device_ID_List_SizeW(out uint length, string filter, uint flags);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    static extern int CM_Get_Device_ID_ListW(string filter, char[] buffer, uint length, uint flags);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    static extern int CM_Locate_DevNodeW(out uint node, string id, uint flags);

    [DllImport("cfgmgr32.dll")]
    static extern int CM_Get_Parent(out uint parent, uint node, uint flags);

    [DllImport("cfgmgr32.dll")]
    static extern int CM_Get_Device_ID_Size(out uint length, uint node, uint flags);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    static extern int CM_Get_Device_IDW(uint node, char[] buffer, uint length, uint flags);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    static extern int CM_Get_DevNode_Registry_PropertyW(
        uint node,
        uint property,
        out uint type,
        byte[]? buffer,
        ref uint length,
        uint flags
    );

    [DllImport("cfgmgr32.dll")]
    static extern int CM_Get_DevNode_Status(out uint status, out uint problem, uint node, uint flags);

    [DllImport("cfgmgr32.dll")]
    static extern int CM_Disable_DevNode(uint node, uint flags);

    [DllImport("cfgmgr32.dll")]
    static extern int CM_Enable_DevNode(uint node, uint flags);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    static extern int CM_Get_Device_Interface_List_SizeW(out uint length, ref Guid cls, string id, uint flags);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    static extern int CM_Get_Device_Interface_ListW(ref Guid cls, string id, char[] buffer, uint length, uint flags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFileW(
        string name,
        uint access,
        uint share,
        IntPtr security,
        uint disposition,
        uint flags,
        IntPtr template
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(
        SafeFileHandle device,
        uint code,
        IntPtr input,
        uint inputLength,
        out long output,
        uint outputLength,
        out uint returned,
        IntPtr overlapped
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(
        SafeFileHandle device,
        uint code,
        IntPtr input,
        uint inputLength,
        out GetDiskAttributes output,
        uint outputLength,
        out uint returned,
        IntPtr overlapped
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(
        SafeFileHandle device,
        uint code,
        IntPtr input,
        uint inputLength,
        out StorageDeviceNumber output,
        uint outputLength,
        out uint returned,
        IntPtr overlapped
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(
        SafeFileHandle device,
        uint code,
        ref SetDiskAttributes input,
        uint inputLength,
        IntPtr output,
        uint outputLength,
        out uint returned,
        IntPtr overlapped
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(
        SafeFileHandle device,
        uint code,
        IntPtr input,
        uint inputLength,
        byte[] output,
        uint outputLength,
        out uint returned,
        IntPtr overlapped
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(
        SafeFileHandle device,
        uint code,
        IntPtr input,
        uint inputLength,
        IntPtr output,
        uint outputLength,
        out uint returned,
        IntPtr overlapped
    );

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFindVolumeHandle FindFirstVolumeW(char[] name, uint length);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool FindNextVolumeW(SafeFindVolumeHandle find, char[] name, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool FindVolumeClose(IntPtr find);
}
