namespace Compliance.Core;

/// <summary>
/// USB storage control (<see cref="UsbPolicy"/>): which access a plugged-in disk gets, and the events clients send
/// about it. The events are keyed by the disk's instance id, so an administrator can copy one into the allowed list.
/// </summary>
public static class UsbStorage
{
    public const string Allow = "Allow";
    public const string ReadOnly = "ReadOnly";
    public const string Block = "Block";
    public static readonly string[] Modes = [Allow, ReadOnly, Block];

    /// <summary>A disk was plugged in (or was attached when the client started), with the access it was given.</summary>
    public const string Connected = "UsbConnected";

    /// <summary>A disk was removed.</summary>
    public const string Removed = "UsbRemoved";

    /// <summary>A disk was switched off because the policy forbids it; an alert for administrators.</summary>
    public const string Blocked = "UsbBlocked";

    public static readonly string[] EventTypes = [Connected, Removed, Blocked];

    public const string KeyPrefix = "usb:";
    public const int MaxAllowedDevices = 500;

    public static void Validate(UsbPolicy? policy)
    {
        if (policy is null || policy.AllowedDevices is null || !Modes.Contains(policy.Storage))
            throw new ArgumentException("移动存储配置不完整");
        if (policy.AllowedDevices.Length > MaxAllowedDevices)
            throw new ArgumentException($"放行的移动存储设备最多 {MaxAllowedDevices} 个");
        foreach (var d in policy.AllowedDevices)
            if (
                d is null
                || d.Id is null
                || d.Note is null
                || d.Id.Trim().Length is < 4 or > 200
                || d.Id.Trim() != d.Id
                || d.Note.Length > 200
            )
                throw new ArgumentException(
                    "放行设备无效：设备标识 4–200 个字符，前后不能有空格，备注不超过 200 个字符"
                );
        if (
            policy.AllowedDevices.Select(d => d.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count()
            != policy.AllowedDevices.Length
        )
            throw new ArgumentException("放行设备有重复的设备标识");
    }

    /// <summary>The allowed-list entry that covers the disk, if any.</summary>
    public static UsbAllowedDevice? Exemption(UsbPolicy policy, string instanceId) =>
        policy.AllowedDevices.FirstOrDefault(d => instanceId.Contains(d.Id, StringComparison.OrdinalIgnoreCase));

    /// <summary>The access the policy gives this disk: its storage setting, unless the disk is on the allowed list.</summary>
    public static string Access(UsbPolicy policy, string instanceId) =>
        Exemption(policy, instanceId) is null ? policy.Storage : Allow;

    public static string Label(string mode) =>
        mode switch
        {
            Allow => "可读写",
            ReadOnly => "只读",
            Block => "禁止使用",
            _ => mode,
        };

    public static string EventLabel(string type) =>
        type switch
        {
            Connected => "接入",
            Removed => "拔出",
            Blocked => "已拦截",
            _ => type,
        };
}
