using Compliance.Core;

namespace Compliance.Agent;

/// <param name="InstanceId">The disk's Windows device instance id, such as USBSTOR\DISK&amp;VEN_SANDISK&amp;...\4C53...&amp;0.</param>
/// <param name="Disabled">Switched off in Device Manager, by this client or anyone else.</param>
/// <param name="ReadOnly">Writes are refused at the disk.</param>
public record UsbDisk(
    string InstanceId,
    string Name,
    string Serial,
    long SizeBytes,
    bool Disabled = false,
    bool ReadOnly = false
);

/// <summary>The USB disks attached to the computer, and the switches the client uses on them.</summary>
public interface IUsbStorage
{
    /// <summary>Whether the client can switch disks off and make them read-only (it runs as SYSTEM).</summary>
    bool CanControl { get; }

    /// <summary>Every USB disk attached now, including switched-off ones.</summary>
    IReadOnlyList<UsbDisk> Attached();

    void Disable(string instanceId);
    void Enable(string instanceId);
    void SetReadOnly(string instanceId, bool readOnly);
}

/// <param name="Type">One of <see cref="UsbStorage.EventTypes"/>.</param>
/// <param name="Notice">What the signed-in user is told, if anything.</param>
public record UsbEvent(string Type, string InstanceId, string Detail, string? Notice = null);

/// <summary>
/// "移动存储管控": gives each USB disk the access the policy allows, every time it is checked (every 2 seconds), and
/// says when disks come and go. In audit mode, or without the measure required, disks are left alone and the events
/// say what the policy would have done. The client undoes only what it did itself, which it remembers in
/// <paramref name="statePath"/>: a disk switched off in Device Manager by someone else stays off.
/// </summary>
public sealed class UsbGuard(IUsbStorage storage, string statePath)
{
    const int MaxRemembered = 200;

    /// <param name="Disabled">Disks this client switched off, kept after they are removed: they may come back off.</param>
    /// <param name="ReadOnly">Attached disks this client made read-only.</param>
    /// <param name="Seen">The disks attached at the last check, so a restart does not report them as plugged in again.</param>
    record Owned(List<string> Disabled, List<string> ReadOnly, Dictionary<string, UsbDisk> Seen);

    Owned? state;
    string? lastFailure;
    int blockedCount;
    (string Name, DateTimeOffset At)? lastBlocked;

    Owned Load()
    {
        try
        {
            if (DurableFile.Exists(statePath))
                if (
                    DurableFile.Read(statePath, Wire.Read<Owned>) is
                    { Disabled: not null, ReadOnly: not null, Seen: not null } o
                )
                    return o with { Seen = new(o.Seen, StringComparer.OrdinalIgnoreCase) };
        }
        catch (Exception e) when (e is IOException or System.Text.Json.JsonException) { }
        return new([], [], new(StringComparer.OrdinalIgnoreCase));
    }

    void Save(Owned owned)
    {
        if (owned.Disabled.Count > MaxRemembered)
            owned.Disabled.RemoveRange(0, owned.Disabled.Count - MaxRemembered);
        DurableFile.Write(statePath, Wire.Serialize(owned));
    }

    static bool Has(List<string> ids, string id) => ids.Contains(id, StringComparer.OrdinalIgnoreCase);

    static void Drop(List<string> ids, string id) =>
        ids.RemoveAll(x => string.Equals(x, id, StringComparison.OrdinalIgnoreCase));

    /// <summary>The disk as an administrator recognizes it: its name, size and serial number.</summary>
    public static string Describe(UsbDisk disk)
    {
        var facts = new[]
        {
            Inventory.Bytes(disk.SizeBytes),
            disk.Serial.Length > 0 ? "序列号 " + disk.Serial : "",
        }.Where(x => x.Length > 0);
        var name = disk.Name.Length > 0 ? disk.Name : "USB 存储设备";
        return facts.Any() ? $"{name}（{string.Join("，", facts)}）" : name;
    }

    /// <summary>Applies the policy to the attached disks and returns what happened since the last call.</summary>
    public List<UsbEvent> Sweep(PolicyDocument policy)
    {
        var events = new List<UsbEvent>();
        var enforced = Controls.Enforced(policy, Controls.Usb) && storage.CanControl;
        var disks = storage.Attached();
        var owned = state ??= Load();
        var seen = owned.Seen;
        var changed = false;
        lastFailure = null;
        foreach (var disk in disks)
        {
            var id = disk.InstanceId;
            var isNew = !seen.ContainsKey(id);
            var wanted = UsbStorage.Access(policy.Usb, id);
            var access = enforced ? wanted : UsbStorage.Allow;
            var describe = Describe(disk);
            var current = disk;
            var switchedOff = false;
            try
            {
                if (access == UsbStorage.Block && !disk.Disabled)
                {
                    // Claimed before switching: if the client stops right after, the disk must not look like someone
                    // else's when the policy later allows it again.
                    if (!Has(owned.Disabled, id))
                    {
                        owned.Disabled.Add(id);
                        Save(owned);
                    }
                    storage.Disable(id);
                    current = disk with { Disabled = true };
                    switchedOff = true;
                }
                else if (access != UsbStorage.Block && disk.Disabled && Has(owned.Disabled, id))
                {
                    storage.Enable(id);
                    Drop(owned.Disabled, id);
                    Save(owned);
                    current = disk with { Disabled = false };
                }

                if (access == UsbStorage.ReadOnly && !current.Disabled && !current.ReadOnly)
                {
                    if (!Has(owned.ReadOnly, id))
                    {
                        owned.ReadOnly.Add(id);
                        Save(owned);
                    }
                    storage.SetReadOnly(id, true);
                    current = current with { ReadOnly = true };
                }
                else if (access != UsbStorage.ReadOnly && current.ReadOnly && Has(owned.ReadOnly, id))
                {
                    storage.SetReadOnly(id, false);
                    Drop(owned.ReadOnly, id);
                    Save(owned);
                    current = current with { ReadOnly = false };
                }
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                lastFailure = $"{describe} 无法设为“{UsbStorage.Label(access)}”：{e.Message}";
            }

            // Plugged in again while still switched off from before counts as blocked too.
            if (switchedOff || isNew && access == UsbStorage.Block && current.Disabled)
            {
                blockedCount++;
                lastBlocked = (disk.Name, DateTimeOffset.UtcNow);
                events.Add(
                    new(
                        UsbStorage.Blocked,
                        id,
                        $"{describe}：单位策略禁止使用 U 盘和移动硬盘，已停用该设备",
                        $"Blocked: {describe} 已停用：单位策略禁止使用 U 盘和移动硬盘"
                    )
                );
            }
            else if (isNew)
            {
                var state = current.Disabled
                    ? "已停用"
                    : UsbStorage.Label(current.ReadOnly ? UsbStorage.ReadOnly : UsbStorage.Allow);
                var why =
                    UsbStorage.Exemption(policy.Usb, id) is { } exempt
                        ? $"，已放行（{(exempt.Note.Length > 0 ? exempt.Note : exempt.Id)}）"
                    : !enforced && wanted != UsbStorage.Allow ? $"，策略为“{UsbStorage.Label(wanted)}”，未启用强制执行"
                    : "";
                events.Add(
                    new(
                        UsbStorage.Connected,
                        id,
                        $"{describe}，{state}{why}",
                        current.ReadOnly && Has(owned.ReadOnly, id)
                            ? $"Blocked: {describe} 只能读取：单位策略禁止向 U 盘和移动硬盘写入文件"
                            : null
                    )
                );
            }
            if (!seen.TryGetValue(id, out var was) || was != current)
            {
                seen[id] = current;
                changed = true;
            }
        }

        var attached = disks.Select(d => d.InstanceId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var gone in seen.Keys.Where(id => !attached.Contains(id)).ToArray())
        {
            events.Add(new(UsbStorage.Removed, gone, Describe(seen[gone])));
            seen.Remove(gone);
            // Read-only is set for as long as the disk stays attached; a switched-off disk may come back switched off.
            Drop(owned.ReadOnly, gone);
            changed = true;
        }
        if (changed)
            Save(owned);
        return events;
    }

    /// <summary>
    /// Switches back on and makes writable the attached disks this client changed, for the MSI to run when the client
    /// is uninstalled; null when that worked.
    /// </summary>
    public string? RemoveOwn()
    {
        var owned = Load();
        var problems = new List<string>();
        foreach (var disk in storage.Attached())
        {
            try
            {
                if (disk.Disabled && Has(owned.Disabled, disk.InstanceId))
                    storage.Enable(disk.InstanceId);
                if (disk.ReadOnly && Has(owned.ReadOnly, disk.InstanceId))
                    storage.SetReadOnly(disk.InstanceId, false);
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                problems.Add($"{Describe(disk)}：{e.Message}");
            }
        }
        if (problems.Count == 0)
            Save(state = new([], [], new(StringComparer.OrdinalIgnoreCase)));
        return problems.Count == 0 ? null : "未能恢复移动存储设备：" + string.Join("；", problems);
    }

    public ControlState State(PolicyDocument policy)
    {
        if (policy.Usb.Storage == UsbStorage.Allow)
            return new(Controls.Usb, policy.Serial, "Uncovered", "策略允许使用 U 盘和移动硬盘，无需管控");
        if (!storage.CanControl)
            return new(Controls.Usb, policy.Serial, "Uncovered", "客户端未以系统权限运行，无法停用设备或设为只读");
        var label = UsbStorage.Label(policy.Usb.Storage);
        var allowed = policy.Usb.AllowedDevices.Length;
        var exempt = allowed > 0 ? $"，放行 {allowed} 个设备" : "";
        if (!Controls.Enforced(policy, Controls.Usb))
            return new(
                Controls.Usb,
                policy.Serial,
                "Ready",
                $"可启用：强制模式下 U 盘和移动硬盘将{label}{exempt}",
                true
            );
        if (lastFailure is not null)
            return new(Controls.Usb, policy.Serial, "Error", lastFailure);
        var detail = $"已生效：U 盘和移动硬盘{label}{exempt}，每 2 秒检查一次";
        if (lastBlocked is { } last)
            detail += $"，已停用 {blockedCount} 次，最近一次 {last.Name}（{last.At.ToLocalTime():MM-dd HH:mm}）";
        return new(Controls.Usb, policy.Serial, "Applied", detail, true);
    }
}

/// <summary>
/// The USB disks of a simulated device, from usb.json next to its fixture: a list of <see cref="UsbDisk"/>, read on
/// every check so a demo can plug and remove disks by editing it. Switching them is only remembered.
/// </summary>
public sealed class FixtureUsbStorage(string path) : IUsbStorage
{
    readonly Dictionary<string, (bool Disabled, bool ReadOnly)> switched = new(StringComparer.OrdinalIgnoreCase);

    public bool CanControl => true;

    public IReadOnlyList<UsbDisk> Attached()
    {
        if (!File.Exists(path))
            return [];
        var disks = Wire.Read<UsbDisk[]>(File.ReadAllText(path)) ?? [];
        return
        [
            .. disks.Select(d =>
                switched.TryGetValue(d.InstanceId, out var s)
                    ? d with
                    {
                        Disabled = s.Disabled,
                        ReadOnly = s.ReadOnly,
                    }
                    : d
            ),
        ];
    }

    (bool Disabled, bool ReadOnly) Current(string id) =>
        switched.GetValueOrDefault(
            id,
            Attached().FirstOrDefault(d => d.InstanceId == id) is { } d ? (d.Disabled, d.ReadOnly) : default
        );

    public void Disable(string instanceId) => switched[instanceId] = Current(instanceId) with { Disabled = true };

    public void Enable(string instanceId) => switched[instanceId] = Current(instanceId) with { Disabled = false };

    public void SetReadOnly(string instanceId, bool readOnly) =>
        switched[instanceId] = Current(instanceId) with { ReadOnly = readOnly };
}
