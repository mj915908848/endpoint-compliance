using Compliance.Core;

namespace Compliance.Server;

public sealed partial class Transaction
{
    // ---- USB storage records --------------------------------------------------------------

    /// <summary>Keeps one USB storage event a device sent; <paramref name="id"/> makes a retried event a no-op.</summary>
    public Task InsertUsbEvent(
        string id,
        string deviceId,
        DateTimeOffset at,
        string type,
        string instanceId,
        string detail
    ) =>
        Execute(
            """
            INSERT INTO usb_events(id, device_id, at, type, instance_id, detail)
            VALUES(@id, @device, @at, @type, @instance, @detail) ON CONFLICT(id) DO NOTHING
            """,
            ("id", id),
            ("device", deviceId),
            ("at", at),
            ("type", type),
            ("instance", instanceId),
            ("detail", detail)
        );

    /// <summary>
    /// USB storage records since <paramref name="since"/>, newest first: of one device, or of every device in use.
    /// </summary>
    public Task<List<UsbEventRow>> UsbEvents(DateTimeOffset since, string? deviceId, int limit) =>
        Query(
            $"""
            SELECT d.id, d.host_name, d.note, d.group_name, u.at, u.type, u.instance_id, u.detail
            FROM usb_events u JOIN devices d ON d.id = u.device_id
            WHERE u.at >= @since AND {(deviceId is null ? "d.archived_at IS NULL" : "u.device_id = @device")}
            ORDER BY u.at DESC, u.id LIMIT @limit
            """,
            r => new UsbEventRow(
                r.GetString(0),
                r.GetString(1),
                r.GetString(2),
                r.GetString(3),
                Time(r, 4),
                r.GetString(5),
                r.GetString(6),
                r.GetString(7)
            ),
            ("since", since),
            ("device", deviceId ?? ""),
            ("limit", (long)limit)
        );

    public Task<int> PruneUsbEvents(DateTimeOffset cutoff, int limit) =>
        Execute(
            "DELETE FROM usb_events WHERE id IN (SELECT id FROM usb_events WHERE at < @cutoff LIMIT @limit)",
            ("cutoff", cutoff),
            ("limit", (long)limit)
        );
}
