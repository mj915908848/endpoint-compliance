using System.Data.Common;
using Compliance.Core;

namespace Compliance.Server;

public sealed partial class Transaction
{
    // ---- asset inventory -----------------------------------------------------------------

    const int SoftwareRowsPerInsert = 100;

    /// <summary>A device's latest inventory and when it arrived.</summary>
    public async Task<(AssetInventory Inventory, DateTimeOffset ReceivedAt)?> GetInventory(string deviceId)
    {
        var head = await Query(
            "SELECT hardware, received_at FROM device_inventory WHERE device_id = @id",
            r => (Wire.Read<AssetInventory>(r.GetString(0)), Time(r, 1)),
            ("id", deviceId)
        );
        if (head.Count == 0)
            return null;
        var software = await Query(
            "SELECT name, version, publisher, installed_on, scope FROM device_software WHERE device_id = @id",
            r => new InstalledProgram(r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4)),
            ("id", deviceId)
        );
        var (inventory, received) = head[0];
        return (
            inventory with
            {
                Software =
                [
                    .. software
                        .OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
                        .ThenBy(p => p.Scope, StringComparer.Ordinal)
                        .ThenBy(p => p.Version, StringComparer.Ordinal),
                ],
            },
            received
        );
    }

    /// <summary>Replaces a device's inventory with <paramref name="inventory"/>, already normalized.</summary>
    public async Task PutInventory(string deviceId, AssetInventory inventory, DateTimeOffset receivedAt)
    {
        await Execute(
            """
            INSERT INTO device_inventory(device_id, collected_at, received_at, hardware, software_count)
            VALUES(@id, @collected, @received, @hardware, @count)
            ON CONFLICT(device_id) DO UPDATE SET collected_at = excluded.collected_at,
                received_at = excluded.received_at, hardware = excluded.hardware, software_count = excluded.software_count
            """,
            ("id", deviceId),
            ("collected", inventory.CollectedAt),
            ("received", receivedAt),
            ("hardware", Wire.Serialize(inventory with { Software = [] })),
            ("count", (long)inventory.Software.Length)
        );
        await Execute("DELETE FROM device_software WHERE device_id = @id", ("id", deviceId));
        foreach (var chunk in inventory.Software.Chunk(SoftwareRowsPerInsert))
        {
            var args = new List<(string, object?)> { ("id", deviceId) };
            var rows = new List<string>();
            for (var i = 0; i < chunk.Length; i++)
            {
                var p = chunk[i];
                rows.Add($"(@id, @n{i}, @v{i}, @p{i}, @d{i}, @s{i})");
                args.AddRange([
                    ("n" + i, p.Name),
                    ("v" + i, p.Version),
                    ("p" + i, p.Publisher),
                    ("d" + i, p.InstalledOn),
                    ("s" + i, p.Scope),
                ]);
            }
            await Execute(
                "INSERT INTO device_software(device_id, name, version, publisher, installed_on, scope) VALUES "
                    + string.Join(", ", rows),
                [.. args]
            );
        }
    }

    public async Task InsertInventoryChanges(string deviceId, IEnumerable<InventoryChange> changes)
    {
        // Changes of one inventory share a time; ids that start with their position keep them in the order given.
        var batch = Guid.NewGuid().ToString("N")[..12];
        foreach (var (c, i) in changes.Select((c, i) => (c, i)))
            await Execute(
                "INSERT INTO inventory_changes(id, device_id, at, kind, subject, detail) VALUES(@id, @device, @at, @kind, @subject, @detail)",
                ("id", $"{c.At.UtcTicks:D19}-{batch}-{i:D4}"),
                ("device", deviceId),
                ("at", c.At),
                ("kind", c.Kind),
                ("subject", c.Subject),
                ("detail", c.Detail)
            );
    }

    static InventoryChange ReadChange(DbDataReader r, int i) =>
        new(Time(r, i), r.GetString(i + 1), r.GetString(i + 2), r.GetString(i + 3));

    /// <summary>A device's changes, newest first.</summary>
    public Task<List<InventoryChange>> DeviceInventoryChanges(string deviceId, int limit) =>
        Query(
            "SELECT at, kind, subject, detail FROM inventory_changes WHERE device_id = @id ORDER BY at DESC, id LIMIT @limit",
            r => ReadChange(r, 0),
            ("id", deviceId),
            ("limit", (long)limit)
        );

    /// <summary>Changes of devices in use since <paramref name="since"/>, newest first.</summary>
    public Task<List<InventoryChangeRow>> InventoryChangesSince(DateTimeOffset since, int limit) =>
        Query(
            """
            SELECT d.id, d.host_name, d.note, d.group_name, c.at, c.kind, c.subject, c.detail
            FROM inventory_changes c JOIN devices d ON d.id = c.device_id
            WHERE c.at >= @since AND d.archived_at IS NULL ORDER BY c.at DESC, c.id LIMIT @limit
            """,
            r =>
            {
                var change = ReadChange(r, 4);
                return new InventoryChangeRow(
                    r.GetString(0),
                    r.GetString(1),
                    r.GetString(2),
                    r.GetString(3),
                    change.At,
                    change.Kind,
                    change.Subject,
                    change.Detail
                );
            },
            ("since", since),
            ("limit", (long)limit)
        );

    public Task<int> PruneInventoryChanges(DateTimeOffset cutoff, int limit) =>
        Execute(
            "DELETE FROM inventory_changes WHERE id IN (SELECT id FROM inventory_changes WHERE at < @cutoff LIMIT @limit)",
            ("cutoff", cutoff),
            ("limit", (long)limit)
        );

    /// <summary>The hardware of every device in use that has sent an inventory.</summary>
    public Task<List<AssetRow>> Assets() =>
        Query(
            """
            SELECT d.id, d.host_name, d.note, d.group_name, i.hardware, i.software_count, i.received_at
            FROM device_inventory i JOIN devices d ON d.id = i.device_id
            WHERE d.archived_at IS NULL ORDER BY d.host_name, d.id
            """,
            r =>
            {
                var inventory = Wire.Read<AssetInventory>(r.GetString(4));
                return new AssetRow(
                    r.GetString(0),
                    r.GetString(1),
                    r.GetString(2),
                    r.GetString(3),
                    inventory.Hardware,
                    inventory.OperatingSystem,
                    inventory.Disks,
                    inventory.Volumes,
                    (int)Long(r, 5),
                    inventory.CollectedAt,
                    Time(r, 6)
                );
            }
        );

    /// <summary>Each program on devices in use: how many devices have it, and how many have each version.</summary>
    public async Task<List<SoftwareSummary>> Software()
    {
        const string From = "FROM device_software s JOIN devices d ON d.id = s.device_id WHERE d.archived_at IS NULL";
        var versions = (
            await Query(
                $"SELECT s.name, s.version, COUNT(DISTINCT s.device_id) {From} GROUP BY s.name, s.version",
                r => (Name: r.GetString(0), Version: new SoftwareVersion(r.GetString(1), (int)Long(r, 2)))
            )
        ).ToLookup(x => x.Name, x => x.Version);
        return await Query(
            $"SELECT s.name, MAX(s.publisher), COUNT(DISTINCT s.device_id) {From} GROUP BY s.name",
            r => new SoftwareSummary(
                r.GetString(0),
                r.GetString(1),
                (int)Long(r, 2),
                [.. versions[r.GetString(0)].OrderByDescending(v => v.Devices).ThenBy(v => v.Version)]
            )
        );
    }

    /// <summary>The devices in use that have <paramref name="name"/>, with the version and who it is installed for.</summary>
    public Task<List<SoftwareInstall>> SoftwareDevices(string name) =>
        Query(
            """
            SELECT d.id, d.host_name, d.note, d.group_name, s.version, s.scope, s.installed_on
            FROM device_software s JOIN devices d ON d.id = s.device_id
            WHERE s.name = @name AND d.archived_at IS NULL ORDER BY d.host_name, d.id, s.version
            """,
            r => new SoftwareInstall(
                r.GetString(0),
                r.GetString(1),
                r.GetString(2),
                r.GetString(3),
                r.GetString(4),
                r.GetString(5),
                r.GetString(6)
            ),
            ("name", name)
        );
}
