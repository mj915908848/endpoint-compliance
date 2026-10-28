using System.Data.Common;
using System.Globalization;
using Compliance.Core;

namespace Compliance.Server;

public sealed partial class Transaction
{
    // ---- devices -------------------------------------------------------------------------

    // Inserts leave out note, agent_version, network and source_address (added by migrations 3, 6 and 8), so the legacy import in migration 2
    // can still insert.
    const string DeviceColumns =
        "id, host_name, public_key_pem, last_heartbeat, applied_policy_version, controls, snapshot, snapshot_sequence, target_policy_version";
    const string DeviceSelect =
        DeviceColumns
        + ", note, agent_version, network, source_address, verdict_detail, archived_at, health, shutdown_at, group_name";

    // The same columns with controls and snapshot left out: most requests need neither, and parsing the snapshot of
    // every device is the bulk of reading one.
    const string DeviceHeadSelect =
        "id, host_name, public_key_pem, last_heartbeat, applied_policy_version, NULL, NULL, snapshot_sequence, target_policy_version, note, agent_version, network, source_address, verdict_detail, archived_at, health, shutdown_at, group_name";

    static DeviceRecord ReadDevice(DbDataReader r) =>
        new(
            r.GetString(0),
            r.GetString(1),
            r.GetString(2),
            OptionalTime(r, 3),
            Long(r, 4),
            r.IsDBNull(5) ? null : Wire.Read<ControlState[]>(r.GetString(5)),
            r.IsDBNull(6) ? null : Wire.Read<ScanSnapshot>(r.GetString(6)),
            Long(r, 7),
            Long(r, 8),
            r.GetString(9),
            r.GetString(10),
            r.GetString(11) is { Length: > 0 } network ? Wire.Read<NetworkAdapter[]>(network) : null,
            r.GetString(12),
            r.IsDBNull(13) ? null : Wire.Read<StoredVerdict>(r.GetString(13)),
            OptionalTime(r, 14),
            r.GetString(15) is { Length: > 0 } health ? Wire.Read<ClientHealth>(health) : null,
            OptionalTime(r, 16),
            r.GetString(17)
        );

    public Task<DeviceRecord?> GetDevice(string id) =>
        Single($"SELECT {DeviceSelect} FROM devices WHERE id = @id", ReadDevice, ("id", id));

    /// <summary>Full records of the devices <paramref name="ids"/>, a few hundred per query.</summary>
    public Task<List<DeviceRecord>> GetDevices(IEnumerable<string> ids) =>
        QueryIn($"SELECT {DeviceSelect} FROM devices WHERE id IN ({{in}})", ids, ReadDevice);

    public async Task<DeviceRecord> RequireDevice(string id) =>
        await GetDevice(id) ?? throw new ApiError(404, "Device not found");

    public async Task<DeviceRecord> RequireDeviceHead(string id) =>
        await GetDeviceHead(id) ?? throw new ApiError(404, "Device not found");

    /// <summary>Request authentication only needs the key, not the snapshot document.</summary>
    public Task<string?> GetDevicePublicKey(string id) =>
        Single("SELECT public_key_pem FROM devices WHERE id = @id", r => r.GetString(0), ("id", id));

    /// <summary>A device without its controls and snapshot.</summary>
    public Task<DeviceRecord?> GetDeviceHead(string id) =>
        Single($"SELECT {DeviceHeadSelect} FROM devices WHERE id = @id", ReadDevice, ("id", id));

    /// <summary>Every device without its controls and snapshot.</summary>
    public Task<List<DeviceRecord>> AllDeviceHeads() => Query($"SELECT {DeviceHeadSelect} FROM devices", ReadDevice);

    /// <summary>
    /// The devices in use (or, with <paramref name="archived"/>, the archived ones) without their controls and
    /// snapshot. Lists, counts and upgrades leave archived devices out; policy assignment keeps them, as they may be
    /// switched on again.
    /// </summary>
    public Task<List<DeviceRecord>> DeviceHeads(bool archived = false) =>
        Query(
            $"SELECT {DeviceHeadSelect} FROM devices WHERE archived_at IS {(archived ? "NOT NULL" : "NULL")}",
            ReadDevice
        );

    /// <summary>Archives the devices <paramref name="ids"/> not archived yet; returns those it archived.</summary>
    public async Task<List<(string Id, string HostName)>> ArchiveDevices(IEnumerable<string> ids, DateTimeOffset at)
    {
        var archived = new List<(string, string)>();
        foreach (var id in ids)
            if (
                await Single(
                    "UPDATE devices SET archived_at = @at WHERE id = @id AND archived_at IS NULL RETURNING host_name",
                    r => r.GetString(0),
                    ("at", at),
                    ("id", id)
                ) is
                { } host
            )
                archived.Add((id, host));
        return archived;
    }

    /// <summary>Takes a device out of the archive; returns whether it was archived.</summary>
    public async Task<bool> RestoreDevice(string id) =>
        await Execute("UPDATE devices SET archived_at = NULL WHERE id = @id AND archived_at IS NOT NULL", ("id", id))
        > 0;

    /// <summary>Devices in use whose last heartbeat is before <paramref name="cutoff"/>, oldest first.</summary>
    public Task<List<string>> DevicesSilentSince(DateTimeOffset cutoff, int limit) =>
        Query(
            $"""
            SELECT id FROM devices
            WHERE archived_at IS NULL AND last_heartbeat IS NOT NULL AND last_heartbeat < @cutoff
            ORDER BY last_heartbeat, id LIMIT {limit}
            """,
            r => r.GetString(0),
            ("cutoff", cutoff)
        );

    public Task SetDeviceHealth(string id, ClientHealth health) =>
        Execute("UPDATE devices SET health = @health WHERE id = @id", ("health", Wire.Serialize(health)), ("id", id));

    public async Task<bool> DeviceKeyExists(string publicKeyPem) =>
        await Count("SELECT COUNT(*) FROM devices WHERE public_key_pem = @key", ("key", publicKeyPem)) > 0;

    public Task InsertDevice(DeviceRecord d) =>
        Execute(
            $"INSERT INTO devices({DeviceColumns}) VALUES(@id, @host, @key, @heartbeat, @applied, @controls, @snapshot, @sequence, @target)",
            ("id", d.Id),
            ("host", d.HostName),
            ("key", d.PublicKeyPem),
            ("heartbeat", d.LastHeartbeat),
            ("applied", d.AppliedPolicyVersion),
            ("controls", d.Controls is null ? null : Wire.Serialize(d.Controls)),
            ("snapshot", d.Snapshot is null ? null : Wire.Serialize(d.Snapshot)),
            ("sequence", d.SnapshotSequence),
            ("target", d.TargetPolicyVersion)
        );

    /// <summary>Removes a device and everything recorded for it; its agent can no longer sign requests.</summary>
    public async Task DeleteDevice(string id)
    {
        await Execute("DELETE FROM events WHERE device_id = @id", ("id", id));
        await Execute("DELETE FROM alerts WHERE device_id = @id", ("id", id));
        await Execute("DELETE FROM snapshot_incidents WHERE device_id = @id", ("id", id));
        await Execute("DELETE FROM commands WHERE device_id = @id", ("id", id));
        await Execute("DELETE FROM verdict_history WHERE device_id = @id", ("id", id));
        await Execute("DELETE FROM nonces WHERE device = @id", ("id", id));
        await Execute("DELETE FROM device_inventory WHERE device_id = @id", ("id", id));
        await Execute("DELETE FROM device_software WHERE device_id = @id", ("id", id));
        await Execute("DELETE FROM inventory_changes WHERE device_id = @id", ("id", id));
        await Execute("DELETE FROM devices WHERE id = @id", ("id", id));
    }

    public Task UpdateHeartbeat(
        string id,
        string hostName,
        DateTimeOffset at,
        long appliedPolicyVersion,
        ControlState[] controls,
        string agentVersion,
        NetworkAdapter[]? network,
        string sourceAddress
    ) =>
        Execute(
            "UPDATE devices SET host_name = @host, last_heartbeat = @at, applied_policy_version = @applied, controls = @controls, agent_version = @version, network = @network, source_address = @source WHERE id = @id",
            ("host", hostName),
            ("version", agentVersion),
            ("network", network is null ? "" : Wire.Serialize(network)),
            ("source", sourceAddress),
            ("at", at),
            ("applied", appliedPolicyVersion),
            ("controls", Wire.Serialize(controls)),
            ("id", id)
        );

    /// <summary>The ids of the policy keys the device's client trusts, as its heartbeat reports them.</summary>
    public Task SetDevicePolicyKeys(string id, string[] keyIds) =>
        Execute(
            "UPDATE devices SET policy_keys = @keys WHERE id = @id",
            ("keys", string.Join(",", keyIds)),
            ("id", id)
        );

    /// <summary>Enrolled devices and whether their client trusts <paramref name="keyId"/>.</summary>
    public Task<List<(string Id, string HostName, DateTimeOffset? LastHeartbeat, bool Trusts)>> DevicesTrustingKey(
        string keyId
    ) =>
        Query<(string, string, DateTimeOffset?, bool)>(
            "SELECT id, host_name, last_heartbeat, policy_keys FROM devices WHERE archived_at IS NULL ORDER BY host_name, id",
            r =>
                (
                    r.GetString(0),
                    r.GetString(1),
                    r.IsDBNull(2) ? null : Time(r, 2),
                    r.GetString(3).Split(',').Contains(keyId, StringComparer.Ordinal)
                )
        );

    public Task SetDeviceNote(string id, string note) =>
        Execute("UPDATE devices SET note = @note WHERE id = @id", ("note", note), ("id", id));

    public Task UpdateSnapshot(string id, ScanSnapshot snapshot, long sequence) =>
        Execute(
            "UPDATE devices SET snapshot = @snapshot, snapshot_sequence = @sequence WHERE id = @id",
            ("snapshot", Wire.Serialize(snapshot)),
            ("sequence", sequence),
            ("id", id)
        );

    /// <summary>
    /// Stores <paramref name="v"/> unless the device's snapshot or policy changed since it was computed; whoever
    /// changed them stores or refreshes their own.
    /// </summary>
    public Task<int> SaveVerdict(string id, StoredVerdict v) =>
        Execute(
            """
            UPDATE devices SET verdict = @verdict, violation_count = @count, verdict_valid_until = @until,
                verdict_sequence = @sequence, verdict_policy = @policy, verdict_detail = @detail
            WHERE id = @id AND snapshot_sequence = @sequence AND target_policy_version = @policy
            """,
            ("verdict", v.Current?.ToString()),
            ("count", (long)v.ViolationCount),
            ("until", v.ValidUntil),
            ("sequence", v.SnapshotSequence),
            ("policy", v.TargetPolicyVersion),
            ("detail", Wire.Serialize(v)),
            ("id", id)
        );

    /// <summary>
    /// Up to <paramref name="limit"/> devices whose stored verdict no longer holds: never computed, computed for another
    /// snapshot or policy, or past its validity.
    /// </summary>
    public Task<List<string>> DevicesWithStaleVerdicts(DateTimeOffset now, int limit) =>
        Query(
            $"""
            SELECT id FROM devices
            WHERE verdict_sequence <> snapshot_sequence OR verdict_policy <> target_policy_version
                OR verdict_valid_until <= @now
            ORDER BY id LIMIT {limit}
            """,
            r => r.GetString(0),
            ("now", now)
        );

    /// <summary>The device's client said Windows is shutting down; see <see cref="DeviceStatus.IsShutDown"/>.</summary>
    public Task SetShutdown(string id, DateTimeOffset at) =>
        Execute("UPDATE devices SET shutdown_at = @at WHERE id = @id", ("at", at), ("id", id));

    public Task SetDeviceGroup(string id, string group) =>
        Execute("UPDATE devices SET group_name = @group WHERE id = @id", ("group", group), ("id", id));

    public Task SetTargetPolicy(string id, long version) =>
        Execute("UPDATE devices SET target_policy_version = @version WHERE id = @id", ("version", version), ("id", id));

    /// <summary>
    /// Devices whose last heartbeat is at or before <paramref name="cutoff"/>, that have no active offline alert and
    /// did not say they were shutting down.
    /// </summary>
    public Task<List<(string Id, string HostName)>> DevicesGoingOffline(DateTimeOffset cutoff) =>
        Query(
            """
            SELECT d.id, d.host_name FROM devices d
            LEFT JOIN alerts a ON a.id = 'offline:' || d.id
            WHERE d.last_heartbeat IS NOT NULL AND d.last_heartbeat <= @cutoff AND d.archived_at IS NULL
                AND (d.shutdown_at IS NULL OR d.shutdown_at < d.last_heartbeat)
                AND (a.id IS NULL OR a.state <> 'Active')
            """,
            r => (r.GetString(0), r.GetString(1)),
            ("cutoff", cutoff)
        );

    /// <summary>Devices with an active offline alert whose last heartbeat is after <paramref name="cutoff"/>.</summary>
    public Task<List<string>> DevicesBackOnline(DateTimeOffset cutoff) =>
        Query(
            """
            SELECT d.id FROM devices d
            JOIN alerts a ON a.id = 'offline:' || d.id
            WHERE a.state = 'Active' AND d.last_heartbeat > @cutoff
            """,
            r => r.GetString(0),
            ("cutoff", cutoff)
        );
}
