using System.Data.Common;
using System.Globalization;
using Compliance.Core;

namespace Compliance.Server;

public sealed partial class Transaction
{
    // ---- alerts --------------------------------------------------------------------------

    const string AlertColumns =
        "id, device_id, host_name, type, object_key, summary, state, last_sequence, first_seen, last_seen, acknowledged";

    static AlertSummary ReadAlert(DbDataReader r) =>
        new(
            r.GetString(0),
            r.GetString(1),
            r.GetString(2),
            r.GetString(3),
            r.GetString(4),
            r.GetString(5),
            r.GetString(6),
            Long(r, 7),
            Time(r, 8),
            Time(r, 9),
            Long(r, 10) != 0
        );

    /// <summary>Every alert of one device, by id.</summary>
    public async Task<Dictionary<string, AlertSummary>> DeviceAlerts(string deviceId) =>
        (
            await Query($"SELECT {AlertColumns} FROM alerts WHERE device_id = @device", ReadAlert, ("device", deviceId))
        ).ToDictionary(a => a.Id);

    public Task<AlertSummary?> GetAlert(string id) =>
        Single($"SELECT {AlertColumns} FROM alerts WHERE id = @id", ReadAlert, ("id", id));

    /// <summary>Alerts not resolved, and those resolved since <paramref name="resolvedSince"/>, newest first.</summary>
    public Task<List<AlertSummary>> AlertsNewestFirst(DateTimeOffset resolvedSince) =>
        Query(
            $"SELECT {AlertColumns} FROM alerts WHERE state <> 'Resolved' OR last_seen >= @since ORDER BY last_seen DESC, id DESC",
            ReadAlert,
            ("since", resolvedSince)
        );

    /// <summary>
    /// A page of resolved alerts older than the last one shown (<paramref name="before"/>, <paramref name="beforeId"/>),
    /// newest first; the id breaks ties between alerts resolved at the same moment.
    /// </summary>
    public Task<List<AlertSummary>> ResolvedAlertsBefore(DateTimeOffset before, string beforeId, int limit) =>
        Query(
            $"""
            SELECT {AlertColumns} FROM alerts
            WHERE state = 'Resolved' AND (last_seen < @before OR (last_seen = @before AND id < @id))
            ORDER BY last_seen DESC, id DESC LIMIT @limit
            """,
            ReadAlert,
            ("before", before),
            ("id", beforeId),
            ("limit", (long)limit)
        );

    /// <summary>
    /// Deletes at most <paramref name="limit"/> alerts resolved before <paramref name="cutoff"/>, with the records kept
    /// for recovering them; returns how many alerts.
    /// </summary>
    public async Task<int> PruneResolvedAlerts(DateTimeOffset cutoff, int limit)
    {
        var removed = await Execute(
            """
            DELETE FROM alerts WHERE id IN (
                SELECT id FROM alerts WHERE state = 'Resolved' AND last_seen < @cutoff LIMIT @limit)
            """,
            ("cutoff", cutoff),
            ("limit", (long)limit)
        );
        if (removed > 0)
            await Execute(
                "DELETE FROM snapshot_incidents WHERE NOT EXISTS (SELECT 1 FROM alerts WHERE alerts.id = snapshot_incidents.id)"
            );
        return removed;
    }

    /// <summary>
    /// An alert that becomes active, newly or again, waits to be pushed (see <see cref="PendingNotifications"/>). Each
    /// time it becomes active again counts as another activation, so a push still under way for an earlier one does
    /// not mark this one as pushed.
    /// </summary>
    public Task UpsertAlert(AlertSummary a) =>
        WriteAlert(
            a,
            """
            , notified) VALUES(@id, @device, @host, @type, @key, @summary, @state, @sequence, @first, @last, @ack, @notified)
            ON CONFLICT(id) DO UPDATE SET
                notified = CASE WHEN excluded.state = 'Active' AND alerts.state <> 'Active' THEN 0 ELSE alerts.notified END,
                activations = alerts.activations
                    + CASE WHEN excluded.state = 'Active' AND alerts.state <> 'Active' THEN 1 ELSE 0 END,
            """,
            ("notified", a.State != "Active")
        );

    /// <summary>Migration 2 imports 0.1.0 alerts before migration 7 adds <c>notified</c>.</summary>
    public Task InsertLegacyAlert(AlertSummary a) =>
        WriteAlert(
            a,
            """
            ) VALUES(@id, @device, @host, @type, @key, @summary, @state, @sequence, @first, @last, @ack)
            ON CONFLICT(id) DO UPDATE SET
            """
        );

    Task WriteAlert(AlertSummary a, string insertTail, params (string Name, object? Value)[] extra) =>
        Execute(
            $"""
            INSERT INTO alerts({AlertColumns}{insertTail}
                device_id = excluded.device_id, host_name = excluded.host_name, type = excluded.type,
                object_key = excluded.object_key, summary = excluded.summary, state = excluded.state,
                last_sequence = excluded.last_sequence, first_seen = excluded.first_seen,
                last_seen = excluded.last_seen, acknowledged = excluded.acknowledged
            """,
            [
                ("id", a.Id),
                ("device", a.DeviceId),
                ("host", a.HostName),
                ("type", a.Type),
                ("key", a.ObjectKey),
                ("summary", a.Summary),
                ("state", a.State),
                ("sequence", a.LastSequence),
                ("first", a.FirstSeen),
                ("last", a.LastSeen),
                ("ack", a.Acknowledged),
                .. extra,
            ]
        );

    /// <summary>Active alerts not pushed yet, oldest first, with the note of their device and their activation.</summary>
    public Task<List<(AlertSummary Alert, string Note, long Activation)>> PendingNotifications(int limit) =>
        Query(
            $"""
            SELECT {string.Join(", ", AlertColumns.Split(", ").Select(c => "a." + c))}, COALESCE(d.note, ''),
                a.activations
            FROM alerts a LEFT JOIN devices d ON d.id = a.device_id
            WHERE a.notified = 0 AND a.state = 'Active'
            ORDER BY a.first_seen, a.id LIMIT @limit
            """,
            r => (ReadAlert(r), r.GetString(11), r.GetInt64(12)),
            ("limit", (long)limit)
        );

    /// <summary>Marks alerts pushed, unless one became active again since its activation was read.</summary>
    public async Task MarkNotified(IEnumerable<(string Id, long Activation)> alerts)
    {
        foreach (var (id, activation) in alerts)
            await Execute(
                "UPDATE alerts SET notified = 1 WHERE id = @id AND activations = @activation",
                ("id", id),
                ("activation", activation)
            );
    }

    /// <summary>Alerts whose state, or activation while active, changed since it was last sent to syslog.</summary>
    public Task<List<(AlertSummary Alert, string Note, long Activation)>> PendingForwards(int limit) =>
        Query(
            $"""
            SELECT {string.Join(", ", AlertColumns.Split(", ").Select(c => "a." + c))}, COALESCE(d.note, ''),
                a.activations
            FROM alerts a LEFT JOIN devices d ON d.id = a.device_id
            WHERE a.forwarded_state <> a.state OR (a.state = 'Active' AND a.forwarded_activation <> a.activations)
            ORDER BY a.last_seen, a.id LIMIT @limit
            """,
            r => (ReadAlert(r), r.GetString(11), r.GetInt64(12)),
            ("limit", (long)limit)
        );

    /// <summary>Records what was sent of each alert; an alert that changed again since stays pending.</summary>
    public async Task MarkForwarded(IEnumerable<(string Id, string State, long Activation)> alerts)
    {
        foreach (var (id, state, activation) in alerts)
            await Execute(
                """
                UPDATE alerts SET forwarded_state = @state, forwarded_activation = @activation
                WHERE id = @id AND state = @state AND activations = @activation
                """,
                ("id", id),
                ("state", state),
                ("activation", activation)
            );
    }

    /// <summary>Marks every alert as sent, while forwarding is off, so turning it on does not send a backlog.</summary>
    public Task<int> MarkAllForwarded() =>
        Execute(
            """
            UPDATE alerts SET forwarded_state = state, forwarded_activation = activations
            WHERE forwarded_state <> state OR forwarded_activation <> activations
            """
        );

    public Task AcknowledgeAlert(string id) => Execute("UPDATE alerts SET acknowledged = 1 WHERE id = @id", ("id", id));

    /// <summary>Resolves every active alert of a device, as when it is archived.</summary>
    public Task<int> ResolveDeviceAlerts(string deviceId, DateTimeOffset lastSeen) =>
        Execute(
            "UPDATE alerts SET state = 'Resolved', last_seen = @last WHERE device_id = @device AND state <> 'Resolved'",
            ("last", lastSeen),
            ("device", deviceId)
        );

    public Task ResolveAlert(string id, DateTimeOffset lastSeen) =>
        Execute(
            "UPDATE alerts SET state = 'Resolved', last_seen = @last WHERE id = @id",
            ("last", lastSeen),
            ("id", id)
        );

    // ---- snapshot incidents --------------------------------------------------------------

    static SnapshotIncident ReadIncident(DbDataReader r) =>
        new(r.GetString(0), r.GetString(1), r.GetString(2), Wire.Read<string[]>(r.GetString(3)));

    public Task<SnapshotIncident?> GetSnapshotIncident(string id) =>
        Single("SELECT id, device_id, scope, modules FROM snapshot_incidents WHERE id = @id", ReadIncident, ("id", id));

    public Task<List<SnapshotIncident>> SnapshotIncidents(string deviceId) =>
        Query(
            "SELECT id, device_id, scope, modules FROM snapshot_incidents WHERE device_id = @device",
            ReadIncident,
            ("device", deviceId)
        );

    public Task PutSnapshotIncident(SnapshotIncident incident) =>
        Execute(
            """
            INSERT INTO snapshot_incidents(id, device_id, scope, modules) VALUES(@id, @device, @scope, @modules)
            ON CONFLICT(id) DO UPDATE SET device_id = excluded.device_id, scope = excluded.scope, modules = excluded.modules
            """,
            ("id", incident.Id),
            ("device", incident.DeviceId),
            ("scope", incident.Scope),
            ("modules", Wire.Serialize(incident.Modules))
        );
}
