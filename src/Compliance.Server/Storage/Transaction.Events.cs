using System.Data.Common;
using System.Globalization;
using Compliance.Core;

namespace Compliance.Server;

public sealed partial class Transaction
{
    // ---- events --------------------------------------------------------------------------

    public Task<string?> GetEventBody(string deviceId, string eventId) =>
        Single(
            "SELECT body FROM events WHERE device_id = @device AND event_id = @event",
            r => r.GetString(0),
            ("device", deviceId),
            ("event", eventId)
        );

    /// <summary>
    /// Deletes at most <paramref name="limit"/> events received before <paramref name="cutoff"/>, only snapshots
    /// when <paramref name="snapshotsOnly"/>; returns how many. Kept small so each batch is a short transaction.
    /// </summary>
    public Task<int> PruneEvents(DateTimeOffset cutoff, bool snapshotsOnly, int limit) =>
        Execute(
            $"""
            DELETE FROM events WHERE (device_id, event_id) IN (
                SELECT device_id, event_id FROM events
                WHERE received_at < @cutoff{(snapshotsOnly ? " AND type = 'Snapshot'" : "")}
                LIMIT @limit)
            """,
            ("cutoff", cutoff),
            ("limit", (long)limit)
        );

    public Task<int> PruneSessions(DateTimeOffset now) =>
        Execute("DELETE FROM sessions WHERE expires_at < @now", ("now", now));

    public Task<int> PruneCommands(DateTimeOffset cutoff) =>
        Execute("DELETE FROM commands WHERE expires_at < @cutoff", ("cutoff", cutoff));

    /// <summary>Fingerprints of those of <paramref name="eventIds"/> the device has already sent.</summary>
    public async Task<Dictionary<string, string>> EventFingerprints(string deviceId, IEnumerable<string> eventIds) =>
        (
            await QueryIn(
                "SELECT event_id, fingerprint FROM events WHERE device_id = @device AND event_id IN ({in})",
                eventIds,
                r => (Id: r.GetString(0), Fingerprint: r.GetString(1)),
                ("device", deviceId)
            )
        ).ToDictionary(x => x.Id, x => x.Fingerprint);

    /// <summary>Those of <paramref name="sequences"/> already taken by the device's stored events.</summary>
    public async Task<HashSet<long>> UsedSequences(string deviceId, IEnumerable<long> sequences) =>
        (
            await QueryIn(
                "SELECT sequence FROM events WHERE device_id = @device AND sequence IN ({in})",
                sequences,
                r => Long(r, 0),
                ("device", deviceId)
            )
        ).ToHashSet();

    /// <summary>The highest event sequence the device's snapshot, stored events and alerts hold; 0 if none.</summary>
    public Task<long> LastSequence(string deviceId) =>
        Count(
            """
            SELECT MAX(s) FROM (
                SELECT COALESCE(MAX(sequence), 0) AS s FROM events WHERE device_id = @device
                UNION ALL SELECT COALESCE(MAX(last_sequence), 0) FROM alerts WHERE device_id = @device
                UNION ALL SELECT snapshot_sequence FROM devices WHERE id = @device
            ) AS sequences
            """,
            ("device", deviceId)
        );

    public Task InsertEvent(string deviceId, StoredEvent stored) =>
        Execute(
            """
            INSERT INTO events(device_id, event_id, sequence, type, object_key, source_time, received_at, fingerprint, body)
            VALUES(@device, @event, @sequence, @type, @key, @source, @received, @fingerprint, @body)
            """,
            ("device", deviceId),
            ("event", stored.Event.EventId),
            ("sequence", stored.Event.Sequence),
            ("type", stored.Event.Type),
            ("key", stored.Event.ObjectKey),
            ("source", stored.Event.SourceTime),
            ("received", stored.ReceivedAt),
            ("fingerprint", stored.Fingerprint),
            ("body", Wire.Serialize(stored.Event))
        );
}
