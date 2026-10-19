using Compliance.Core;
using Microsoft.Data.Sqlite;

namespace Compliance.Agent;

public sealed class OutboxCapacityException(string message) : Exception(message);

/// <summary>What one upload of queued events came to.</summary>
/// <param name="Failure">Set when the upload stopped at a failure that is retried later.</param>
public sealed record UploadResult(int Accepted, int Refused, int Quarantined, HttpRequestException? Failure);

public static class EventUpload
{
    /// <summary>Refusals that sending the same request again cannot change.</summary>
    public static bool Permanent(HttpRequestException e) =>
        e.StatusCode
            is System.Net.HttpStatusCode.BadRequest
                or System.Net.HttpStatusCode.UnprocessableEntity
                or System.Net.HttpStatusCode.Conflict;

    private static TimeSpan RetryDelay(HttpRequestException e) =>
        e is AgentApiException { RetryAfter: { } serverDelay } && serverDelay > TimeSpan.Zero
            ? serverDelay
            : TimeSpan.FromSeconds(30 + Random.Shared.Next(30));

    /// <summary>
    /// Sends <paramref name="pending"/> and removes what the server accepts. A batch the server refuses as invalid does
    /// not say which event is at fault, so it is sent again one event at a time, and only an event refused on its own
    /// is quarantined; the others are delivered. A network or server failure keeps every unsent event for a retry.
    /// </summary>
    public static async Task<UploadResult> SendAsync(
        EventOutbox queue,
        AgentEvent[] pending,
        Func<EventBatch, CancellationToken, Task<EventReceipt>> send,
        CancellationToken ct
    )
    {
        async Task<(int Accepted, int Refused)> Deliver(AgentEvent[] events)
        {
            var receipt = await send(new EventBatch(events), ct);
            var ids = events.Select(x => x.EventId).ToArray();
            var accepted = receipt.AcceptedEventIds.Intersect(ids).ToArray();
            await queue.AcknowledgeAsync(accepted, ct);
            var refused = ids.Except(receipt.AcceptedEventIds).ToArray();
            if (refused.Length > 0)
                await queue.RetryAsync(refused, TimeSpan.FromMinutes(1), "Server did not accept event", false, ct);
            return (accepted.Length, refused.Length);
        }

        if (pending.Length == 0)
            return new(0, 0, 0, null);
        try
        {
            var (accepted, refused) = await Deliver(pending);
            return new(accepted, refused, 0, null);
        }
        catch (HttpRequestException e) when (!Permanent(e) || pending.Length == 1)
        {
            var permanent = Permanent(e);
            await queue.RetryAsync(pending.Select(x => x.EventId), RetryDelay(e), e.Message, permanent, ct);
            return new(0, 0, permanent ? 1 : 0, e);
        }
        catch (HttpRequestException)
        {
            int accepted = 0,
                refused = 0,
                quarantined = 0;
            for (var i = 0; i < pending.Length; i++)
            {
                try
                {
                    var (a, r) = await Deliver([pending[i]]);
                    accepted += a;
                    refused += r;
                }
                catch (HttpRequestException one) when (Permanent(one))
                {
                    await queue.RetryAsync([pending[i].EventId], TimeSpan.Zero, one.Message, true, ct);
                    quarantined++;
                }
                catch (HttpRequestException other)
                {
                    await queue.RetryAsync(
                        pending[i..].Select(x => x.EventId),
                        RetryDelay(other),
                        other.Message,
                        false,
                        ct
                    );
                    return new(accepted, refused, quarantined, other);
                }
            }
            return new(accepted, refused, quarantined, null);
        }
    }
}

public record LocalTransition(string Type, string ObjectKey, string Detail, string? UserSid);

public sealed class EventOutbox : IAsyncDisposable
{
    private readonly SqliteConnection db;
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly int maxEvents;
    private readonly long maxBytes;
    private readonly string databasePath;

    public EventOutbox(string path, int maxEvents = 100000, long maxBytes = 1024L * 1024 * 1024)
    {
        if (maxEvents < 1 || maxBytes < 1)
            throw new ArgumentOutOfRangeException("Outbox limits must be positive");
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        this.maxEvents = maxEvents;
        this.maxBytes = maxBytes;
        databasePath = Path.GetFullPath(path);
        db = new SqliteConnection(
            new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadWriteCreate }.ToString()
        );
        try
        {
            db.Open();
            using var cmd = db.CreateCommand();
            cmd.CommandText =
                "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; "
                + "CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, json TEXT NOT NULL, next_attempt TEXT, attempts INTEGER NOT NULL DEFAULT 0, error TEXT); "
                + "CREATE TABLE IF NOT EXISTS quarantine(seq INTEGER PRIMARY KEY, id TEXT NOT NULL, json TEXT NOT NULL, error TEXT NOT NULL, at TEXT NOT NULL); "
                + "CREATE TABLE IF NOT EXISTS local_incidents(key TEXT PRIMARY KEY,detail TEXT NOT NULL,sid TEXT,active INTEGER NOT NULL,last_notice TEXT NOT NULL);";
            cmd.ExecuteNonQuery();
            // Queues from before findings were recorded get the column; their snapshots are never merged away.
            cmd.CommandText = "SELECT COUNT(*) FROM pragma_table_info('events') WHERE name='findings'";
            if (Convert.ToInt64(cmd.ExecuteScalar()) == 0)
            {
                cmd.CommandText = "ALTER TABLE events ADD COLUMN findings TEXT";
                cmd.ExecuteNonQuery();
            }
        }
        catch
        {
            // Releases the file so a damaged one can be set aside.
            db.Dispose();
            throw;
        }
    }

    public async Task<AgentEvent> EnqueueAsync(
        string type,
        string objectKey,
        ScanSnapshot? snapshot,
        string? detail,
        CancellationToken ct = default
    )
    {
        await gate.WaitAsync(ct);
        try
        {
            using var tx = db.BeginTransaction();
            var id = Guid.NewGuid().ToString("D");
            var when = snapshot?.CollectedAt ?? DateTimeOffset.UtcNow;
            // The sequence is not known yet; its digits barely change the size.
            var needed =
                System.Text.Encoding.UTF8.GetByteCount(
                    Wire.Serialize(new AgentEvent(id, long.MaxValue, when, type, objectKey, snapshot, detail))
                ) + 8192L;
            await PruneQuarantineAsync(tx, ct);
            var findings = snapshot is null ? null : Findings(snapshot);
            if (type == "Snapshot")
                await DropSameHourSnapshotsAsync(tx, when, findings!, ct);
            var dropped = 0;
            while (await FullAsync(tx, needed, ct) && await DropOldestSnapshotAsync(tx, ct) is > 0 and var n)
                dropped += n;
            if (await CountAsync(tx, ct) >= maxEvents)
                throw new OutboxCapacityException("Critical event cannot be durably retained: outbox capacity reached");
            if (await UsedBytesAsync(tx, ct) + needed >= maxBytes)
                throw new OutboxCapacityException(
                    "Critical event cannot be durably retained: outbox byte limit reached"
                );
            using var insert = db.CreateCommand();
            insert.Transaction = tx;
            insert.CommandText = "INSERT INTO events(id,json,findings) VALUES($id,'',$findings) RETURNING seq";
            insert.Parameters.AddWithValue("$id", id);
            insert.Parameters.AddWithValue("$findings", (object?)findings ?? DBNull.Value);
            var seq = Convert.ToInt64(await insert.ExecuteScalarAsync(ct));
            var evt = new AgentEvent(id, seq, when, type, objectKey, snapshot, detail);
            using var update = db.CreateCommand();
            update.Transaction = tx;
            update.CommandText = "UPDATE events SET json=$json WHERE seq=$seq";
            update.Parameters.AddWithValue("$json", Wire.Serialize(evt));
            update.Parameters.AddWithValue("$seq", seq);
            await update.ExecuteNonQueryAsync(ct);
            tx.Commit();
            Dropped += dropped;
            return evt;
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task<bool> FullAsync(SqliteTransaction tx, long needed, CancellationToken ct) =>
        await CountAsync(tx, ct) >= maxEvents || await UsedBytesAsync(tx, ct) + needed >= maxBytes;

    private async Task<long> CountAsync(SqliteTransaction tx, CancellationToken ct)
    {
        using var count = db.CreateCommand();
        count.Transaction = tx;
        count.CommandText = "SELECT (SELECT COUNT(*) FROM events)+(SELECT COUNT(*) FROM quarantine)";
        return Convert.ToInt64(await count.ExecuteScalarAsync(ct));
    }

    /// <summary>
    /// Pages holding rows plus the write-ahead log. Deleted rows leave free pages that later rows reuse, so this
    /// rather than the file size says whether another event fits.
    /// </summary>
    private async Task<long> UsedBytesAsync(SqliteTransaction tx, CancellationToken ct)
    {
        using var pages = db.CreateCommand();
        pages.Transaction = tx;
        pages.CommandText =
            "SELECT ((SELECT page_count FROM pragma_page_count())-(SELECT freelist_count FROM pragma_freelist_count()))"
            + "*(SELECT page_size FROM pragma_page_size())";
        var wal = File.Exists(databasePath + "-wal") ? new FileInfo(databasePath + "-wal").Length : 0;
        return Convert.ToInt64(await pages.ExecuteScalarAsync(ct)) + wal;
    }

    /// <summary>
    /// Makes room in a full queue, one snapshot at a time. The server keeps only the newest snapshot, so the oldest
    /// queued ones go, those the server already refused before those still waiting; other events are never dropped.
    /// Returns 0 when no snapshot is left to drop.
    /// </summary>
    private async Task<int> DropOldestSnapshotAsync(SqliteTransaction tx, CancellationToken ct)
    {
        using var drop = db.CreateCommand();
        drop.Transaction = tx;
        drop.CommandText =
            "DELETE FROM quarantine WHERE seq IN (SELECT seq FROM quarantine WHERE json_extract(json,'$.type')='Snapshot' ORDER BY seq LIMIT 1)";
        var dropped = await drop.ExecuteNonQueryAsync(ct);
        if (dropped > 0)
            return dropped;
        drop.CommandText =
            "DELETE FROM events WHERE seq IN (SELECT seq FROM events WHERE json_extract(json,'$.type')='Snapshot' ORDER BY seq LIMIT 1)";
        return await drop.ExecuteNonQueryAsync(ct);
    }

    /// <summary>
    /// Keeps one waiting snapshot per hour: a new one replaces those from the same hour that are still queued. The
    /// server keeps only the newest snapshot and the verdict changes between them, so a device that was offline for a
    /// week sends about 170 snapshots when it is back rather than 2000, and its current state arrives sooner.
    /// </summary>
    /// <summary>
    /// What a snapshot found, in the terms the server keeps incidents by: product and user, and the object for proxy
    /// settings and sensitive files. Process ids and other details that change between scans are left out.
    /// </summary>
    internal static string Findings(ScanSnapshot snapshot) =>
        Convert.ToHexStringLower(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(
                    string.Join(
                        "\n",
                        snapshot
                            .Evidence.Where(e => e.Confirmed && e.Kind != EvidenceKind.Clue)
                            .Select(e =>
                                e.ProductId
                                + "|"
                                + (e.UserSid ?? "machine")
                                + (e.Kind is EvidenceKind.Proxy or EvidenceKind.SensitiveFile ? "|" + e.ObjectKey : "")
                            )
                            .Distinct()
                            .Order(StringComparer.Ordinal)
                    )
                )
            )
        );

    /// <summary>
    /// Snapshots from the same hour that found the same things are replaced by the newest one. One that found
    /// something else is kept, so a violation found and gone again while offline still reaches the server.
    /// </summary>
    private async Task DropSameHourSnapshotsAsync(
        SqliteTransaction tx,
        DateTimeOffset when,
        string findings,
        CancellationToken ct
    )
    {
        var hour = when.UtcDateTime.ToString("yyyyMMddHH");
        var replaced = new List<long>();
        using (var find = db.CreateCommand())
        {
            find.Transaction = tx;
            find.CommandText =
                "SELECT seq, json_extract(json,'$.sourceTime') FROM events WHERE json_extract(json,'$.type')='Snapshot' AND findings=$findings";
            find.Parameters.AddWithValue("$findings", findings);
            using var reader = await find.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
                if (
                    !reader.IsDBNull(1)
                    && DateTimeOffset.TryParse(
                        reader.GetString(1),
                        System.Globalization.CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.None,
                        out var at
                    )
                    && at.UtcDateTime.ToString("yyyyMMddHH") == hour
                )
                    replaced.Add(reader.GetInt64(0));
        }
        using var drop = db.CreateCommand();
        drop.Transaction = tx;
        drop.CommandText = "DELETE FROM events WHERE seq=$seq";
        var seq = drop.Parameters.Add("$seq", SqliteType.Integer);
        foreach (var s in replaced)
        {
            seq.Value = s;
            await drop.ExecuteNonQueryAsync(ct);
        }
    }

    /// <summary>How long a quarantined event is kept for diagnosis; it is never sent again.</summary>
    public static readonly TimeSpan QuarantineRetention = TimeSpan.FromDays(30);

    /// <summary>Quarantined events kept at most, newest first, so they cannot fill the queue.</summary>
    public const int MaxQuarantined = 1000;

    private async Task PruneQuarantineAsync(SqliteTransaction tx, CancellationToken ct)
    {
        using var prune = db.CreateCommand();
        prune.Transaction = tx;
        prune.CommandText =
            "DELETE FROM quarantine WHERE at < $cutoff OR seq NOT IN (SELECT seq FROM quarantine ORDER BY seq DESC LIMIT $max)";
        prune.Parameters.AddWithValue("$cutoff", DateTimeOffset.UtcNow.Subtract(QuarantineRetention).ToString("O"));
        prune.Parameters.AddWithValue("$max", MaxQuarantined);
        await prune.ExecuteNonQueryAsync(ct);
    }

    /// <summary>
    /// Makes the next event's sequence follow <paramref name="last"/>, the highest the server holds for this device.
    /// The sequence lives in this file only, so a lost or replaced file would start again at 1, and the server ignores
    /// snapshots older than its current one by sequence. Returns whether the sequence was behind.
    /// </summary>
    public async Task<bool> AdvanceSequenceAsync(long last, CancellationToken ct = default)
    {
        if (last <= 0)
            return false;
        await gate.WaitAsync(ct);
        try
        {
            using var tx = db.BeginTransaction();
            using var cmd = db.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText =
                "UPDATE sqlite_sequence SET seq=$last WHERE name='events' AND seq<$last; "
                + "INSERT INTO sqlite_sequence(name,seq) SELECT 'events',$last "
                + "WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name='events')";
            cmd.Parameters.AddWithValue("$last", last);
            var changed = await cmd.ExecuteNonQueryAsync(ct);
            tx.Commit();
            return changed > 0;
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>Queued snapshots dropped to make room since this queue was opened.</summary>
    public int Dropped { get; private set; }

    public async Task<AgentEvent[]> PendingAsync(int max, CancellationToken ct = default)
    {
        await gate.WaitAsync(ct);
        try
        {
            using var cmd = db.CreateCommand();
            cmd.CommandText =
                "SELECT json FROM events WHERE next_attempt IS NULL OR next_attempt <= $now ORDER BY seq LIMIT $max";
            cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
            cmd.Parameters.AddWithValue("$max", max);
            using var reader = await cmd.ExecuteReaderAsync(ct);
            var result = new List<AgentEvent>();
            while (await reader.ReadAsync(ct))
                result.Add(Wire.Read<AgentEvent>(reader.GetString(0)));
            return result.ToArray();
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task<int> UnsentCountAsync(CancellationToken ct = default)
    {
        await gate.WaitAsync(ct);
        try
        {
            using var cmd = db.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM events";
            return Convert.ToInt32(await cmd.ExecuteScalarAsync(ct));
        }
        finally
        {
            gate.Release();
        }
    }

    public int OversizedInLastBatch { get; private set; }

    public async Task<AgentEvent[]> PendingBatchAsync(int max, int maxWireBytes, CancellationToken ct = default)
    {
        if (max < 1 || maxWireBytes < 256)
            throw new ArgumentOutOfRangeException(nameof(maxWireBytes));
        var batch = new List<AgentEvent>();
        var oversized = new List<string>();
        await gate.WaitAsync(ct);
        try
        {
            using var cmd = db.CreateCommand();
            cmd.CommandText =
                "SELECT json FROM events WHERE next_attempt IS NULL OR next_attempt <= $now ORDER BY seq LIMIT $max";
            cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
            cmd.Parameters.AddWithValue("$max", max);
            using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var candidate = Wire.Read<AgentEvent>(reader.GetString(0));
                var oneBytes = System.Text.Encoding.UTF8.GetByteCount(Wire.Serialize(new EventBatch([candidate])));
                if (oneBytes > maxWireBytes)
                {
                    oversized.Add(candidate.EventId);
                    continue;
                }
                var combined = System.Text.Encoding.UTF8.GetByteCount(
                    Wire.Serialize(new EventBatch([.. batch, candidate]))
                );
                if (combined > maxWireBytes)
                    break;
                batch.Add(candidate);
            }
        }
        finally
        {
            gate.Release();
        }
        OversizedInLastBatch = oversized.Count;
        if (oversized.Count > 0)
            await RetryAsync(
                oversized,
                TimeSpan.Zero,
                "Single event exceeds the authenticated API request limit",
                true,
                ct
            );
        return batch.ToArray();
    }

    public async Task AcknowledgeAsync(IEnumerable<string> ids, CancellationToken ct = default)
    {
        await gate.WaitAsync(ct);
        try
        {
            using var tx = db.BeginTransaction();
            foreach (var id in ids)
            {
                using var cmd = db.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText = "DELETE FROM events WHERE id=$id";
                cmd.Parameters.AddWithValue("$id", id);
                await cmd.ExecuteNonQueryAsync(ct);
            }
            tx.Commit();
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task RetryAsync(
        IEnumerable<string> ids,
        TimeSpan delay,
        string error,
        bool permanent,
        CancellationToken ct = default
    )
    {
        await gate.WaitAsync(ct);
        try
        {
            using var tx = db.BeginTransaction();
            foreach (var id in ids)
            {
                using var attempt = db.CreateCommand();
                attempt.Transaction = tx;
                attempt.CommandText = "SELECT attempts FROM events WHERE id=$id";
                attempt.Parameters.AddWithValue("$id", id);
                var prior = await attempt.ExecuteScalarAsync(ct);
                if (prior is null)
                    continue;
                var attempts = Convert.ToInt32(prior);
                var backoff = TimeSpan.FromSeconds(
                    Math.Min(3600, delay.TotalSeconds * Math.Pow(2, Math.Min(attempts, 12))) + Random.Shared.Next(0, 10)
                );
                using var cmd = db.CreateCommand();
                cmd.Transaction = tx;
                if (permanent)
                    cmd.CommandText =
                        "INSERT INTO quarantine(seq,id,json,error,at) SELECT seq,id,json,$error,$at FROM events WHERE id=$id; "
                        + "DELETE FROM events WHERE id=$id";
                else
                    cmd.CommandText =
                        "UPDATE events SET attempts=attempts+1, next_attempt=$at, error=$error WHERE id=$id";
                cmd.Parameters.AddWithValue("$id", id);
                cmd.Parameters.AddWithValue("$error", error[..Math.Min(error.Length, 500)]);
                cmd.Parameters.AddWithValue(
                    "$at",
                    (permanent ? DateTimeOffset.UtcNow : DateTimeOffset.UtcNow.Add(backoff)).ToString("O")
                );
                await cmd.ExecuteNonQueryAsync(ct);
            }
            tx.Commit();
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task<LocalTransition[]> SyncFindingsAsync(
        IReadOnlyDictionary<string, string> findings,
        bool allowRecovery,
        IReadOnlyDictionary<string, string?>? userSids = null,
        DateTimeOffset? at = null,
        CancellationToken ct = default
    )
    {
        var now = at ?? DateTimeOffset.UtcNow;
        await gate.WaitAsync(ct);
        try
        {
            using var tx = db.BeginTransaction();
            using var read = db.CreateCommand();
            read.Transaction = tx;
            read.CommandText = "SELECT key,detail,sid,active,last_notice FROM local_incidents";
            var prior = new Dictionary<string, (string detail, string? sid, bool active, DateTimeOffset last)>();
            using (var rows = await read.ExecuteReaderAsync(ct))
                while (await rows.ReadAsync(ct))
                    prior[rows.GetString(0)] = (
                        rows.GetString(1),
                        rows.IsDBNull(2) ? null : rows.GetString(2),
                        rows.GetInt64(3) != 0,
                        DateTimeOffset.Parse(rows.GetString(4))
                    );
            var changes = new List<LocalTransition>();
            foreach (var (key, detail) in findings)
            {
                var sid = userSids is not null && userSids.TryGetValue(key, out var scope) ? scope : null;
                bool notify = !prior.TryGetValue(key, out var old) || !old.active || old.last <= now.AddMinutes(-30);
                using var put = db.CreateCommand();
                put.Transaction = tx;
                put.CommandText =
                    "INSERT INTO local_incidents(key,detail,sid,active,last_notice) VALUES($key,$detail,$sid,1,$time) ON CONFLICT"
                    + "(key) DO UPDATE"
                    + " SET detail=$detail,sid=$sid,active=1,last_notice=CASE WHEN $notify=1 THEN $time ELSE last_notice END";
                put.Parameters.AddWithValue("$key", key);
                put.Parameters.AddWithValue("$detail", EvidenceSanitizer.Clean(detail));
                put.Parameters.AddWithValue("$sid", (object?)sid ?? DBNull.Value);
                put.Parameters.AddWithValue("$time", now.ToString("O"));
                put.Parameters.AddWithValue("$notify", notify ? 1 : 0);
                await put.ExecuteNonQueryAsync(ct);
                if (notify)
                    changes.Add(new(old.active ? "Reminder" : "Violation", key, detail, sid));
            }
            if (allowRecovery)
                foreach (var (key, old) in prior.Where(x => x.Value.active && !findings.ContainsKey(x.Key)))
                {
                    using var update = db.CreateCommand();
                    update.Transaction = tx;
                    update.CommandText = "UPDATE local_incidents SET active=0,last_notice=$time WHERE key=$key";
                    update.Parameters.AddWithValue("$key", key);
                    update.Parameters.AddWithValue("$time", now.ToString("O"));
                    await update.ExecuteNonQueryAsync(ct);
                    changes.Add(new("Recovered", key, old.detail, old.sid));
                }
            tx.Commit();
            return changes.ToArray();
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await db.DisposeAsync();
        gate.Dispose();
    }
}
