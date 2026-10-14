using Compliance.Core;
using Microsoft.Data.Sqlite;

namespace Compliance.Agent;

public sealed class OutboxCapacityException(string message) : Exception(message);

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
        db.Open();
        using var cmd = db.CreateCommand();
        cmd.CommandText =
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; "
            + "CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, json TEXT NOT NULL, next_attempt TEXT, attempts INTEGER NOT NULL DEFAULT 0, error TEXT); "
            + "CREATE TABLE IF NOT EXISTS quarantine(seq INTEGER PRIMARY KEY, id TEXT NOT NULL, json TEXT NOT NULL, error TEXT NOT NULL, at TEXT NOT NULL); "
            + "CREATE TABLE IF NOT EXISTS local_incidents(key TEXT PRIMARY KEY,detail TEXT NOT NULL,sid TEXT,active INTEGER NOT NULL,last_notice TEXT NOT NULL);";
        cmd.ExecuteNonQuery();
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
            using var count = db.CreateCommand();
            count.Transaction = tx;
            count.CommandText = "SELECT (SELECT COUNT(*) FROM events)+(SELECT COUNT(*) FROM quarantine)";
            if (Convert.ToInt32(await count.ExecuteScalarAsync(ct)) >= maxEvents)
                throw new OutboxCapacityException("Critical event cannot be durably retained: outbox capacity reached");
            var diskBytes =
                (File.Exists(databasePath) ? new FileInfo(databasePath).Length : 0)
                + (File.Exists(databasePath + "-wal") ? new FileInfo(databasePath + "-wal").Length : 0);
            if (diskBytes >= maxBytes)
                throw new OutboxCapacityException(
                    "Critical event cannot be durably retained: outbox byte limit reached"
                );
            var id = Guid.NewGuid().ToString("D");
            var when = snapshot?.CollectedAt ?? DateTimeOffset.UtcNow;
            using var insert = db.CreateCommand();
            insert.Transaction = tx;
            insert.CommandText = "INSERT INTO events(id,json) VALUES($id,'') RETURNING seq";
            insert.Parameters.AddWithValue("$id", id);
            var seq = Convert.ToInt64(await insert.ExecuteScalarAsync(ct));
            var evt = new AgentEvent(id, seq, when, type, objectKey, snapshot, detail);
            using var update = db.CreateCommand();
            update.Transaction = tx;
            update.CommandText = "UPDATE events SET json=$json WHERE seq=$seq";
            var serialized = Wire.Serialize(evt);
            if (diskBytes + System.Text.Encoding.UTF8.GetByteCount(serialized) + 8192 >= maxBytes)
                throw new OutboxCapacityException("Critical event exceeds remaining durable outbox byte limit");
            update.Parameters.AddWithValue("$json", serialized);
            update.Parameters.AddWithValue("$seq", seq);
            await update.ExecuteNonQueryAsync(ct);
            tx.Commit();
            return evt;
        }
        finally
        {
            gate.Release();
        }
    }

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
