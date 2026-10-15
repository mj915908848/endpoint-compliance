using System.Data.Common;
using System.Globalization;
using Compliance.Core;

namespace Compliance.Server;

/// <summary>
/// One unit of work against the relational schema (see <see cref="Migrations"/>).
/// Times are stored as UTC ticks (BIGINT) so ordering and range filters run in SQL.
/// Only free-form documents (snapshots, controls, policy payloads, event bodies) are JSON text.
/// </summary>
public sealed class Transaction
{
    readonly DbConnection connection;
    readonly DbTransaction transaction;

    internal Transaction(DbConnection connection, DbTransaction transaction, bool isSqlite)
    {
        this.connection = connection;
        this.transaction = transaction;
        IsSqlite = isSqlite;
    }

    internal bool IsSqlite { get; }

    // ---- locking -------------------------------------------------------------------------

    /// <summary>
    /// Serializes concurrent writers that share <paramref name="key"/> until commit or rollback.
    /// SQLite transactions are already serialized by <see cref="Store"/>.
    /// </summary>
    public async Task Lock(string key)
    {
        if (IsSqlite)
            return;
        await Execute("SELECT pg_advisory_xact_lock(hashtextextended(@key, 0))", ("key", key));
    }

    // ---- users and sessions --------------------------------------------------------------

    public Task<UserRecord?> GetUser(string username) =>
        Single(
            "SELECT username, password_hash, roles FROM users WHERE username = @username",
            r => new UserRecord(r.GetString(0), r.GetString(1), Wire.Read<string[]>(r.GetString(2))),
            ("username", username)
        );

    public Task InsertUser(UserRecord user) =>
        Execute(
            "INSERT INTO users(username, password_hash, roles) VALUES(@username, @hash, @roles)",
            ("username", user.Username),
            ("hash", user.PasswordHash),
            ("roles", Wire.Serialize(user.Roles))
        );

    public Task<SessionRecord?> GetSession(string tokenHash) =>
        Single(
            "SELECT username, csrf_token, expires_at FROM sessions WHERE token_hash = @hash",
            r => new SessionRecord(r.GetString(0), r.GetString(1), Time(r, 2)),
            ("hash", tokenHash)
        );

    public Task InsertSession(string tokenHash, SessionRecord session) =>
        Execute(
            "INSERT INTO sessions(token_hash, username, csrf_token, expires_at) VALUES(@hash, @username, @csrf, @expires)",
            ("hash", tokenHash),
            ("username", session.Username),
            ("csrf", session.CsrfToken),
            ("expires", session.ExpiresAt)
        );

    public Task DeleteSession(string tokenHash) =>
        Execute("DELETE FROM sessions WHERE token_hash = @hash", ("hash", tokenHash));

    // ---- enrollment codes ----------------------------------------------------------------

    const string CodeColumns = "id, label, expires_at, max_uses, used, created_at, created_by, revoked";

    static EnrollmentCode ReadCode(DbDataReader r) =>
        new(
            r.GetString(0),
            r.GetString(1),
            Time(r, 2),
            (int)Long(r, 3),
            (int)Long(r, 4),
            Time(r, 5),
            r.GetString(6),
            Long(r, 7) != 0
        );

    public Task<EnrollmentCode?> GetCode(string codeHash) =>
        Single($"SELECT {CodeColumns} FROM enrollment_codes WHERE code_hash = @hash", ReadCode, ("hash", codeHash));

    /// <summary>Codes created since multi-use codes exist, newest first.</summary>
    public Task<List<EnrollmentCode>> RecentCodes(int limit) =>
        Query(
            $"SELECT {CodeColumns} FROM enrollment_codes WHERE id <> '' ORDER BY created_at DESC LIMIT {limit}",
            ReadCode
        );

    public Task InsertCode(string codeHash, EnrollmentCode code) =>
        Execute(
            $"INSERT INTO enrollment_codes(code_hash, {CodeColumns}) VALUES(@hash, @id, @label, @expires, @max, 0, @created, @by, 0)",
            ("hash", codeHash),
            ("id", code.Id),
            ("label", code.Label),
            ("expires", code.ExpiresAt),
            ("max", code.MaxUses),
            ("created", code.CreatedAt),
            ("by", code.CreatedBy)
        );

    /// <summary>Migration 2 imports 0.1.0 codes before migration 5 adds the other columns.</summary>
    public Task InsertLegacyCode(string codeHash, CodeRecord code) =>
        Execute(
            "INSERT INTO enrollment_codes(code_hash, expires_at, used) VALUES(@hash, @expires, @used)",
            ("hash", codeHash),
            ("expires", code.ExpiresAt),
            ("used", code.Used)
        );

    public Task CountCodeUse(string codeHash) =>
        Execute("UPDATE enrollment_codes SET used = used + 1 WHERE code_hash = @hash", ("hash", codeHash));

    public Task<int> RevokeCode(string id) =>
        Execute("UPDATE enrollment_codes SET revoked = 1 WHERE id = @id AND id <> ''", ("id", id));

    // ---- devices -------------------------------------------------------------------------

    // Inserts leave out note (added by migration 3), so the legacy import in migration 2 can still insert.
    const string DeviceColumns =
        "id, host_name, public_key_pem, last_heartbeat, applied_policy_version, controls, snapshot, snapshot_sequence, target_policy_version";
    const string DeviceSelect = DeviceColumns + ", note";

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
            r.GetString(9)
        );

    public Task<DeviceRecord?> GetDevice(string id) =>
        Single($"SELECT {DeviceSelect} FROM devices WHERE id = @id", ReadDevice, ("id", id));

    /// <summary>Request authentication only needs the key, not the snapshot document.</summary>
    public Task<string?> GetDevicePublicKey(string id) =>
        Single("SELECT public_key_pem FROM devices WHERE id = @id", r => r.GetString(0), ("id", id));

    public Task<List<DeviceRecord>> AllDevices() => Query($"SELECT {DeviceSelect} FROM devices", ReadDevice);

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
        await Execute("DELETE FROM nonces WHERE device = @id", ("id", id));
        await Execute("DELETE FROM devices WHERE id = @id", ("id", id));
    }

    public Task UpdateHeartbeat(
        string id,
        string hostName,
        DateTimeOffset at,
        long appliedPolicyVersion,
        ControlState[] controls
    ) =>
        Execute(
            "UPDATE devices SET host_name = @host, last_heartbeat = @at, applied_policy_version = @applied, controls = @controls WHERE id = @id",
            ("host", hostName),
            ("at", at),
            ("applied", appliedPolicyVersion),
            ("controls", Wire.Serialize(controls)),
            ("id", id)
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

    public Task SetTargetPolicy(string id, long version) =>
        Execute("UPDATE devices SET target_policy_version = @version WHERE id = @id", ("version", version), ("id", id));

    /// <summary>Devices whose last heartbeat is at or before <paramref name="cutoff"/> and that have no active offline alert.</summary>
    public Task<List<(string Id, string HostName)>> DevicesGoingOffline(DateTimeOffset cutoff) =>
        Query(
            """
            SELECT d.id, d.host_name FROM devices d
            LEFT JOIN alerts a ON a.id = 'offline:' || d.id
            WHERE d.last_heartbeat IS NOT NULL AND d.last_heartbeat <= @cutoff AND (a.id IS NULL OR a.state <> 'Active')
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

    // ---- events --------------------------------------------------------------------------

    public Task<string?> GetEventFingerprint(string deviceId, string eventId) =>
        Single(
            "SELECT fingerprint FROM events WHERE device_id = @device AND event_id = @event",
            r => r.GetString(0),
            ("device", deviceId),
            ("event", eventId)
        );

    public async Task<bool> SequenceUsed(string deviceId, long sequence) =>
        await Count(
            "SELECT COUNT(*) FROM events WHERE device_id = @device AND sequence = @sequence",
            ("device", deviceId),
            ("sequence", sequence)
        ) > 0;

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

    public Task<AlertSummary?> GetAlert(string id) =>
        Single($"SELECT {AlertColumns} FROM alerts WHERE id = @id", ReadAlert, ("id", id));

    public Task<List<AlertSummary>> AlertsNewestFirst() =>
        Query($"SELECT {AlertColumns} FROM alerts ORDER BY last_seen DESC", ReadAlert);

    public Task UpsertAlert(AlertSummary a) =>
        Execute(
            $"""
            INSERT INTO alerts({AlertColumns})
            VALUES(@id, @device, @host, @type, @key, @summary, @state, @sequence, @first, @last, @ack)
            ON CONFLICT(id) DO UPDATE SET
                device_id = excluded.device_id, host_name = excluded.host_name, type = excluded.type,
                object_key = excluded.object_key, summary = excluded.summary, state = excluded.state,
                last_sequence = excluded.last_sequence, first_seen = excluded.first_seen,
                last_seen = excluded.last_seen, acknowledged = excluded.acknowledged
            """,
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
            ("ack", a.Acknowledged)
        );

    public Task AcknowledgeAlert(string id) => Execute("UPDATE alerts SET acknowledged = 1 WHERE id = @id", ("id", id));

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

    // ---- policy releases and drafts ------------------------------------------------------

    static SignedPolicy ReadRelease(DbDataReader r) => new(r.GetString(0), r.GetString(1), r.GetString(2));

    public Task<SignedPolicy?> GetRelease(long version) =>
        Single(
            "SELECT payload, signature, key_id FROM policy_releases WHERE version = @version",
            ReadRelease,
            ("version", version)
        );

    /// <summary>Releases are immutable and versions strictly increase, so the current policy is the newest release.</summary>
    public Task<SignedPolicy?> CurrentRelease() =>
        Single("SELECT payload, signature, key_id FROM policy_releases ORDER BY version DESC LIMIT 1", ReadRelease);

    public Task InsertRelease(
        long version,
        SignedPolicy signed,
        DateTimeOffset publishedAt,
        string policy = ComplianceService.DefaultPolicy
    ) =>
        Execute(
            // The default policy relies on the column default, so the legacy import (before policy_key existed) works.
            policy == ComplianceService.DefaultPolicy
                ? "INSERT INTO policy_releases(version, payload, signature, key_id, published_at) VALUES(@version, @payload, @signature, @key, @at)"
                : "INSERT INTO policy_releases(version, payload, signature, key_id, published_at, policy_key) VALUES(@version, @payload, @signature, @key, @at, @policy)",
            ("version", version),
            ("payload", signed.Payload),
            ("signature", signed.Signature),
            ("key", signed.KeyId),
            ("at", publishedAt),
            ("policy", policy)
        );

    /// <summary>The newest release of every policy that is not deleted.</summary>
    public Task<List<(string Key, SignedPolicy Release)>> LatestReleases() =>
        Query(
            """
            SELECT r.policy_key, r.payload, r.signature, r.key_id FROM policy_releases r
            JOIN policies p ON p.key = r.policy_key
            WHERE p.deleted_at IS NULL
              AND r.version = (SELECT MAX(x.version) FROM policy_releases x WHERE x.policy_key = r.policy_key)
            """,
            r => (r.GetString(0), new SignedPolicy(r.GetString(1), r.GetString(2), r.GetString(3)))
        );

    public Task InsertPolicy(string key, DateTimeOffset at) =>
        Execute(
            "INSERT INTO policies(key, created_at) VALUES(@key, @at) ON CONFLICT(key) DO NOTHING",
            ("key", key),
            ("at", at)
        );

    public async Task<bool> DeletePolicy(string key, DateTimeOffset at) =>
        await Execute(
            "UPDATE policies SET deleted_at = @at WHERE key = @key AND deleted_at IS NULL",
            ("key", key),
            ("at", at)
        ) == 1;

    const string DraftColumns = "id, document, created_by, approved_by, published, impact_reviewed";

    public Task InsertDraft(DraftRecord d, DateTimeOffset createdAt) =>
        Execute(
            $"INSERT INTO policy_drafts({DraftColumns}, created_at) VALUES(@id, @document, @by, @approved, @published, @impact, @at)",
            ("id", d.Id),
            ("document", Wire.Serialize(d.Document)),
            ("by", d.CreatedBy),
            ("approved", d.ApprovedBy),
            ("published", d.Published),
            ("impact", d.ImpactReviewed),
            ("at", createdAt)
        );

    // ---- device commands -----------------------------------------------------------------

    static CommandRecord ReadCommand(DbDataReader r) =>
        new(
            r.GetString(1),
            new DeviceCommand(r.GetString(0), r.GetString(2), Time(r, 3)),
            r.IsDBNull(4) ? null : Wire.Read<CommandReply>(r.GetString(4))
        );

    public Task<CommandRecord?> GetCommand(string id) =>
        Single("SELECT id, device_id, type, expires_at, reply FROM commands WHERE id = @id", ReadCommand, ("id", id));

    public Task<List<CommandRecord>> PendingCommands(string deviceId, DateTimeOffset now) =>
        Query(
            "SELECT id, device_id, type, expires_at, reply FROM commands WHERE device_id = @device AND reply IS NULL AND expires_at > @now ORDER BY expires_at, id",
            ReadCommand,
            ("device", deviceId),
            ("now", now)
        );

    public Task InsertCommand(CommandRecord c) =>
        Execute(
            "INSERT INTO commands(id, device_id, type, expires_at, reply) VALUES(@id, @device, @type, @expires, @reply)",
            ("id", c.Command.Id),
            ("device", c.DeviceId),
            ("type", c.Command.Type),
            ("expires", c.Command.ExpiresAt),
            ("reply", c.Reply is null ? null : Wire.Serialize(c.Reply))
        );

    public Task SetCommandReply(string id, CommandReply reply) =>
        Execute("UPDATE commands SET reply = @reply WHERE id = @id", ("reply", Wire.Serialize(reply)), ("id", id));

    // ---- audit and replay protection -----------------------------------------------------

    public Task Audit(string actor, string action, string target, DateTimeOffset now) =>
        InsertAudit(new AuditRecord(Guid.NewGuid().ToString(), actor, action, target, now));

    public Task InsertAudit(AuditRecord a) =>
        Execute(
            "INSERT INTO audit(id, at, actor, action, target) VALUES(@id, @at, @actor, @action, @target)",
            ("id", a.Id),
            ("at", a.At),
            ("actor", a.Actor),
            ("action", a.Action),
            ("target", a.Target)
        );

    public Task<List<AuditRecord>> RecentAudit(int limit) =>
        Query(
            "SELECT id, actor, action, target, at FROM audit ORDER BY at DESC LIMIT @limit",
            r => new AuditRecord(r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3), Time(r, 4)),
            ("limit", (long)limit)
        );

    public async Task<bool> AcceptNonce(string device, string nonce, DateTimeOffset now)
    {
        await Execute("DELETE FROM nonces WHERE expires < @now", ("now", now.ToUnixTimeSeconds()));
        return await Execute(
                "INSERT INTO nonces(device, nonce, expires) VALUES(@device, @nonce, @expires) ON CONFLICT(device, nonce) DO NOTHING",
                ("device", device),
                ("nonce", nonce),
                ("expires", now.AddMinutes(10).ToUnixTimeSeconds())
            ) == 1;
    }

    // ---- schema helpers (migrations) -----------------------------------------------------

    internal async Task<bool> TableExists(string name) =>
        await Count(
            IsSqlite
                ? "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = @name"
                : "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = @name",
            ("name", name)
        ) > 0;

    internal Task<List<(string Kind, string Id, string Json)>> LegacyRecords() =>
        Query("SELECT kind, id, json FROM records", r => (r.GetString(0), r.GetString(1), r.GetString(2)));

    // ---- plumbing ------------------------------------------------------------------------

    DbCommand Command(string sql, (string Name, object? Value)[] args)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach (var (name, value) in args)
        {
            var parameter = command.CreateParameter();
            parameter.ParameterName = name;
            parameter.Value = value switch
            {
                null => DBNull.Value,
                bool flag => flag ? 1L : 0L,
                DateTimeOffset time => time.UtcTicks,
                _ => value,
            };
            command.Parameters.Add(parameter);
        }
        return command;
    }

    internal async Task<int> Execute(string sql, params (string Name, object? Value)[] args)
    {
        await using var command = Command(sql, args);
        return await command.ExecuteNonQueryAsync();
    }

    async Task<long> Count(string sql, params (string Name, object? Value)[] args)
    {
        await using var command = Command(sql, args);
        return Convert.ToInt64(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture);
    }

    async Task<List<T>> Query<T>(string sql, Func<DbDataReader, T> map, params (string Name, object? Value)[] args)
    {
        await using var command = Command(sql, args);
        await using var reader = await command.ExecuteReaderAsync();
        var rows = new List<T>();
        while (await reader.ReadAsync())
            rows.Add(map(reader));
        return rows;
    }

    async Task<T?> Single<T>(string sql, Func<DbDataReader, T> map, params (string Name, object? Value)[] args)
        where T : class
    {
        var rows = await Query(sql, map, args);
        return rows.Count == 0 ? null : rows[0];
    }

    static long Long(DbDataReader r, int i) => Convert.ToInt64(r.GetValue(i), CultureInfo.InvariantCulture);

    static DateTimeOffset Time(DbDataReader r, int i) => new(Long(r, i), TimeSpan.Zero);

    static DateTimeOffset? OptionalTime(DbDataReader r, int i) => r.IsDBNull(i) ? null : Time(r, i);
}
