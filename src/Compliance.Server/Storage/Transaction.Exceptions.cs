using System.Data.Common;
using Compliance.Core;

namespace Compliance.Server;

public sealed partial class Transaction
{
    // ---- exceptions ------------------------------------------------------------------------

    const string ExceptionColumns = """
        x.id, x.device_id, d.host_name, d.note, d.group_name, x.kind, x.target, x.label, x.reason, x.days,
        x.requested_by, x.requested_at, x.status, x.decided_by, x.decided_at, x.expires_at, x.decision_note, x.object_key
        """;

    static StoredException ReadException(DbDataReader r) =>
        new(
            r.GetString(0),
            r.GetString(1),
            r.GetString(2),
            r.GetString(3),
            r.GetString(4),
            r.GetString(5),
            r.GetString(6),
            r.GetString(7),
            r.GetString(8),
            (int)Long(r, 9),
            r.GetString(10),
            OptionalTime(r, 11),
            r.GetString(12),
            r.GetString(13),
            OptionalTime(r, 14),
            OptionalTime(r, 15),
            r.GetString(16),
            r.GetString(17)
        );

    public Task InsertException(StoredException x) =>
        Execute(
            """
            INSERT INTO policy_exceptions(id, device_id, kind, target, label, reason, days, requested_by, requested_at,
                status, decided_by, decided_at, expires_at, decision_note, object_key)
            VALUES(@id, @device, @kind, @target, @label, @reason, @days, @by, @at, @status, @decidedBy, @decidedAt,
                @expires, @note, @key)
            """,
            ("id", x.Id),
            ("device", x.DeviceId),
            ("kind", x.Kind),
            ("target", x.Target),
            ("label", x.Label),
            ("reason", x.Reason),
            ("days", (long)x.Days),
            ("by", x.RequestedBy),
            ("at", x.RequestedAt),
            ("status", x.Status),
            ("decidedBy", x.DecidedBy),
            ("decidedAt", x.DecidedAt),
            ("expires", x.ExpiresAt),
            ("note", x.DecisionNote),
            ("key", x.ObjectKey)
        );

    /// <summary>A request asked again while still pending replaces what it says.</summary>
    public Task RenewPendingException(string id, string reason, int days, string requestedBy, DateTimeOffset at) =>
        Execute(
            "UPDATE policy_exceptions SET reason = @reason, days = @days, requested_by = @by, requested_at = @at WHERE id = @id",
            ("id", id),
            ("reason", reason),
            ("days", (long)days),
            ("by", requestedBy),
            ("at", at)
        );

    public Task Decide(
        string id,
        string status,
        string decidedBy,
        DateTimeOffset decidedAt,
        DateTimeOffset? expiresAt,
        int days,
        string note
    ) =>
        Execute(
            """
            UPDATE policy_exceptions SET status = @status, decided_by = @by, decided_at = @at, expires_at = @expires,
                days = @days, decision_note = @note WHERE id = @id
            """,
            ("id", id),
            ("status", status),
            ("by", decidedBy),
            ("at", decidedAt),
            ("expires", expiresAt),
            ("days", (long)days),
            ("note", note)
        );

    public async Task<StoredException?> GetException(string id) =>
        (
            await Query(
                $"SELECT {ExceptionColumns} FROM policy_exceptions x JOIN devices d ON d.id = x.device_id WHERE x.id = @id",
                ReadException,
                ("id", id)
            )
        ).FirstOrDefault();

    public async Task<StoredException?> PendingException(string deviceId, string kind, string target) =>
        (
            await Query(
                $"""
                SELECT {ExceptionColumns} FROM policy_exceptions x JOIN devices d ON d.id = x.device_id
                WHERE x.device_id = @device AND x.kind = @kind AND x.target = @target AND x.status = 'Pending'
                """,
                ReadException,
                ("device", deviceId),
                ("kind", kind),
                ("target", target)
            )
        ).FirstOrDefault();

    /// <summary>Requests and exceptions, newest first: pending ones, then decided ones.</summary>
    public Task<List<StoredException>> Exceptions(int limit) =>
        Query(
            $"""
            SELECT {ExceptionColumns} FROM policy_exceptions x JOIN devices d ON d.id = x.device_id
            ORDER BY CASE WHEN x.status = 'Pending' THEN 0 ELSE 1 END,
                COALESCE(x.decided_at, x.requested_at) DESC, x.id LIMIT @limit
            """,
            ReadException,
            ("limit", (long)limit)
        );

    /// <summary>Approved exceptions that have not expired at <paramref name="now"/>, of devices still enrolled.</summary>
    public Task<List<StoredException>> ApprovedExceptions(DateTimeOffset now) =>
        Query(
            $"""
            SELECT {ExceptionColumns} FROM policy_exceptions x JOIN devices d ON d.id = x.device_id
            WHERE x.status = 'Approved' AND x.expires_at > @now ORDER BY x.id
            """,
            ReadException,
            ("now", now)
        );
}
