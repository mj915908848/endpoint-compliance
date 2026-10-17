using System.Data.Common;
using System.Globalization;
using Compliance.Core;

namespace Compliance.Server;

public sealed partial class Transaction
{
    // ---- verdict history -----------------------------------------------------------------

    public Task InsertVerdictChange(VerdictChange c) =>
        Execute(
            "INSERT INTO verdict_history(id, device_id, at, verdict, violation_count, policy_version) VALUES(@id, @device, @at, @verdict, @count, @policy)",
            ("id", Guid.NewGuid().ToString("N")),
            ("device", c.DeviceId),
            ("at", c.At),
            ("verdict", c.Verdict.ToString()),
            ("count", (long)c.ViolationCount),
            ("policy", c.PolicyVersion)
        );

    const string VerdictChangeSelect = "h.device_id, h.at, h.verdict, h.violation_count, h.policy_version";

    static VerdictChange ReadVerdictChange(DbDataReader r) =>
        new(r.GetString(0), Time(r, 1), Enum.Parse<Verdict>(r.GetString(2)), (int)Long(r, 3), Long(r, 4));

    /// <summary>A device's changes at or after <paramref name="since"/>, oldest first.</summary>
    public Task<List<VerdictChange>> DeviceVerdictChanges(string deviceId, DateTimeOffset since) =>
        Query(
            $"SELECT {VerdictChangeSelect} FROM verdict_history h WHERE h.device_id = @device AND h.at >= @since ORDER BY h.at",
            ReadVerdictChange,
            ("device", deviceId),
            ("since", since)
        );

    /// <summary>Changes of every enrolled device at or after <paramref name="since"/>, oldest first.</summary>
    public Task<List<VerdictChange>> VerdictChangesSince(DateTimeOffset since) =>
        Query(
            $"""
            SELECT {VerdictChangeSelect} FROM verdict_history h JOIN devices d ON d.id = h.device_id
            WHERE h.at >= @since ORDER BY h.at
            """,
            ReadVerdictChange,
            ("since", since)
        );

    /// <summary>Each enrolled device's last change before <paramref name="before"/>: its verdict at that moment.</summary>
    public Task<List<VerdictChange>> VerdictsBefore(DateTimeOffset before) =>
        Query(
            $"""
            SELECT {VerdictChangeSelect} FROM verdict_history h JOIN devices d ON d.id = h.device_id
            WHERE h.at = (SELECT MAX(x.at) FROM verdict_history x WHERE x.device_id = h.device_id AND x.at < @before)
            """,
            ReadVerdictChange,
            ("before", before)
        );

    /// <summary>Removes changes older than <paramref name="cutoff"/>, keeping each device's latest so its state stays known.</summary>
    public Task<int> PruneVerdictHistory(DateTimeOffset cutoff, int limit) =>
        Execute(
            """
            DELETE FROM verdict_history WHERE id IN (
                SELECT h.id FROM verdict_history h
                WHERE h.at < @cutoff
                    AND h.at < (SELECT MAX(x.at) FROM verdict_history x WHERE x.device_id = h.device_id)
                LIMIT @limit)
            """,
            ("cutoff", cutoff),
            ("limit", (long)limit)
        );
}
