using System.Data.Common;
using System.Globalization;
using Compliance.Core;

namespace Compliance.Server;

public sealed partial class Transaction
{
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

    /// <summary>Deletes at most <paramref name="limit"/> audit records from before <paramref name="cutoff"/>.</summary>
    public Task<int> PruneAudit(DateTimeOffset cutoff, int limit) =>
        Execute(
            "DELETE FROM audit WHERE id IN (SELECT id FROM audit WHERE at < @cutoff LIMIT @limit)",
            ("cutoff", cutoff),
            ("limit", (long)limit)
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
}
