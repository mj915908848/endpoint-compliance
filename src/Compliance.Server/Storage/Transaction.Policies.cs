using System.Data.Common;
using System.Globalization;
using Compliance.Core;

namespace Compliance.Server;

public sealed partial class Transaction
{
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
        string policy = PolicyService.DefaultPolicy
    ) =>
        Execute(
            // The default policy relies on the column default, so the legacy import (before policy_key existed) works.
            policy == PolicyService.DefaultPolicy
                ? "INSERT INTO policy_releases(version, payload, signature, key_id, published_at) VALUES(@version, @payload, @signature, @key, @at)"
                : "INSERT INTO policy_releases(version, payload, signature, key_id, published_at, policy_key) VALUES(@version, @payload, @signature, @key, @at, @policy)",
            ("version", version),
            ("payload", signed.Payload),
            ("signature", signed.Signature),
            ("key", signed.KeyId),
            ("at", publishedAt),
            ("policy", policy)
        );

    /// <summary>A policy's releases with their serials, newest first.</summary>
    public Task<List<(long Serial, DateTimeOffset PublishedAt, SignedPolicy Release)>> PolicyReleases(
        string key,
        int limit
    ) =>
        Query(
            """
            SELECT version, published_at, payload, signature, key_id FROM policy_releases
            WHERE policy_key = @key ORDER BY version DESC LIMIT @limit
            """,
            r => (r.GetInt64(0), Time(r, 1), new SignedPolicy(r.GetString(2), r.GetString(3), r.GetString(4))),
            ("key", key),
            ("limit", (long)limit)
        );

    /// <summary>Audit records of policy publications, whose target is "{name} v{version}".</summary>
    public Task<List<AuditRecord>> PolicyPublications() =>
        Query(
            "SELECT id, actor, action, target, at FROM audit WHERE action IN ('CreatePolicy', 'PublishPolicy')",
            r => new AuditRecord(r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3), Time(r, 4))
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
}
