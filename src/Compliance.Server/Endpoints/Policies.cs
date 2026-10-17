using Compliance.Core;

namespace Compliance.Server;

public sealed record PolicyListItem(string Key, bool IsDefault, SignedPolicy Release, int Devices);

/// <summary>One earlier release of a policy; PublishedBy is empty once its audit record has been pruned.</summary>
public sealed record PolicyHistoryItem(
    long Version,
    long Serial,
    DateTimeOffset PublishedAt,
    string PublishedBy,
    SignedPolicy Release
);

static partial class Endpoints
{
    static void MapPolicies(IEndpointRouteBuilder routes, ComplianceService s)
    {
        var group = routes.MapGroup("/api/policies");

        // Default first, then by name; Devices counts the devices each policy currently applies to.
        group.MapGet(
            "",
            async (HttpContext c) =>
            {
                Require(c, "Reader");
                return await s.Tx(async tx =>
                {
                    var policies = await s.Policies.All(tx);
                    var devices = await tx.AllDeviceHeads();
                    return policies
                        .Select(p => new PolicyListItem(
                            p.Key,
                            p.IsDefault,
                            p.Release,
                            devices.Count(d => PolicyService.PolicyFor(d.Id, policies) == p)
                        ))
                        .ToArray();
                });
            }
        );

        group.MapGet(
            "/current",
            async (HttpContext c) =>
            {
                Require(c, "Reader");
                return await s.Tx(tx => s.Policies.CurrentRelease(tx));
            }
        );

        // The last 50 releases of a policy, so an administrator can load an earlier one and publish it again.
        group.MapGet(
            "/{key}/history",
            async (HttpContext c, string key) =>
            {
                Require(c, "Reader");
                return await s.Tx(async tx =>
                {
                    if (!(await s.Policies.All(tx)).Any(p => p.Key == key))
                        throw new ApiError(404, "策略不存在或已删除");
                    var publications = await tx.PolicyPublications();
                    var items = new List<PolicyHistoryItem>();
                    foreach (var (serial, at, release) in await tx.PolicyReleases(key, 50))
                    {
                        var doc = Wire.Read<PolicyDocument>(release.Payload);
                        // A re-issue for devices moving between policies repeats the newer release's content.
                        if (items.Count > 0 && items[^1].Version == doc.Version)
                            continue;
                        var target = $"{doc.PolicyId} v{doc.Version}";
                        var by = publications
                            .Where(a => a.Target == target && (a.At - at).Duration() < TimeSpan.FromMinutes(1))
                            .Select(a => a.Actor)
                            .FirstOrDefault();
                        items.Add(new(doc.Version, serial, at, by ?? "", release));
                    }
                    return items;
                });
            }
        );

        // The rule set shipped with this server version, so an upgraded server can adopt new built-in rules
        // by publishing them instead of re-seeding its data.
        group.MapGet(
            "/template",
            (HttpContext c) =>
            {
                Require(c, "Reader");
                return PolicySeed.Create();
            }
        );

        // A Publisher edits and publishes in one step. The server owns the version and validity window so the
        // editor only has to send the rule content. Without a key this publishes the default policy and returns
        // the signed release, as before; "new" creates a policy.
        group.MapPost("", async (HttpContext c) => (await Publish(c, s, PolicyService.DefaultPolicy)).Release);
        group.MapPost("/{key}", (HttpContext c, string key) => Publish(c, s, key == "new" ? null : key));

        group.MapDelete(
            "/{key}",
            async (HttpContext c, string key) =>
            {
                var u = Require(c, "Publisher");
                return await s.Tx(async tx =>
                {
                    await tx.Lock(PolicyService.PolicyLock);
                    var name = await s.Policies.DeletePolicy(tx, key);
                    await tx.Audit(u.Username, "DeletePolicy", name, s.Now);
                    return new { ok = true };
                });
            }
        );
    }

    static async Task<PolicyListItem> Publish(HttpContext c, ComplianceService s, string? key)
    {
        var u = Require(c, "Publisher");
        var doc = await Body<PolicyDocument>(c);
        // The release the editor started from. Without it a release published meanwhile would be replaced unseen.
        long? baseVersion = c.Request.Query.TryGetValue("baseVersion", out var raw)
            ? long.TryParse(raw.ToString(), out var v)
                ? v
                : throw new ApiError(400, "Invalid baseVersion")
            : null;
        return await s.Tx(async tx =>
        {
            await tx.Lock(PolicyService.PolicyLock);
            var (published, signed) = await s.Policies.Publish(tx, key, doc, baseVersion);
            var document = Wire.Read<PolicyDocument>(signed.Payload);
            await tx.Audit(
                u.Username,
                key == null ? "CreatePolicy" : "PublishPolicy",
                $"{document.PolicyId} v{document.Version}",
                s.Now
            );
            var policies = await s.Policies.All(tx);
            var devices = await tx.AllDeviceHeads();
            var state = policies.First(p => p.Key == published);
            return new PolicyListItem(
                published,
                state.IsDefault,
                signed,
                devices.Count(d => PolicyService.PolicyFor(d.Id, policies) == state)
            );
        });
    }
}
