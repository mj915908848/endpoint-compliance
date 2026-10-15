using Compliance.Core;

namespace Compliance.Server;

public sealed record PolicyListItem(string Key, bool IsDefault, SignedPolicy Release, int Devices);

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
                    var policies = await s.Policies(tx);
                    var devices = await tx.AllDevices();
                    return policies
                        .Select(p => new PolicyListItem(
                            p.Key,
                            p.IsDefault,
                            p.Release,
                            devices.Count(d => ComplianceService.PolicyFor(d.Id, policies) == p)
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
                return await s.Tx(tx => s.CurrentRelease(tx));
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
        group.MapPost("", async (HttpContext c) => (await Publish(c, s, ComplianceService.DefaultPolicy)).Release);
        group.MapPost("/{key}", (HttpContext c, string key) => Publish(c, s, key == "new" ? null : key));

        group.MapDelete(
            "/{key}",
            async (HttpContext c, string key) =>
            {
                var u = Require(c, "Publisher");
                return await s.Tx(async tx =>
                {
                    await tx.Lock(ComplianceService.PolicyLock);
                    var name = await s.DeletePolicy(tx, key);
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
        return await s.Tx(async tx =>
        {
            await tx.Lock(ComplianceService.PolicyLock);
            var (published, signed) = await s.Publish(tx, key, doc);
            var document = Wire.Read<PolicyDocument>(signed.Payload);
            await tx.Audit(
                u.Username,
                key == null ? "CreatePolicy" : "PublishPolicy",
                $"{document.PolicyId} v{document.Version}",
                s.Now
            );
            var policies = await s.Policies(tx);
            var devices = await tx.AllDevices();
            var state = policies.First(p => p.Key == published);
            return new PolicyListItem(
                published,
                state.IsDefault,
                signed,
                devices.Count(d => ComplianceService.PolicyFor(d.Id, policies) == state)
            );
        });
    }
}
