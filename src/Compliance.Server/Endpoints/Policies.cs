using Compliance.Core;

namespace Compliance.Server;

static partial class Endpoints
{
    static void MapPolicies(IEndpointRouteBuilder routes, ComplianceService s)
    {
        var group = routes.MapGroup("/api/policies");

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
        // editor only has to send the rule content.
        group.MapPost(
            "",
            async (HttpContext c) =>
            {
                var u = Require(c, "Publisher");
                var doc = await Body<PolicyDocument>(c);
                return await s.Tx(async tx =>
                {
                    await tx.Lock(ComplianceService.PolicyLock);
                    var signed = await s.Publish(tx, doc);
                    await tx.Audit(
                        u.Username,
                        "PublishPolicy",
                        "v" + Wire.Read<PolicyDocument>(signed.Payload).Version,
                        s.Now
                    );
                    return signed;
                });
            }
        );
    }
}
