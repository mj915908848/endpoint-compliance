namespace Compliance.Server;

static partial class Endpoints
{
    static void MapAudit(IEndpointRouteBuilder routes, ComplianceService s)
    {
        var group = routes.MapGroup("/api/audit");

        group.MapGet(
            "",
            async (HttpContext c) =>
            {
                Require(c, "Reader");
                return await s.Tx(async tx => (await tx.RecentAudit(500)).ToArray());
            }
        );
    }
}
