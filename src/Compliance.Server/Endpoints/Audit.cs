namespace Compliance.Server;

static partial class Endpoints
{
    static void MapAudit(IEndpointRouteBuilder routes, ComplianceService s)
    {
        var group = routes.MapGroup("/api/audit");

        group.MapGet(
            "",
            async (HttpContext c, DateTimeOffset? before, string? beforeId, int? limit) =>
            {
                Require(c, "Reader");
                var size = Math.Clamp(limit ?? 500, 1, 500);
                return await s.Tx(async tx => (await tx.AuditPage(before, beforeId ?? "", size)).ToArray());
            }
        );
    }
}
