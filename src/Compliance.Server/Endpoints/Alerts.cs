namespace Compliance.Server;

static partial class Endpoints
{
    static void MapAlerts(IEndpointRouteBuilder routes, ComplianceService s)
    {
        var group = routes.MapGroup("/api/alerts");

        group.MapGet(
            "",
            async (HttpContext c) =>
            {
                Require(c, "Reader");
                return await s.Tx(async tx =>
                    (await tx.AlertsNewestFirst(s.Now - ComplianceService.RecentlyResolved)).ToArray()
                );
            }
        );

        // Older resolved alerts, a page at a time: pass the last alert shown as before/beforeId.
        group.MapGet(
            "/resolved",
            async (HttpContext c, DateTimeOffset before, string beforeId, int? limit) =>
            {
                Require(c, "Reader");
                var size = Math.Clamp(limit ?? 100, 1, 500);
                return await s.Tx(async tx => (await tx.ResolvedAlertsBefore(before, beforeId, size)).ToArray());
            }
        );

        group.MapPost(
            "/{id}/ack",
            async (HttpContext c, string id) =>
            {
                var u = Require(c, "Operator");
                return await s.Tx(async tx =>
                {
                    var a = await tx.GetAlert(id) ?? throw new ApiError(404, "Alert not found");
                    await tx.Lock(ComplianceService.DeviceLock(a.DeviceId));
                    await tx.AcknowledgeAlert(id);
                    await tx.Audit(u.Username, "AcknowledgeAlert", id, s.Now);
                    return new { ok = true };
                });
            }
        );
    }
}
