using Compliance.Core;

namespace Compliance.Server;

static partial class Endpoints
{
    static void MapDevices(IEndpointRouteBuilder routes, ComplianceService s)
    {
        var group = routes.MapGroup("/api/devices");

        group.MapGet(
            "",
            async (HttpContext c) =>
            {
                Require(c, "Reader");
                return await s.Tx(async tx =>
                {
                    await s.UpdateOffline(tx);
                    var list = new List<DeviceSummary>();
                    foreach (var d in await tx.AllDevices())
                        list.Add(await s.Summary(tx, d));
                    return list.OrderBy(d => d.HostName).ToArray();
                });
            }
        );

        group.MapGet(
            "/{id}",
            async (HttpContext c, string id) =>
            {
                Require(c, "Reader");
                return await s.Tx(async tx =>
                {
                    var d = await s.Device(tx, id);
                    return new
                    {
                        device = await s.Summary(tx, d),
                        snapshot = d.Snapshot,
                        controls = d.Controls ?? [],
                        pendingCommands = (await tx.PendingCommands(id, s.Now)).Count,
                    };
                });
            }
        );

        group.MapGet(
            "/{id}/report",
            async (HttpContext c, string id) =>
            {
                Require(c, "Reader");
                return await s.Tx(async tx => await s.Report(tx, await s.Device(tx, id)));
            }
        );

        group.MapGet(
            "/{id}/report.md",
            async (HttpContext c, string id) =>
            {
                Require(c, "Reader");
                var markdown = await s.Tx(async tx =>
                    ReportRenderer.Markdown(await s.Report(tx, await s.Device(tx, id)))
                );
                return Results.Text(markdown, "text/markdown; charset=utf-8");
            }
        );

        group.MapDelete(
            "/{id}",
            async (HttpContext c, string id) =>
            {
                var u = Require(c, "Operator");
                return await s.Tx(async tx =>
                {
                    await tx.Lock(ComplianceService.DeviceLock(id));
                    var d = await s.Device(tx, id);
                    await tx.DeleteDevice(id);
                    await tx.Audit(u.Username, "DeleteDevice", $"{d.HostName}（{id}）", s.Now);
                    return new { deleted = id };
                });
            }
        );

        group.MapPost(
            "/{id}/commands",
            async (HttpContext c, string id) =>
            {
                var u = Require(c, "Operator");
                var r = await Body<CommandRequest>(c);
                if (r.Type != "ScanNow")
                    throw new ApiError(400, "Only ScanNow is supported");
                return await s.Tx(async tx =>
                {
                    await s.Device(tx, id);
                    var command = new DeviceCommand(Guid.NewGuid().ToString(), "ScanNow", s.Now.AddMinutes(10));
                    await tx.InsertCommand(new CommandRecord(id, command));
                    await tx.Audit(u.Username, "RequestScan", id, s.Now);
                    return command;
                });
            }
        );
    }
}
