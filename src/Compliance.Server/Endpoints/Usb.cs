using Compliance.Core;

namespace Compliance.Server;

static partial class Endpoints
{
    const int MaxUsbEvents = 1000;
    public static readonly TimeSpan UsbEventRetention = TimeSpan.FromDays(365);

    static void MapUsb(IEndpointRouteBuilder routes, ComplianceService s)
    {
        var group = routes.MapGroup("/api/usb-events");

        // USB disks plugged in, removed and blocked in the last days (30 by default), newest first; of one device, or
        // of every device in use.
        group.MapGet(
            "",
            async (HttpContext c, int? days, string? deviceId) =>
            {
                Require(c, "Reader");
                return await s.Tx(async tx => (await UsbEvents(s, tx, days, deviceId)).ToArray());
            }
        );

        group.MapGet(
            "/export.csv",
            async (HttpContext c, int? days, string? deviceId) =>
            {
                var u = Require(c, "Reader");
                var rows = await s.Tx(async tx =>
                {
                    var list = await UsbEvents(s, tx, days, deviceId);
                    await tx.Audit(u.Username, "ExportUsbEvents", $"{list.Count} 条", s.Now);
                    return list;
                });
                return Results.Text(
                    Csv([
                        ["时间", "计算机名", "备注", "分组", "事件", "设备", "设备实例 ID", "设备 ID"],
                        .. rows.Select(r =>
                            (IEnumerable<string>)
                                [
                                    CsvTime(r.At),
                                    r.HostName,
                                    r.Note,
                                    r.Group,
                                    UsbStorage.EventLabel(r.Type),
                                    r.Detail,
                                    r.InstanceId,
                                    r.DeviceId,
                                ]
                        ),
                    ]),
                    "text/csv; charset=utf-8"
                );
            }
        );
    }

    static async Task<List<UsbEventRow>> UsbEvents(ComplianceService s, Transaction tx, int? days, string? deviceId)
    {
        if (deviceId is not null)
            await s.DeviceHead(tx, deviceId);
        var since = s.Now - TimeSpan.FromDays(Math.Clamp(days ?? 30, 1, 365));
        return await tx.UsbEvents(since, deviceId, MaxUsbEvents);
    }
}
