using System.Text;
using Compliance.Core;

namespace Compliance.Server;

static partial class Endpoints
{
    const int MaxNoteLength = 100;

    static void MapDevices(IEndpointRouteBuilder routes, ComplianceService s)
    {
        var group = routes.MapGroup("/api/devices");

        group.MapGet(
            "",
            async (HttpContext c) =>
            {
                Require(c, "Reader");
                return await s.Tx(async tx => (await s.Summaries(tx)).OrderBy(d => d.HostName).ToArray());
            }
        );

        group.MapGet(
            "/export.csv",
            async (HttpContext c) =>
            {
                var u = Require(c, "Reader");
                var rows = await s.Tx(async tx =>
                {
                    var list = await s.Export(tx);
                    await tx.Audit(u.Username, "ExportDevices", $"{list.Count} 台", s.Now);
                    return list;
                });
                return Results.Text(DeviceCsv(rows), "text/csv; charset=utf-8");
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

        // Daily counts of devices by verdict; offset is the browser's time zone in minutes east of UTC.
        group.MapGet(
            "/trend",
            async (HttpContext c, int? days, int? offset) =>
            {
                Require(c, "Reader");
                var span = Math.Clamp(days ?? 30, 1, 90);
                var zone = TimeSpan.FromMinutes(Math.Clamp(offset ?? 0, -14 * 60, 14 * 60));
                var start = VerdictTrend.Start(s.Now, span, zone);
                return await s.Tx(async tx =>
                    VerdictTrend.Daily(
                        s.Now,
                        span,
                        zone,
                        await tx.VerdictsBefore(start),
                        await tx.VerdictChangesSince(start)
                    )
                );
            }
        );

        group.MapGet(
            "/{id}/history",
            async (HttpContext c, string id, int? days) =>
            {
                Require(c, "Reader");
                var since = s.Now - TimeSpan.FromDays(Math.Clamp(days ?? 90, 1, 400));
                return await s.Tx(async tx =>
                {
                    await s.DeviceHead(tx, id);
                    return (await tx.DeviceVerdictChanges(id, since)).ToArray();
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

        // A free-text label such as the employee or department, since host names rarely say whose PC it is.
        group.MapPut(
            "/{id}/note",
            async (HttpContext c, string id) =>
            {
                var u = Require(c, "Operator");
                var note = ((await Body<NoteRequest>(c)).Note ?? "").Trim();
                if (note.Length > MaxNoteLength)
                    throw new ApiError(400, $"备注不能超过 {MaxNoteLength} 个字符");
                return await s.Tx(async tx =>
                {
                    await tx.Lock(ComplianceService.DeviceLock(id));
                    var d = await s.Device(tx, id);
                    await tx.SetDeviceNote(id, note);
                    await tx.Audit(u.Username, "SetDeviceNote", $"{d.HostName}（{id}）：{note}", s.Now);
                    return await s.Summary(tx, d with { Note = note });
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

    /// <summary>
    /// The device list for Excel: UTF-8 with a byte order mark, every field quoted, and fields that start like a
    /// formula prefixed with an apostrophe so a host name or note cannot run as one.
    /// </summary>
    static string DeviceCsv(List<(DeviceSummary Device, string[] Reasons)> rows)
    {
        static string Field(string value)
        {
            if (value.Length > 0 && value[0] is '=' or '+' or '-' or '@' or '\t' or '\r')
                value = "'" + value;
            return "\"" + value.Replace("\"", "\"\"") + "\"";
        }
        static string Time(DateTimeOffset? t) => t is { } v ? v.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") : "";

        var b = new StringBuilder("\uFEFF");
        void Line(IEnumerable<string> fields) => b.Append(string.Join(",", fields.Select(Field))).Append("\r\n");
        Line([
            "计算机名",
            "备注",
            "IP 地址",
            "MAC 地址",
            "在线状态",
            "当前结论",
            "违规对象数",
            "检查说明",
            "防护状态",
            "策略",
            "策略版本",
            "终端已应用",
            "客户端版本",
            "客户端需升级",
            "最近心跳",
            "最近检查",
            "数据来源",
            "上报来源 IP",
            "设备 ID",
        ]);
        foreach (var (d, reasons) in rows.OrderBy(r => r.Device.HostName, StringComparer.CurrentCultureIgnoreCase))
            Line([
                d.HostName,
                d.Note,
                string.Join("；", (d.Network ?? []).SelectMany(a => a.Addresses)),
                string.Join("；", (d.Network ?? []).Select(a => a.Mac)),
                Labels.Online(d.OnlineState),
                Labels.Verdict(d.CurrentVerdict),
                d.ViolationCount.ToString(),
                string.Join("；", reasons),
                d.ProtectionStatus,
                d.PolicyName,
                "v" + d.TargetPolicyVersion,
                Labels.YesNo(d.PolicyApplied),
                d.AgentVersion,
                Labels.YesNo(d.AgentOutdated),
                Time(d.LastHeartbeat),
                Time(d.LastScan),
                d.LastScan == null ? ""
                : d.Simulated ? "模拟数据"
                : "实机采集",
                d.SourceAddress,
                d.Id,
            ]);
        return b.ToString();
    }
}
