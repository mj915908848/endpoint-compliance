using System.Globalization;
using System.Text;
using Compliance.Core;

namespace Compliance.Server;

static partial class Endpoints
{
    static void MapReports(IEndpointRouteBuilder routes, ComplianceService s)
    {
        var group = routes.MapGroup("/api/reports");

        // The compliance report for the days from..to (yyyy-MM-dd, both included) in the time zone offset minutes
        // east of UTC; by default the last 7 days.
        group.MapGet(
            "/compliance",
            async (HttpContext c, string? from, string? to, int? offset) =>
            {
                Require(c, "Reader");
                var (start, end, zone) = Period(s, from, to, offset);
                return await s.Tx(tx => Reports.Load(tx, s, start, end, zone));
            }
        );

        group.MapGet(
            "/compliance.md",
            async (HttpContext c, string? from, string? to, int? offset) =>
            {
                var u = Require(c, "Reader");
                var (start, end, zone) = Period(s, from, to, offset);
                var report = await s.Tx(async tx =>
                {
                    var r = await Reports.Load(tx, s, start, end, zone);
                    await tx.Audit(u.Username, "ExportReport", Reports.Period(r), s.Now);
                    return r;
                });
                return Results.Text(Reports.Markdown(report, zone), "text/markdown; charset=utf-8", Encoding.UTF8);
            }
        );
    }

    static (DateOnly From, DateOnly To, TimeSpan Offset) Period(
        ComplianceService s,
        string? from,
        string? to,
        int? offset
    )
    {
        var zone = TimeSpan.FromMinutes(Math.Clamp(offset ?? 0, -14 * 60, 14 * 60));
        var today = DateOnly.FromDateTime(s.Now.ToOffset(zone).DateTime);
        static DateOnly? Day(string? text) =>
            text is null ? null
            : DateOnly.TryParseExact(text, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d)
                ? d
            : throw new ApiError(400, "日期格式应为 yyyy-MM-dd");
        var end = Day(to) ?? today;
        var start = Day(from) ?? end.AddDays(-6);
        if (start > end)
            throw new ApiError(400, "开始日期不能晚于结束日期");
        if (end > today)
            throw new ApiError(400, "结束日期不能晚于今天");
        if (end.DayNumber - start.DayNumber + 1 > Reports.MaxDays)
            throw new ApiError(400, $"报表最长 {Reports.MaxDays} 天");
        if (start < today.AddDays(-400))
            throw new ApiError(400, "只能查看最近 400 天的报表");
        return (start, end, zone);
    }
}
