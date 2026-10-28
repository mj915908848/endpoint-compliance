using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Compliance.Core;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Compliance.Server.Tests;

/// <summary>Compliance reports for a period, their export, and the scheduled summary pushed to a group robot.</summary>
public class ReportTests
{
    const string WeCom = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test";

    static async Task Failing(Fixture f, string group)
    {
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        await f.Client.PostAsJsonAsync("/api/devices/group", new { ids = new[] { f.Device }, group });
        var snapshot = new ScanSnapshot
        {
            DeviceId = f.Device,
            HostName = "host",
            CollectedAt = f.Clock.Now,
            PolicyVersion = 1,
            Evidence = [new("cursor", "Cursor", EvidenceKind.Installation, "Cursor", "registry", "Cursor 已安装")],
        };
        await f.Agent(
            "POST",
            "/api/agent/events",
            new EventBatch([new("s1", 1, f.Clock.Now, "Snapshot", "scan", snapshot)])
        );
    }

    static string Day(DateTimeOffset t) => t.ToString("yyyy-MM-dd");

    [Fact]
    public async Task A_report_counts_verdicts_groups_problems_and_devices_still_failing()
    {
        await using var f = new Fixture();
        await f.Login();
        var failedAt = f.Clock.Now;
        await Failing(f, "研发部");
        f.Clock.Now += TimeSpan.FromDays(8);
        await f.Login();

        var from = Day(f.Clock.Now.AddDays(-9));
        var r = (
            await f.Client.GetFromJsonAsync<PeriodReport>(
                $"/api/reports/compliance?from={from}&to={Day(f.Clock.Now)}&offset=0",
                Wire.Json
            )
        )!;
        Assert.Equal(10, r.Days.Length);
        Assert.Equal(new ReportCounts(0, 0, 0, 0), r.Start);
        Assert.Equal(new ReportCounts(1, 0, 1, 0), r.End);
        Assert.Equal(new ReportGroup("研发部", 1, 0, 1, 0), Assert.Single(r.Groups));
        var issue = Assert.Single(r.Issues);
        Assert.Equal(("Violation", "Cursor", 1, 1), (issue.Type, issue.Subject, issue.Devices, issue.Alerts));
        Assert.Equal(("Violation", 1), (r.AlertTypes[0].Type, r.AlertTypes[0].Opened));
        var lingering = Assert.Single(r.Lingering);
        Assert.Equal(
            (f.Device, "研发部", failedAt, 1),
            (lingering.DeviceId, lingering.Group, lingering.Since, lingering.ViolationCount)
        );

        // A week before the device reported, nothing yet; the default is the last 7 days.
        var earlier = (
            await f.Client.GetFromJsonAsync<PeriodReport>(
                $"/api/reports/compliance?from={Day(failedAt.AddDays(-7))}&to={Day(failedAt.AddDays(-1))}",
                Wire.Json
            )
        )!;
        Assert.Equal(0, earlier.End.Devices);
        Assert.Empty(earlier.Issues);
        Assert.Equal(
            7,
            (await f.Client.GetFromJsonAsync<PeriodReport>("/api/reports/compliance", Wire.Json))!.Days.Length
        );

        foreach (
            var bad in new[]
            {
                $"from={Day(f.Clock.Now)}&to={Day(f.Clock.Now.AddDays(-1))}",
                $"to={Day(f.Clock.Now.AddDays(1))}",
                "from=2026/10/01",
                $"from={Day(f.Clock.Now.AddDays(-400))}&to={Day(f.Clock.Now)}",
            }
        )
            Assert.Equal(
                HttpStatusCode.BadRequest,
                (await f.Client.GetAsync("/api/reports/compliance?" + bad)).StatusCode
            );

        await f.Login("reader");
        var markdown = await f.Client.GetStringAsync($"/api/reports/compliance.md?from={from}&to={Day(f.Clock.Now)}");
        Assert.Contains("# 终端合规报表", markdown);
        Assert.Contains("| 研发部 | 1 | 0 | 1 | 0 | 0% |", markdown);
        Assert.Contains("| 违规 | Cursor | 1 | 1 |", markdown);
        Assert.Contains("8 天（超期）", markdown);
        await f.Login();
        Assert.Contains("ExportReport", await f.Client.GetStringAsync("/api/audit"));
    }

    [Fact]
    public void Reports_are_due_on_monday_or_the_first_from_nine_for_a_day()
    {
        var china = TimeSpan.FromHours(8);
        DateTimeOffset At(string local) => DateTimeOffset.Parse(local + "+08:00");
        // 2026-11-02 is a Monday.
        Assert.Null(AlertNotifier.DueReport(NotificationSettings.Weekly, At("2026-11-02T08:59:00"), china));
        Assert.Equal(
            (new DateOnly(2026, 10, 26), new DateOnly(2026, 11, 1), "上周合规周报"),
            AlertNotifier.DueReport(NotificationSettings.Weekly, At("2026-11-02T09:00:00"), china)
        );
        Assert.NotNull(AlertNotifier.DueReport(NotificationSettings.Weekly, At("2026-11-03T08:59:00"), china));
        Assert.Null(AlertNotifier.DueReport(NotificationSettings.Weekly, At("2026-11-03T09:00:00"), china));
        Assert.Equal(
            (new DateOnly(2026, 10, 1), new DateOnly(2026, 10, 31), "上月合规月报"),
            AlertNotifier.DueReport(NotificationSettings.Monthly, At("2026-11-01T10:00:00"), china)
        );
        Assert.Null(AlertNotifier.DueReport(NotificationSettings.Monthly, At("2026-11-02T10:00:00"), china));
        Assert.Null(AlertNotifier.DueReport(NotificationSettings.Off, At("2026-11-02T10:00:00"), china));
    }

    [Fact]
    public async Task The_scheduled_report_is_pushed_once_per_period()
    {
        await using var f = new Fixture();
        await f.Login();
        await Failing(f, "");
        var notifier = f.Services.GetRequiredService<AlertNotifier>();
        var put = await f.Client.PutAsJsonAsync(
            "/api/settings/notifications",
            new
            {
                enabled = true,
                channel = "WeCom",
                webhookUrl = WeCom,
                types = Array.Empty<string>(),
                consoleUrl = "https://compliance.example.com",
                reportSchedule = "Weekly",
            }
        );
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);
        var settings = await f.Client.GetFromJsonAsync<JsonElement>("/api/settings", Wire.Json);
        Assert.Equal("Weekly", settings.GetProperty("notifications").GetProperty("reportSchedule").GetString());

        // Next Monday 09:30 where the server runs.
        var offset = TimeZoneInfo.Local.GetUtcOffset(f.Clock.Now);
        var local = f.Clock.Now.ToOffset(offset);
        var monday = local.Date.AddDays(7 - ((int)local.DayOfWeek + 6) % 7);
        f.Clock.Now = new DateTimeOffset(monday.AddHours(9.5), offset);
        await notifier.RunReports();
        var (_, body) = Assert.Single(f.Webhook.Requests);
        var text = JsonDocument.Parse(body).RootElement.GetProperty("text").GetProperty("content").GetString()!;
        Assert.Contains("【终端合规】上周合规周报", text);
        Assert.Contains("不通过 1", text);
        Assert.Contains("最常见的问题：Cursor（1 台）", text);
        Assert.Contains($"https://compliance.example.com/reports?from={monday.AddDays(-7):yyyy-MM-dd}", text);

        await notifier.RunReports();
        f.Clock.Now += TimeSpan.FromHours(2);
        await notifier.RunReports();
        Assert.Single(f.Webhook.Requests);

        await f.Login();
        Assert.Equal(
            HttpStatusCode.BadRequest,
            (
                await f.Client.PutAsJsonAsync(
                    "/api/settings/notifications",
                    new
                    {
                        enabled = true,
                        channel = "WeCom",
                        webhookUrl = WeCom,
                        types = Array.Empty<string>(),
                        reportSchedule = "Off",
                    }
                )
            ).StatusCode
        );
    }
}
