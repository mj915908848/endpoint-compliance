using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Compliance.Core;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Compliance.Server.Tests;

public class SettingsTests
{
    const string WeCom = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test";

    static object Notifications(bool enabled = true, string[]? types = null, string url = WeCom) =>
        new
        {
            enabled,
            channel = "WeCom",
            webhookUrl = url,
            types = types ?? ["Violation"],
            consoleUrl = "https://compliance.example.com/",
        };

    static async Task<HttpResponseMessage> Event(Fixture f, long sequence, string type, string key, string detail) =>
        await f.Agent(
            "POST",
            "/api/agent/events",
            new EventBatch([new("e" + sequence, sequence, f.Clock.Now, type, key, Detail: detail)])
        );

    [Fact]
    public async Task New_alerts_are_pushed_once_per_activation_and_only_while_enabled()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        await f.Client.PutAsJsonAsync($"/api/devices/{f.Device}/note", new { note = "张三" });
        var notifier = f.Services.GetRequiredService<AlertNotifier>();

        // Raised while pushing is off: handled without sending, also once it is turned on.
        await Event(f, 1, "Violation", "before", "old violation");
        await notifier.Run();
        Assert.Empty(f.Webhook.Requests);

        Assert.Equal(
            HttpStatusCode.BadRequest,
            (
                await f.Client.PutAsJsonAsync(
                    "/api/settings/notifications",
                    Notifications(url: "https://evil.example/x")
                )
            ).StatusCode
        );
        Assert.Equal(
            HttpStatusCode.OK,
            (await f.Client.PutAsJsonAsync("/api/settings/notifications", Notifications())).StatusCode
        );
        await notifier.Run();
        Assert.Empty(f.Webhook.Requests);

        await Event(f, 2, "Violation", "clash", "Clash 已安装");
        await Event(f, 3, "Health", "agent", "客户端异常");
        await notifier.Run();
        var (url, body) = Assert.Single(f.Webhook.Requests);
        Assert.Equal(WeCom, url.ToString());
        var text = JsonDocument.Parse(body).RootElement.GetProperty("text").GetProperty("content").GetString()!;
        Assert.Contains("新告警 1 条", text);
        Assert.Contains("host（张三）", text);
        Assert.Contains("Clash 已安装", text);
        Assert.DoesNotContain("客户端异常", text);
        Assert.Contains("https://compliance.example.com/alerts", text);

        // Still active: not pushed again. Resolved and raised again: pushed again.
        await Event(f, 4, "Violation", "clash", "Clash 仍在");
        await notifier.Run();
        Assert.Single(f.Webhook.Requests);
        await Event(f, 5, "Recovered", "clash", "已卸载");
        await Event(f, 6, "Violation", "clash", "Clash 又装上了");
        await notifier.Run();
        Assert.Equal(2, f.Webhook.Requests.Count);

        // A refused message is retried on the next run.
        f.Webhook.Reply = """{"errcode":93000,"errmsg":"invalid webhook url"}""";
        await Event(f, 7, "Violation", "v2rayn", "v2rayN 已安装");
        await notifier.Run();
        Assert.False(notifier.Last!.Ok);
        Assert.Contains("93000", notifier.Last.Error);
        f.Webhook.Reply = """{"errcode":0,"errmsg":"ok"}""";
        await notifier.Run();
        Assert.Equal(4, f.Webhook.Requests.Count);
        Assert.True(notifier.Last.Ok);
        await notifier.Run();
        Assert.Equal(4, f.Webhook.Requests.Count);

        var test = await f.Client.PostAsJsonAsync("/api/settings/notifications/test", new { });
        Assert.True((await test.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("ok").GetBoolean());
        Assert.Contains(
            "测试消息",
            JsonDocument
                .Parse(f.Webhook.Requests[^1].Body)
                .RootElement.GetProperty("text")
                .GetProperty("content")
                .GetString()
        );

        var settings = await f.Client.GetFromJsonAsync<JsonElement>("/api/settings");
        Assert.True(settings.GetProperty("notifications").GetProperty("enabled").GetBoolean());
        Assert.Equal(
            "https://compliance.example.com",
            settings.GetProperty("notifications").GetProperty("consoleUrl").GetString()
        );
        await f.Login("reader");
        Assert.Equal(HttpStatusCode.Forbidden, (await f.Client.GetAsync("/api/settings")).StatusCode);
    }

    [Fact]
    public void DingTalk_and_Feishu_messages_are_signed_with_the_secret()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1700000000);
        var ding = AlertNotifier.Request(
            new NotificationSettings
            {
                Channel = "DingTalk",
                WebhookUrl = "https://oapi.dingtalk.com/robot/send?access_token=t",
                Secret = "SEC123",
            },
            "hello",
            now
        );
        var query = ding.RequestUri!.Query;
        Assert.Contains("timestamp=1700000000000", query);
        Assert.Contains("&sign=", query);

        var feishu = AlertNotifier.Request(
            new NotificationSettings
            {
                Channel = "Feishu",
                WebhookUrl = "https://open.feishu.cn/open-apis/bot/v2/hook/x",
                Secret = "SEC123",
            },
            "hello",
            now
        );
        var body = JsonDocument.Parse(feishu.Content!.ReadAsStringAsync().Result).RootElement;
        Assert.Equal("1700000000", body.GetProperty("timestamp").GetString());
        Assert.Equal("hello", body.GetProperty("content").GetProperty("text").GetString());
        // HMAC-SHA256 keyed with "timestamp\nsecret" over nothing, as Feishu documents.
        Assert.Equal(
            Convert.ToBase64String(
                System.Security.Cryptography.HMACSHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes("1700000000\nSEC123"),
                    Array.Empty<byte>()
                )
            ),
            body.GetProperty("sign").GetString()
        );
    }

    [Fact]
    public async Task Changing_the_password_needs_the_current_one_and_signs_out_other_sessions()
    {
        await using var f = new Fixture();
        var other = f.CreateClient(new() { BaseAddress = new("http://localhost") });
        Assert.Equal(
            HttpStatusCode.OK,
            (
                await other.PostAsJsonAsync(
                    "/api/auth/login",
                    new { username = "admin", password = "test-admin-password-long" }
                )
            ).StatusCode
        );
        await f.Login();

        async Task<HttpStatusCode> Change(string current, string next) =>
            (
                await f.Client.PostAsJsonAsync(
                    "/api/auth/password",
                    new { currentPassword = current, newPassword = next }
                )
            ).StatusCode;
        Assert.Equal(HttpStatusCode.BadRequest, await Change("wrong-password", "a-new-password-123"));
        Assert.Equal(HttpStatusCode.BadRequest, await Change("test-admin-password-long", "short"));
        Assert.Equal(HttpStatusCode.OK, await Change("test-admin-password-long", "a-new-password-123"));

        Assert.Equal(HttpStatusCode.OK, (await f.Client.GetAsync("/api/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await other.GetAsync("/api/me")).StatusCode);
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            (
                await other.PostAsJsonAsync(
                    "/api/auth/login",
                    new { username = "admin", password = "test-admin-password-long" }
                )
            ).StatusCode
        );
        Assert.Equal(
            HttpStatusCode.OK,
            (
                await other.PostAsJsonAsync(
                    "/api/auth/login",
                    new { username = "admin", password = "a-new-password-123" }
                )
            ).StatusCode
        );

        // The configured bootstrap password does not come back on restart.
        await using var restart = new Fixture(f.Directory, f.Clock);
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            (
                await restart.Client.PostAsJsonAsync(
                    "/api/auth/login",
                    new { username = "admin", password = "test-admin-password-long" }
                )
            ).StatusCode
        );
    }

    [Fact]
    public async Task Device_list_exports_for_Excel_without_running_formulas()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        await f.Client.PutAsJsonAsync($"/api/devices/{f.Device}/note", new { note = "=HYPERLINK(\"x\")" });
        var response = await f.Client.GetAsync("/api/devices/export.csv");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var csv = await response.Content.ReadAsStringAsync();
        Assert.StartsWith("﻿\"计算机名\",\"备注\"", csv);
        var row = csv.Split("\r\n")[1];
        Assert.StartsWith("\"host\",\"'=HYPERLINK(\"\"x\"\")\",\"\",\"\",\"失联\"", row);
        Assert.Contains(f.Device, row);
        var audit = await f.Client.GetFromJsonAsync<AuditRecord[]>("/api/audit", Wire.Json);
        Assert.Contains(audit!, a => a.Action == "ExportDevices");
    }

    [Fact]
    public async Task Audit_records_are_kept_forever_unless_a_period_is_chosen()
    {
        await using var f = new Fixture();
        await f.Login();
        var service = f.Services.GetRequiredService<ComplianceService>();
        async Task<AuditRecord[]> Audit() => (await f.Client.GetFromJsonAsync<AuditRecord[]>("/api/audit", Wire.Json))!;

        f.Clock.Now = f.Clock.Now.AddDays(400);
        await f.Login();
        await service.Housekeeping.Maintain();
        Assert.Contains(await Audit(), a => a.Action == "CreateUser");

        Assert.Equal(
            HttpStatusCode.BadRequest,
            (await f.Client.PutAsJsonAsync("/api/settings/audit-retention", new { days = 30 })).StatusCode
        );
        Assert.Equal(
            HttpStatusCode.OK,
            (await f.Client.PutAsJsonAsync("/api/settings/audit-retention", new { days = 365 })).StatusCode
        );
        await service.Housekeeping.Maintain();
        var kept = await Audit();
        Assert.DoesNotContain(kept, a => a.Action == "CreateUser");
        Assert.Contains(kept, a => a.Action == "SetAuditRetention");
        Assert.Contains(kept, a => a.Action == "PruneAudit" && a.Actor == "system");
    }
}
