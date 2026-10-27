using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Compliance.Core;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Compliance.Server.Tests;

/// <summary>Archiving devices, what clients report about themselves, and staged upgrades with their outcomes.</summary>
public class DeviceLifecycleTests
{
    // Each test device signs with its own key.
    static readonly System.Runtime.CompilerServices.ConditionalWeakTable<Fixture, Dictionary<string, ECDsa>> Keys = [];

    static async Task<string> Enroll(Fixture f, string version = "0.2.8")
    {
        f.Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        Keys.GetOrCreateValue(f)[f.Device] = f.Key;
        await Heartbeat(f, version);
        return f.Device;
    }

    static void Use(Fixture f, string device)
    {
        f.Device = device;
        f.Key = Keys.GetOrCreateValue(f)[device];
    }

    static async Task<HttpResponseMessage> Heartbeat(
        Fixture f,
        string version = "0.2.8",
        ClientHealth? health = null,
        UpgradeOutcome? upgrade = null
    ) =>
        await f.Agent(
            "POST",
            "/api/agent/heartbeat",
            new HeartbeatRequest("host", version, f.Clock.Now, 1, [], Health: health, Upgrade: upgrade)
        );

    static async Task<DeviceSummary[]> Devices(Fixture f, bool archived = false) =>
        (await f.Client.GetFromJsonAsync<DeviceSummary[]>($"/api/devices?archived={archived}", Wire.Json))!;

    static async Task<AlertSummary[]> Alerts(Fixture f) =>
        (await f.Client.GetFromJsonAsync<AlertSummary[]>("/api/alerts", Wire.Json))!;

    [Fact]
    public async Task Archived_devices_leave_lists_and_alerts_and_come_back_when_they_report()
    {
        await using var f = new Fixture();
        await f.Login();
        var kept = await Enroll(f);
        var archived = await Enroll(f);
        var service = f.Services.GetRequiredService<ComplianceService>();
        f.Clock.Now += TimeSpan.FromMinutes(10);
        await service.Tx(async tx =>
        {
            await service.Housekeeping.UpdateOffline(tx);
            return true;
        });
        Assert.Equal(2, (await Alerts(f)).Count(a => a.Type == "Offline" && a.State == "Active"));

        var r = await f.Client.PostAsJsonAsync("/api/devices/archive", new { ids = new[] { archived, archived } });
        Assert.Equal(1, (await r.Content.ReadFromJsonAsync<DevicesChanged>(Wire.Json))!.Done);
        Assert.Equal([kept], (await Devices(f)).Select(d => d.Id));
        var listed = Assert.Single(await Devices(f, archived: true));
        Assert.Equal((archived, f.Clock.Now), (listed.Id, listed.ArchivedAt));
        Assert.DoesNotContain(await Alerts(f), a => a.DeviceId == archived && a.State == "Active");
        // Archiving again changes nothing; an archived device is never reported offline again.
        r = await f.Client.PostAsJsonAsync("/api/devices/archive", new { ids = new[] { archived } });
        Assert.Equal(0, (await r.Content.ReadFromJsonAsync<DevicesChanged>(Wire.Json))!.Done);
        await service.Tx(async tx =>
        {
            await service.Housekeeping.UpdateOffline(tx);
            return true;
        });
        Assert.DoesNotContain(await Alerts(f), a => a.DeviceId == archived && a.State == "Active");

        // Reporting again takes it out of the archive.
        Use(f, archived);
        Assert.Equal(HttpStatusCode.OK, (await Heartbeat(f)).StatusCode);
        Assert.Empty(await Devices(f, archived: true));
        Assert.Equal(2, (await Devices(f)).Length);
        Assert.Contains("RestoreDevice", await f.Client.GetStringAsync("/api/audit"));

        // Restoring by hand and deleting several at once.
        await f.Client.PostAsJsonAsync("/api/devices/archive", new { ids = new[] { archived } });
        r = await f.Client.PostAsJsonAsync("/api/devices/restore", new { ids = new[] { archived } });
        Assert.Equal(1, (await r.Content.ReadFromJsonAsync<DevicesChanged>(Wire.Json))!.Done);
        r = await f.Client.PostAsJsonAsync("/api/devices/delete", new { ids = new[] { kept, archived, "missing" } });
        Assert.Equal(2, (await r.Content.ReadFromJsonAsync<DevicesChanged>(Wire.Json))!.Done);
        Assert.Empty(await Devices(f));
        Assert.Equal(
            HttpStatusCode.BadRequest,
            (await f.Client.PostAsJsonAsync("/api/devices/delete", new { ids = Array.Empty<string>() })).StatusCode
        );

        await f.Login("reader");
        Assert.Equal(
            HttpStatusCode.Forbidden,
            (await f.Client.PostAsJsonAsync("/api/devices/archive", new { ids = new[] { kept } })).StatusCode
        );
    }

    [Fact]
    public async Task Tamper_events_alert_and_a_shut_down_device_is_not_reported_offline()
    {
        await using var f = new Fixture();
        await f.Login();
        await Enroll(f);
        var r = await f.Agent(
            "POST",
            "/api/agent/events",
            new EventBatch([
                new("t1", 1, f.Clock.Now, "Tamper", "tamper:service-start", Detail: "启动类型被改为“禁用”，已恢复"),
                new("t2", 2, f.Clock.Now, "Shutdown", "agent:power", Detail: "系统关机或重启"),
            ])
        );
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var alert = Assert.Single(await Alerts(f));
        Assert.Equal(("Tamper", "tamper:service-start", "Active"), (alert.Type, alert.ObjectKey, alert.State));
        Assert.Equal("Shutdown", Assert.Single(await Devices(f)).OnlineState);

        // Off for the night: no offline alert. Started again, it is online, and silence is an outage again.
        var service = f.Services.GetRequiredService<ComplianceService>();
        async Task Housekeeping() =>
            await service.Tx(async tx =>
            {
                await service.Housekeeping.UpdateOffline(tx);
                return true;
            });
        f.Clock.Now += TimeSpan.FromHours(10);
        await Housekeeping();
        await f.Login(); // the session timed out overnight
        Assert.DoesNotContain(await Alerts(f), a => a.Type == "Offline");
        await Heartbeat(f);
        Assert.Equal("Online", Assert.Single(await Devices(f)).OnlineState);
        f.Clock.Now += TimeSpan.FromMinutes(10);
        await Housekeeping();
        Assert.Contains(await Alerts(f), a => a.Type == "Offline" && a.State == "Active");
        Assert.Equal("Offline", Assert.Single(await Devices(f)).OnlineState);
    }

    [Fact]
    public async Task Devices_silent_for_the_chosen_days_are_archived_by_maintenance()
    {
        await using var f = new Fixture();
        await f.Login();
        var silent = await Enroll(f);
        var settings = await f.Client.GetFromJsonAsync<AppSettings>("/api/settings", Wire.Json);
        Assert.Equal(Housekeeping.DefaultArchiveDays, settings!.ArchiveDays);
        Assert.Equal(
            HttpStatusCode.BadRequest,
            (await f.Client.PutAsJsonAsync("/api/settings/archive-days", new { days = 7 })).StatusCode
        );
        Assert.Equal(
            HttpStatusCode.OK,
            (await f.Client.PutAsJsonAsync("/api/settings/archive-days", new { days = 60 })).StatusCode
        );
        f.Clock.Now += TimeSpan.FromDays(59);
        await f.Login();
        var active = await Enroll(f);
        var service = f.Services.GetRequiredService<ComplianceService>();
        await service.Housekeeping.Maintain();
        Assert.Null((await service.Tx(tx => tx.RequireDeviceHead(silent))).ArchivedAt);
        f.Clock.Now += TimeSpan.FromDays(2);
        await service.Housekeeping.Maintain();
        Assert.NotNull((await service.Tx(tx => tx.RequireDeviceHead(silent))).ArchivedAt);
        Assert.Null((await service.Tx(tx => tx.RequireDeviceHead(active))).ArchivedAt);

        // 0 turns it off.
        await f.Login();
        await f.Client.PutAsJsonAsync("/api/settings/archive-days", new { days = 0 });
        f.Clock.Now += TimeSpan.FromDays(400);
        await service.Housekeeping.Maintain();
        Assert.Null((await service.Tx(tx => tx.RequireDeviceHead(active))).ArchivedAt);
    }

    [Fact]
    public async Task A_client_reporting_problems_raises_one_alert_that_resolves_when_they_clear()
    {
        await using var f = new Fixture();
        await f.Login();
        await Enroll(f);
        var started = f.Clock.Now - TimeSpan.FromHours(2);
        var well = new ClientHealth(started, 3, f.Clock.Now, f.Clock.Now, 0, 0);
        Assert.Equal(HttpStatusCode.OK, (await Heartbeat(f, health: well)).StatusCode);
        Assert.DoesNotContain(await Alerts(f), a => a.Type == "Health");

        var stuck = well with { Queued = 500, OldestQueued = f.Clock.Now - TimeSpan.FromHours(3) };
        await Heartbeat(
            f,
            health: stuck with
            {
                EnforcementError = "IOException: disk full",
                EnforcementErrorAt = f.Clock.Now,
            }
        );
        var alert = Assert.Single(await Alerts(f), a => a.Type == "Health");
        Assert.Equal("Active", alert.State);
        Assert.Contains("积压", alert.Summary);
        Assert.Contains("结束禁用程序", alert.Summary);
        var detail = await f.Client.GetFromJsonAsync<DeviceDetail>($"/api/devices/{f.Device}", Wire.Json);
        Assert.Equal(500, detail!.Health!.Queued);
        Assert.Equal(2, detail.HealthProblems!.Length);

        // The enforcement error ages out; the backlog stays.
        f.Clock.Now += ClientStatus.EnforcementErrorAge;
        await Heartbeat(f, health: stuck);
        alert = Assert.Single(await Alerts(f), a => a.Type == "Health");
        Assert.DoesNotContain("结束禁用程序", alert.Summary);

        await Heartbeat(f, health: well);
        Assert.Equal("Resolved", Assert.Single(await Alerts(f), a => a.Type == "Health").State);

        Assert.Equal(HttpStatusCode.BadRequest, (await Heartbeat(f, health: well with { Queued = -1 })).StatusCode);
    }

    static Task<HttpResponseMessage> Upload(Fixture f, string version)
    {
        var bytes = RandomNumberGenerator.GetBytes(4096);
        PackageCrypto.MsiSignature.CopyTo(bytes);
        var content = new ByteArrayContent(bytes);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        return f.Client.PostAsync($"/api/client-packages?version={version}", content);
    }

    static async Task<DeviceCommand[]> Commands(Fixture f) =>
        (await (await f.Agent("GET", "/api/agent/commands")).Content.ReadFromJsonAsync<DeviceCommand[]>(Wire.Json))!;

    static async Task<UpgradeProgress> Progress(Fixture f) =>
        (await f.Client.GetFromJsonAsync<UpgradeProgress>("/api/client-packages/0.2.30/rollout", Wire.Json))!;

    [Fact]
    public async Task A_staged_rollout_reaches_online_devices_first_and_shows_how_each_upgrade_ended()
    {
        await using var f = new Fixture();
        await f.Login();
        var away = await Enroll(f);
        f.Clock.Now += TimeSpan.FromMinutes(10);
        var first = await Enroll(f);
        var second = await Enroll(f);
        var third = await Enroll(f);
        Assert.Equal(HttpStatusCode.OK, (await Upload(f, "0.2.30")).StatusCode);

        Assert.Equal(
            HttpStatusCode.BadRequest,
            (await f.Client.PostAsync("/api/client-packages/0.2.30/rollout?count=0", null)).StatusCode
        );
        var r = await f.Client.PostAsync("/api/client-packages/0.2.30/rollout?count=2", null);
        Assert.Equal(2, (await r.Content.ReadFromJsonAsync<UpgradeRollout>(Wire.Json))!.Queued);
        var progress = await Progress(f);
        Assert.Equal(2, progress.Remaining);
        Assert.All(progress.Devices, d => Assert.Equal("Waiting", d.State));
        Assert.DoesNotContain(progress.Devices, d => d.DeviceId == away);
        var sent = progress.Devices.Select(d => d.DeviceId).ToHashSet();

        // One device installs and reports success by its version, the other reports a failed installer.
        Use(f, sent.First());
        var command = Assert.Single(await Commands(f));
        await f.Agent("POST", $"/api/agent/commands/{command.Id}/ack", new CommandReply(true, "开始安装"));
        Assert.Equal("Installing", (await Progress(f)).Devices.Single(d => d.DeviceId == f.Device).State);
        await Heartbeat(f, "0.2.30", upgrade: new(command.Id, "0.2.30", true, "已升级到 0.2.30"));

        Use(f, sent.Last());
        command = Assert.Single(await Commands(f));
        await f.Agent("POST", $"/api/agent/commands/{command.Id}/ack", new CommandReply(true, "开始安装"));
        await Heartbeat(f, upgrade: new(command.Id, "0.2.30", false, "安装程序返回 1603"));
        // A second report of the same upgrade is not recorded again.
        await Heartbeat(f, upgrade: new(command.Id, "0.2.30", true, "later"));

        progress = await Progress(f);
        Assert.Equal("Succeeded", progress.Devices.Single(d => d.DeviceId == sent.First()).State);
        var failed = progress.Devices.Single(d => d.DeviceId == sent.Last());
        Assert.Equal(("Failed", "安装程序返回 1603"), (failed.State, failed.Detail));
        var audit = await f.Client.GetStringAsync("/api/audit");
        Assert.Contains("UpgradeFailed", audit);
        Assert.Contains("UpgradeSucceeded", audit);

        // The rest go next, the failed one with them; the one on the new version does not.
        r = await f.Client.PostAsync("/api/client-packages/0.2.30/rollout", null);
        Assert.Equal(3, (await r.Content.ReadFromJsonAsync<UpgradeRollout>(Wire.Json))!.Queued);
        progress = await Progress(f);
        Assert.Equal(0, progress.Remaining);
        Assert.Equal(new[] { away, first, second, third }.Order(), progress.Devices.Select(d => d.DeviceId).Order());

        // Started but never reported: after an hour it did not take effect.
        Use(f, away);
        command = Assert.Single(await Commands(f));
        await f.Agent("POST", $"/api/agent/commands/{command.Id}/ack", new CommandReply(true, "开始安装"));
        f.Clock.Now += ClientStatus.InstallTimeout;
        await f.Login();
        Assert.Equal("NotApplied", (await Progress(f)).Devices.Single(d => d.DeviceId == away).State);
    }
}
