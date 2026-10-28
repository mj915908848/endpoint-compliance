using System.Net;
using System.Net.Http.Json;
using Compliance.Core;
using Xunit;

namespace Compliance.Server.Tests;

/// <summary>USB storage control: the records clients send, the alerts for blocked disks, and the policy setting.</summary>
public class UsbTests
{
    const string Stick = @"USBSTOR\DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00\4C530001&0";

    static AgentEvent Usb(Fixture f, string id, long sequence, string type, string detail) =>
        new(id, sequence, f.Clock.Now, type, UsbStorage.KeyPrefix + Stick, Detail: detail);

    [Fact]
    public async Task Disks_coming_and_going_are_recorded_and_blocked_ones_raise_alerts()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        var batch = new EventBatch([
            Usb(f, "u1", 1, UsbStorage.Connected, "SanDisk Ultra（30 GB，序列号 4C530001），可读写"),
            Usb(f, "u2", 2, UsbStorage.Removed, "SanDisk Ultra（30 GB，序列号 4C530001）"),
        ]);
        Assert.Equal(HttpStatusCode.OK, (await f.Agent("POST", "/api/agent/events", batch)).StatusCode);
        // A retried batch records nothing twice.
        Assert.Equal(HttpStatusCode.OK, (await f.Agent("POST", "/api/agent/events", batch)).StatusCode);
        Assert.Empty((await f.Client.GetFromJsonAsync<AlertSummary[]>("/api/alerts", Wire.Json))!);

        f.Clock.Now += TimeSpan.FromMinutes(1);
        await f.Agent(
            "POST",
            "/api/agent/events",
            new EventBatch([
                Usb(f, "u3", 3, UsbStorage.Blocked, "SanDisk Ultra：单位策略禁止使用 U 盘和移动硬盘，已停用该设备"),
            ])
        );
        var alert = Assert.Single((await f.Client.GetFromJsonAsync<AlertSummary[]>("/api/alerts", Wire.Json))!);
        Assert.Equal((UsbStorage.Blocked, "Active"), (alert.Type, alert.State));

        var records = await f.Client.GetFromJsonAsync<UsbEventRow[]>("/api/usb-events?days=7", Wire.Json);
        Assert.Equal(3, records!.Length);
        Assert.Equal(UsbStorage.Blocked, records[0].Type);
        Assert.All(records, r => Assert.Equal((Stick, "host"), (r.InstanceId, r.HostName)));
        var own = await f.Client.GetFromJsonAsync<UsbEventRow[]>($"/api/usb-events?deviceId={f.Device}", Wire.Json);
        Assert.Equal(3, own!.Length);
        Assert.Equal(HttpStatusCode.NotFound, (await f.Client.GetAsync("/api/usb-events?deviceId=missing")).StatusCode);

        var csv = await f.Client.GetStringAsync("/api/usb-events/export.csv");
        Assert.Contains("已拦截", csv);
        Assert.Contains(Stick, csv);
        Assert.Contains("ExportUsbEvents", await f.Client.GetStringAsync("/api/audit"));

        await f.Login("reader");
        Assert.Equal(3, (await f.Client.GetFromJsonAsync<UsbEventRow[]>("/api/usb-events", Wire.Json))!.Length);

        await f.Login();
        Assert.Equal(HttpStatusCode.OK, (await f.Client.DeleteAsync($"/api/devices/{f.Device}")).StatusCode);
        Assert.Empty((await f.Client.GetFromJsonAsync<UsbEventRow[]>("/api/usb-events", Wire.Json))!);
    }

    [Fact]
    public async Task The_policy_setting_is_checked_and_enforcing_needs_something_to_enforce()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        Assert.Equal(
            HttpStatusCode.BadRequest,
            (await f.Publish(PolicySeed.Create() with { Usb = new() { Storage = "Sometimes" } })).StatusCode
        );
        Assert.Equal(
            HttpStatusCode.BadRequest,
            (
                await f.Publish(
                    PolicySeed.Create() with
                    {
                        Usb = new() { Storage = UsbStorage.Block, AllowedDevices = [new("IK0042"), new("ik0042")] },
                    }
                )
            ).StatusCode
        );
        var ok = await f.Publish(
            PolicySeed.Create() with
            {
                Usb = new()
                {
                    Storage = UsbStorage.ReadOnly,
                    AllowedDevices = [new("PROD_IRONKEY") { Note = "公司加密盘" }],
                },
            }
        );
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        var signed = await (await f.Agent("GET", "/api/agent/policy")).Content.ReadFromJsonAsync<SignedPolicy>(
            Wire.Json
        );
        var held = Wire.Read<PolicyDocument>(signed!.Payload).Usb;
        Assert.Equal((UsbStorage.ReadOnly, "公司加密盘"), (held.Storage, held.AllowedDevices.Single().Note));

        var r = await f.Client.PostAsJsonAsync(
            "/api/policies/new",
            new PolicyDocument
            {
                PolicyId = "usb-pilot",
                Mode = "Enforce",
                TargetDeviceIds = [f.Device],
                RequiredControls = [Controls.Usb],
            },
            Wire.Json
        );
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
        Assert.Contains("移动存储管控", await r.Content.ReadAsStringAsync());
    }
}
