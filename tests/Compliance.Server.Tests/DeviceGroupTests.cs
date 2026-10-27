using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Compliance.Core;
using Xunit;

namespace Compliance.Server.Tests;

/// <summary>Device groups: set by enrollment codes or by hand, and the policies that apply to them.</summary>
public class DeviceGroupTests
{
    static async Task<Dictionary<string, DeviceSummary>> Devices(Fixture f) =>
        (await f.Client.GetFromJsonAsync<DeviceSummary[]>("/api/devices", Wire.Json))!.ToDictionary(d => d.Id);

    static async Task<string> GroupCode(Fixture f, string group)
    {
        var r = await f.Client.PostAsJsonAsync("/api/enrollment-codes", new { expiresMinutes = 15, group });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var created = await r.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(group.Trim(), created.GetProperty("group").GetString());
        return created.GetProperty("code").GetString()!;
    }

    static async Task<string> EnrollNew(Fixture f, string code)
    {
        f.Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return f.Device = (await f.Enroll(code)).DeviceId;
    }

    static Task<HttpResponseMessage> SetGroup(Fixture f, string group, params string[] ids) =>
        f.Client.PostAsJsonAsync("/api/devices/group", new { ids, group });

    [Fact]
    public async Task Devices_join_groups_by_code_or_by_hand_and_follow_the_group_policy()
    {
        await using var f = new Fixture();
        await f.Login();
        var created = await f.Client.PostAsJsonAsync(
            "/api/policies/new",
            new PolicyDocument { PolicyId = "研发部策略", TargetGroups = ["研发部"] },
            Wire.Json
        );
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        Assert.Equal(0, (await created.Content.ReadFromJsonAsync<PolicyListItem>(Wire.Json))!.Devices);

        // A code's group is the device's from its enrollment, and so is the group's policy; agents accept it.
        var dev = await EnrollNew(f, await GroupCode(f, " 研发部 "));
        var other = await EnrollNew(f, await f.Code());
        var devices = await Devices(f);
        Assert.Equal(("研发部", "研发部策略"), (devices[dev].Group, devices[dev].PolicyName));
        Assert.Equal(("", "Default"), (devices[other].Group, devices[other].PolicyName));
        Assert.Contains("CreateEnrollmentCode", await f.Client.GetStringAsync("/api/audit"));

        // Moved by hand, case aside: the other device joins the group's policy; leaving it goes back to the default.
        var r = await SetGroup(f, "研发部", dev, other, "missing");
        Assert.Equal(1, (await r.Content.ReadFromJsonAsync<DevicesChanged>(Wire.Json))!.Done);
        Assert.Equal("研发部策略", (await Devices(f))[other].PolicyName);
        var list = await f.Client.GetFromJsonAsync<PolicyListItem[]>("/api/policies", Wire.Json);
        Assert.Equal([(true, 0), (false, 2)], list!.Select(p => (p.IsDefault, p.Devices)));
        await SetGroup(f, "", other);
        devices = await Devices(f);
        Assert.Equal(("", "Default"), (devices[other].Group, devices[other].PolicyName));
        Assert.Contains("SetDeviceGroup", await f.Client.GetStringAsync("/api/audit"));
        Assert.Contains("研发部", await f.Client.GetStringAsync("/api/devices/export.csv"));

        // A policy naming the device itself wins over its group's.
        Assert.Equal(
            HttpStatusCode.OK,
            (
                await f.Client.PostAsJsonAsync(
                    "/api/policies/new",
                    new PolicyDocument { PolicyId = "试点", TargetDeviceIds = [dev] },
                    Wire.Json
                )
            ).StatusCode
        );
        Assert.Equal("试点", (await Devices(f))[dev].PolicyName);

        // One policy per group; groups or devices, not both; enforcement needs named pilot devices.
        async Task<HttpStatusCode> Create(PolicyDocument doc) =>
            (await f.Client.PostAsJsonAsync("/api/policies/new", doc, Wire.Json)).StatusCode;
        Assert.Equal(HttpStatusCode.Conflict, await Create(new() { PolicyId = "重复", TargetGroups = ["研发部"] }));
        Assert.Equal(
            HttpStatusCode.BadRequest,
            await Create(
                new()
                {
                    PolicyId = "混合",
                    TargetGroups = ["销售部"],
                    TargetDeviceIds = [other],
                }
            )
        );
        Assert.Equal(
            HttpStatusCode.BadRequest,
            await Create(
                new()
                {
                    PolicyId = "强制",
                    Mode = "Enforce",
                    TargetGroups = ["销售部"],
                    RequiredControls = ["process"],
                }
            )
        );
        Assert.Equal(HttpStatusCode.BadRequest, (await SetGroup(f, new string('部', 65), other)).StatusCode);

        await f.Login("reader");
        Assert.Equal(HttpStatusCode.Forbidden, (await SetGroup(f, "销售部", other)).StatusCode);
    }
}
