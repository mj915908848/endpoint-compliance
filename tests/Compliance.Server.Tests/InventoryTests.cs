using System.Net;
using System.Net.Http.Json;
using Compliance.Core;
using Xunit;

namespace Compliance.Server.Tests;

/// <summary>Asset inventory: what clients report about their hardware and software, and what changed.</summary>
public class InventoryTests
{
    const long GB = 1024L * 1024 * 1024;

    static AssetInventory Sample(DateTimeOffset at, params InstalledProgram[] software) =>
        new(
            at,
            new("LENOVO", "ThinkPad T14", "PF3ABCDE", "R1MET70W", "Intel(R) Core(TM) i7-1365U", 10, 12, 16 * GB),
            new("Windows 11 专业版", "10.0.22631.4317", "23H2", "64 位", at.AddDays(-300), at.AddHours(-5)),
            [new("SAMSUNG MZVL2512", 512_000_000_000, "SSD", "NVMe")],
            [new("C:", "", "NTFS", 511_000_000_000, 200_000_000_000)],
            software
        );

    static InstalledProgram P(string name, string version, string scope = Inventory.Machine) =>
        new(name, version, "Vendor", "20260101", scope);

    static Task<HttpResponseMessage> Send(Fixture f, AssetInventory inventory) =>
        f.Agent("POST", "/api/agent/inventory", inventory);

    [Fact]
    public async Task Inventories_are_listed_across_devices_and_their_changes_recorded()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        var first = Sample(
            f.Clock.Now,
            P("Google Chrome", "130.0"),
            P("WeChat", "3.9", "zhangsan"),
            P("WeChat", "3.9", "zhangsan"),
            P("7-Zip", "24.08")
        );
        Assert.Equal(HttpStatusCode.OK, (await Send(f, first)).StatusCode);

        var held = await f.Client.GetFromJsonAsync<DeviceInventory>($"/api/devices/{f.Device}/inventory", Wire.Json);
        Assert.Equal(["7-Zip", "Google Chrome", "WeChat"], held!.Inventory!.Software.Select(p => p.Name));
        Assert.Equal("2026-01-01", held.Inventory.Software[0].InstalledOn);
        Assert.Equal("ThinkPad T14", held.Inventory.Hardware.Model);
        // The first inventory starts the record; it is not a list of programs just installed.
        Assert.Empty(held.Changes);

        var assets = await f.Client.GetFromJsonAsync<AssetRow[]>("/api/assets", Wire.Json);
        Assert.Equal((3, "PF3ABCDE"), (assets!.Single().SoftwareCount, assets[0].Hardware.SerialNumber));

        f.Clock.Now += TimeSpan.FromMinutes(10);
        var second = Sample(
            f.Clock.Now,
            P("Google Chrome", "131.0"),
            P("WeChat", "3.9", "zhangsan"),
            P("Clash Verge", "2.0", "zhangsan")
        ) with
        {
            Hardware = first.Hardware with { MemoryBytes = 32 * GB },
        };
        await Send(f, second);
        // A late copy of an earlier inventory changes nothing.
        Assert.Equal(
            HttpStatusCode.OK,
            (await Send(f, first with { CollectedAt = f.Clock.Now.AddHours(-2) })).StatusCode
        );

        held = await f.Client.GetFromJsonAsync<DeviceInventory>($"/api/devices/{f.Device}/inventory", Wire.Json);
        Assert.Equal(3, held!.Inventory!.Software.Length);
        var changes = held.Changes.Select(c => (c.Kind, c.Subject, c.Detail)).ToArray();
        Assert.Contains(("HardwareChanged", "内存", "16 GB → 32 GB"), changes);
        Assert.Contains(("SoftwareUpdated", "Google Chrome", "130.0 → 131.0"), changes);
        Assert.Contains(("SoftwareInstalled", "Clash Verge", "版本 2.0（用户 zhangsan）"), changes);
        Assert.Contains(("SoftwareRemoved", "7-Zip", "版本 24.08"), changes);
        Assert.Equal(4, changes.Length);

        var recent = await f.Client.GetFromJsonAsync<InventoryChangeRow[]>("/api/assets/changes?days=7", Wire.Json);
        Assert.Equal(4, recent!.Length);
        Assert.All(recent, r => Assert.Equal("host", r.HostName));

        // A second device with another Chrome version: counted per program and per version.
        f.Key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var other = f.Device = (await f.Enroll(await f.Code())).DeviceId;
        await Send(f, Sample(f.Clock.Now, P("Google Chrome", "130.0"), P("Google Chrome", "130.0", "lisi")));
        var software = await f.Client.GetFromJsonAsync<SoftwareSummary[]>("/api/assets/software", Wire.Json);
        var chrome = software!.First();
        Assert.Equal(("Google Chrome", 2), (chrome.Name, chrome.Devices));
        Assert.Equal([("130.0", 1), ("131.0", 1)], chrome.Versions.Select(v => (v.Version, v.Devices)));
        var installs = await f.Client.GetFromJsonAsync<SoftwareInstall[]>(
            "/api/assets/software/devices?name=" + Uri.EscapeDataString("Google Chrome"),
            Wire.Json
        );
        Assert.Equal(3, installs!.Length);

        var csv = await f.Client.GetStringAsync("/api/assets/export.csv");
        Assert.Contains("ThinkPad T14", csv);
        Assert.Contains("32 GB", csv);
        Assert.Contains("Clash Verge", await f.Client.GetStringAsync("/api/assets/software/export.csv"));
        var audit = await f.Client.GetStringAsync("/api/audit");
        Assert.Contains("ExportAssets", audit);
        Assert.Contains("ExportSoftware", audit);

        // Archived devices drop out of the lists; deleted ones take their inventory with them.
        Assert.Equal(
            HttpStatusCode.OK,
            (await f.Client.PostAsJsonAsync("/api/devices/archive", new { ids = new[] { other } })).StatusCode
        );
        Assert.Single((await f.Client.GetFromJsonAsync<AssetRow[]>("/api/assets", Wire.Json))!);
        Assert.Equal(HttpStatusCode.OK, (await f.Client.DeleteAsync($"/api/devices/{other}")).StatusCode);
        software = await f.Client.GetFromJsonAsync<SoftwareSummary[]>("/api/assets/software", Wire.Json);
        Assert.Equal(
            [("Clash Verge", 1), ("Google Chrome", 1), ("WeChat", 1)],
            software!.Select(x => (x.Name, x.Devices))
        );
    }

    [Fact]
    public async Task Inventories_are_checked_and_readers_only_read()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        var many = Enumerable.Range(0, Inventory.MaxSoftware + 1).Select(i => P("p" + i, "1")).ToArray();
        Assert.Equal(HttpStatusCode.BadRequest, (await Send(f, Sample(f.Clock.Now, many))).StatusCode);
        Assert.Equal(
            HttpStatusCode.BadRequest,
            (await Send(f, Sample(f.Clock.Now.AddHours(1), P("a", "1")))).StatusCode
        );
        Assert.Equal(
            HttpStatusCode.BadRequest,
            (await f.Agent("POST", "/api/agent/inventory", new { collectedAt = f.Clock.Now })).StatusCode
        );
        // Without the device's signature the path is refused like every other agent path.
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            (await f.Client.PostAsJsonAsync("/api/agent/inventory", Sample(f.Clock.Now), Wire.Json)).StatusCode
        );

        await f.Login("reader");
        var none = await f.Client.GetFromJsonAsync<DeviceInventory>($"/api/devices/{f.Device}/inventory", Wire.Json);
        Assert.Null(none!.Inventory);
        Assert.Equal(HttpStatusCode.OK, (await f.Client.GetAsync("/api/assets/software")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await f.Client.GetAsync("/api/assets/software/devices")).StatusCode);
    }
}
