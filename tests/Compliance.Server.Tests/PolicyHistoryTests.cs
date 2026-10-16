using System.Net;
using System.Net.Http.Json;
using Compliance.Core;
using Xunit;

namespace Compliance.Server.Tests;

public class PolicyHistoryTests
{
    [Fact]
    public async Task History_lists_a_policys_releases_newest_first_and_an_old_one_can_be_published_again()
    {
        await using var f = new Fixture();
        await f.Login();
        var device = (await f.Enroll(await f.Code())).DeviceId;
        async Task<PolicyListItem> Publish(string key, PolicyDocument doc)
        {
            var response = await f.Client.PostAsJsonAsync($"/api/policies/{key}", doc, Wire.Json);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return (await response.Content.ReadFromJsonAsync<PolicyListItem>(Wire.Json))!;
        }
        async Task<PolicyHistoryItem[]> History(string key) =>
            (await f.Client.GetFromJsonAsync<PolicyHistoryItem[]>($"/api/policies/{key}/history", Wire.Json))!;

        var pilot = await Publish("new", new PolicyDocument { PolicyId = "研发部", TargetDeviceIds = [device] });
        var original = Wire.Read<PolicyDocument>(pilot.Release.Payload);
        await Publish(pilot.Key, original with { BlockDomains = ["example.com"] });
        // A release of another policy is not part of this one's history.
        await Publish("default", PolicySeed.Create() with { BlockDomains = ["other.example"] });

        var history = await History(pilot.Key);
        Assert.Equal([2L, 1L], history.Select(h => h.Version));
        Assert.Equal([3L, 2L], history.Select(h => h.Serial));
        Assert.All(history, h => Assert.Equal("admin", h.PublishedBy));
        Assert.Equal(["example.com"], Wire.Read<PolicyDocument>(history[0].Release.Payload).BlockDomains);
        Assert.Equal([2L, 1L], (await History("default")).Select(h => h.Version));

        // Restoring publishes the old content as a new version.
        var restored = await Publish(pilot.Key, Wire.Read<PolicyDocument>(history[1].Release.Payload));
        var doc = Wire.Read<PolicyDocument>(restored.Release.Payload);
        Assert.Equal((3L, 5L, original.BlockDomains), (doc.Version, doc.Serial, doc.BlockDomains));
        Assert.Equal(3L, (await History(pilot.Key))[0].Version);

        Assert.Equal(HttpStatusCode.NotFound, (await f.Client.GetAsync("/api/policies/nope/history")).StatusCode);
        await f.Login("reader");
        Assert.Equal(HttpStatusCode.OK, (await f.Client.GetAsync($"/api/policies/{pilot.Key}/history")).StatusCode);
    }
}
