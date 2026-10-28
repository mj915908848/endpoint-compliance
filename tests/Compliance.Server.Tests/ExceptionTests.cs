using System.Net;
using System.Net.Http.Json;
using Compliance.Core;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Compliance.Server.Tests;

/// <summary>Exception approval: requests from devices, decisions, and the exceptions policies carry to devices.</summary>
public class ExceptionTests
{
    const string Stick = @"USBSTOR\DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00\4C530001&0";

    static AgentEvent Request(Fixture f, string id, long sequence, ExceptionRequest r) =>
        new(
            id,
            sequence,
            f.Clock.Now,
            PolicyExceptions.RequestEvent,
            $"exception:{r.Kind}:{r.Target}",
            Detail: PolicyExceptions.Serialize(r)
        );

    static async Task<PolicyException[]> Held(Fixture f) =>
        Wire.Read<PolicyDocument>(
            (
                await (await f.Agent("GET", "/api/agent/policy")).Content.ReadFromJsonAsync<SignedPolicy>(Wire.Json)
            )!.Payload
        ).Exceptions;

    static async Task<StoredException[]> List(Fixture f) =>
        (await f.Client.GetFromJsonAsync<StoredException[]>("/api/exceptions", Wire.Json))!;

    [Fact]
    public async Task A_request_raises_an_alert_and_an_approval_reaches_the_device_until_it_expires()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        var asked = new ExceptionRequest(
            PolicyExceptions.Product,
            "clash",
            "Clash",
            "测试代理连通性",
            7,
            @"CORP\zhang"
        );
        await f.Agent("POST", "/api/agent/events", new EventBatch([Request(f, "e1", 1, asked)]));
        // Asked again while pending: the same request, updated.
        await f.Agent(
            "POST",
            "/api/agent/events",
            new EventBatch([Request(f, "e2", 2, asked with { Reason = "联调海外接口", Days = 3 })])
        );
        // Broken requests are ignored rather than refused, so the client does not retry them forever.
        var broken = new AgentEvent(
            "e3",
            3,
            f.Clock.Now,
            PolicyExceptions.RequestEvent,
            "exception:Product:x",
            Detail: "not json"
        );
        Assert.Equal(
            HttpStatusCode.OK,
            (await f.Agent("POST", "/api/agent/events", new EventBatch([broken]))).StatusCode
        );

        var request = Assert.Single(await List(f));
        Assert.Equal(
            (PolicyExceptions.Pending, "联调海外接口", 3, @"CORP\zhang", "Clash"),
            (request.Status, request.Reason, request.Days, request.RequestedBy, request.Label)
        );
        var alert = Assert.Single((await f.Client.GetFromJsonAsync<AlertSummary[]>("/api/alerts", Wire.Json))!);
        Assert.Equal((PolicyExceptions.RequestEvent, "Active"), (alert.Type, alert.State));
        Assert.Contains("联调海外接口", alert.Summary);
        Assert.Empty(await Held(f));

        // Readers and operators see requests but cannot decide them.
        await f.Login("operator");
        Assert.Single(await List(f));
        Assert.Equal(
            HttpStatusCode.Forbidden,
            (
                await f.Client.PostAsJsonAsync(
                    $"/api/exceptions/{request.Id}/approve",
                    new ExceptionDecision(null, null)
                )
            ).StatusCode
        );

        await f.Login();
        Assert.Equal(
            HttpStatusCode.BadRequest,
            (
                await f.Client.PostAsJsonAsync($"/api/exceptions/{request.Id}/approve", new ExceptionDecision(91, null))
            ).StatusCode
        );
        var approved = await f.Client.PostAsJsonAsync(
            $"/api/exceptions/{request.Id}/approve",
            new ExceptionDecision(5, "项目结束后收回"),
            Wire.Json
        );
        Assert.Equal(HttpStatusCode.OK, approved.StatusCode);
        var decided = (await approved.Content.ReadFromJsonAsync<StoredException>(Wire.Json))!;
        Assert.Equal(
            (PolicyExceptions.Approved, 5, f.Clock.Now.AddDays(5), "admin"),
            (decided.Status, decided.Days, decided.ExpiresAt, decided.DecidedBy)
        );
        Assert.Equal(
            HttpStatusCode.Conflict,
            (
                await f.Client.PostAsJsonAsync(
                    $"/api/exceptions/{request.Id}/reject",
                    new ExceptionDecision(null, null)
                )
            ).StatusCode
        );
        Assert.Equal(
            "Resolved",
            Assert.Single((await f.Client.GetFromJsonAsync<AlertSummary[]>("/api/alerts", Wire.Json))!).State
        );
        var held = Assert.Single(await Held(f));
        Assert.Equal(
            (f.Device, PolicyExceptions.Product, "clash", "Clash"),
            (held.DeviceId, held.Kind, held.Target, held.Label)
        );
        var audit = await f.Client.GetStringAsync("/api/audit");
        Assert.Contains("ApproveException", audit);
        Assert.Contains("项目结束后收回", audit);

        // Publishing keeps the exceptions in force, whatever the editor sends.
        Assert.Equal(HttpStatusCode.OK, (await f.Publish(PolicySeed.Create() with { Exceptions = [] })).StatusCode);
        Assert.Single(await Held(f));

        // Once expired, the next maintenance run takes it out of the policies.
        f.Clock.Now += TimeSpan.FromDays(6);
        var service = f.Services.GetRequiredService<ComplianceService>();
        var reissued = await service.Tx(async tx =>
        {
            await tx.Lock(PolicyService.PolicyLock);
            return await service.Policies.RefreshExceptions(tx);
        });
        Assert.Equal(1, reissued);
        Assert.Empty(await Held(f));
        await f.Login();
        Assert.Equal(
            HttpStatusCode.Conflict,
            (
                await f.Client.PostAsJsonAsync(
                    $"/api/exceptions/{request.Id}/revoke",
                    new ExceptionDecision(null, null)
                )
            ).StatusCode
        );
    }

    [Fact]
    public async Task Administrators_reject_create_and_revoke_exceptions()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        await f.Agent(
            "POST",
            "/api/agent/events",
            new EventBatch([
                Request(f, "e1", 1, new(PolicyExceptions.Usb, Stick, "SanDisk Ultra", "拷贝培训资料", 1, @"CORP\li")),
            ])
        );
        var request = Assert.Single(await List(f));
        var rejected = await f.Client.PostAsJsonAsync(
            $"/api/exceptions/{request.Id}/reject",
            new ExceptionDecision(null, "请使用公司加密盘"),
            Wire.Json
        );
        Assert.Equal(
            PolicyExceptions.Rejected,
            (await rejected.Content.ReadFromJsonAsync<StoredException>(Wire.Json))!.Status
        );
        Assert.Empty(await Held(f));

        // A new request after a decision is a new request.
        await f.Agent(
            "POST",
            "/api/agent/events",
            new EventBatch([
                Request(f, "e2", 2, new(PolicyExceptions.Usb, Stick, "SanDisk Ultra", "再申请一次", 1, @"CORP\li")),
            ])
        );
        Assert.Equal(2, (await List(f)).Length);
        Assert.Equal(PolicyExceptions.Pending, (await List(f))[0].Status);

        Assert.Equal(
            HttpStatusCode.BadRequest,
            (
                await f.Client.PostAsJsonAsync(
                    "/api/exceptions",
                    new NewException(f.Device, PolicyExceptions.Product, "no-such-product", null, "试用", 3),
                    Wire.Json
                )
            ).StatusCode
        );
        var created = await f.Client.PostAsJsonAsync(
            "/api/exceptions",
            new NewException(f.Device, PolicyExceptions.Usb, "PROD_IRONKEY", "公司加密盘", "财务部专用", 30),
            Wire.Json
        );
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        var exception = (await created.Content.ReadFromJsonAsync<StoredException>(Wire.Json))!;
        Assert.Equal((PolicyExceptions.Approved, "公司加密盘"), (exception.Status, exception.Label));
        Assert.Equal("PROD_IRONKEY", Assert.Single(await Held(f)).Target);

        var revoked = await f.Client.PostAsJsonAsync(
            $"/api/exceptions/{exception.Id}/revoke",
            new ExceptionDecision(null, null),
            Wire.Json
        );
        Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);
        Assert.Empty(await Held(f));
        var audit = await f.Client.GetStringAsync("/api/audit");
        Assert.Contains("CreateException", audit);
        Assert.Contains("RevokeException", audit);
        Assert.Contains("RejectException", audit);

        Assert.Equal(HttpStatusCode.OK, (await f.Client.DeleteAsync($"/api/devices/{f.Device}")).StatusCode);
        Assert.Empty(await List(f));
    }
}
