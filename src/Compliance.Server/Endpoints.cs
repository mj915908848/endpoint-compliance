using System.Security.Cryptography;
using Compliance.Core;
using Microsoft.AspNetCore.RateLimiting;

namespace Compliance.Server;

static class Endpoints
{
    static UserRecord Require(HttpContext c, string role)
    {
        var u = c.Items["user"] as UserRecord ?? throw new ApiError(401, "Login required");
        if (!u.Roles.Contains(role))
            throw new ApiError(403, "Role required: " + role);
        return u;
    }

    static string Agent(HttpContext c) => (string)c.Items["device"]!;

    static async Task<T> Body<T>(HttpContext c) =>
        await c.Request.ReadFromJsonAsync<T>(Wire.Json) ?? throw new ApiError(400, "Body required");

    public static void Map(WebApplication app, ComplianceService s, Settings settings)
    {
        MapSession(app, s, settings);
        MapDevices(app, s);
        MapPolicies(app, s);
        MapAgent(app, s);
    }

    static void MapSession(WebApplication app, ComplianceService s, Settings settings)
    {
        app.MapGet(
            "/api/status",
            () =>
                new
                {
                    mode = settings.DemoMode ? (settings.DemoHttpLan ? "LanHttpTrial" : "LoopbackDemo") : "Production",
                    storage = settings.Storage,
                    networkCapabilities = new[]
                    {
                        new
                        {
                            id = "network",
                            implemented = false,
                            verified = false,
                            detail = "通用 API 网络执行层未实现",
                        },
                    },
                    policyPublicKeyPem = s.PublicKey,
                    policyKeyId = s.KeyId,
                }
        );

        app.MapPost(
                "/api/auth/login",
                async (HttpContext c) =>
                {
                    var login = await Body<LoginRequest>(c);
                    if (
                        string.IsNullOrWhiteSpace(login.Username)
                        || login.Username.Length > 100
                        || login.Password == null
                        || login.Password.Length > 1024
                    )
                        throw new ApiError(401, "Invalid credentials");
                    var result = await s.Tx(async tx =>
                    {
                        var user = await tx.GetUser(login.Username);
                        if (user == null || !Secrets.Check(login.Password, user.PasswordHash))
                            throw new ApiError(401, "Invalid credentials");
                        var token = Secrets.Token();
                        var session = new SessionRecord(user.Username, Secrets.Token(), s.Now.AddHours(8));
                        await tx.InsertSession(Secrets.Hash(token), session);
                        await tx.Audit(user.Username, "Login", user.Username, s.Now);
                        return (user, token, session);
                    });
                    c.Response.Cookies.Append(
                        "compliance-session",
                        result.token,
                        new CookieOptions
                        {
                            HttpOnly = true,
                            Secure = c.Request.IsHttps,
                            SameSite = SameSiteMode.Strict,
                            Expires = result.session.ExpiresAt,
                            Path = "/",
                        }
                    );
                    return Results.Json(
                        new
                        {
                            username = result.user.Username,
                            roles = result.user.Roles,
                            csrfToken = result.session.CsrfToken,
                        }
                    );
                }
            )
            .RequireRateLimiting("login");

        app.MapGet(
            "/api/me",
            (HttpContext c) =>
            {
                var u = (UserRecord)c.Items["user"]!;
                var session = (SessionRecord)c.Items["session"]!;
                return new
                {
                    username = u.Username,
                    roles = u.Roles,
                    csrfToken = session.CsrfToken,
                };
            }
        );

        app.MapPost(
            "/api/auth/logout",
            async (HttpContext c) =>
            {
                var user = (UserRecord)c.Items["user"]!;
                await s.Tx(async tx =>
                {
                    await tx.DeleteSession(Secrets.Hash(c.Request.Cookies["compliance-session"]!));
                    await tx.Audit(user.Username, "Logout", user.Username, s.Now);
                    return true;
                });
                c.Response.Cookies.Delete("compliance-session");
                return new { ok = true };
            }
        );

        app.MapGet(
            "/api/audit",
            async (HttpContext c) =>
            {
                Require(c, "Reader");
                return await s.Tx(async tx => (await tx.RecentAudit(500)).ToArray());
            }
        );
    }

    static void MapDevices(WebApplication app, ComplianceService s)
    {
        app.MapGet(
            "/api/devices",
            async (HttpContext c) =>
            {
                Require(c, "Reader");
                return await s.Tx(async tx =>
                {
                    await s.UpdateOffline(tx);
                    var list = new List<DeviceSummary>();
                    foreach (var d in await tx.AllDevices())
                        list.Add(await s.Summary(tx, d));
                    return list.OrderBy(d => d.HostName).ToArray();
                });
            }
        );

        app.MapGet(
            "/api/devices/{id}",
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

        app.MapGet(
            "/api/devices/{id}/report",
            async (HttpContext c, string id) =>
            {
                Require(c, "Reader");
                return await s.Tx(async tx => await s.Report(tx, await s.Device(tx, id)));
            }
        );

        app.MapGet(
            "/api/devices/{id}/report.md",
            async (HttpContext c, string id) =>
            {
                Require(c, "Reader");
                var markdown = await s.Tx(async tx =>
                    ReportRenderer.Markdown(await s.Report(tx, await s.Device(tx, id)))
                );
                return Results.Text(markdown, "text/markdown; charset=utf-8");
            }
        );

        app.MapPost(
            "/api/devices/{id}/commands",
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

        app.MapGet(
            "/api/alerts",
            async (HttpContext c) =>
            {
                Require(c, "Reader");
                return await s.Tx(async tx =>
                {
                    await s.UpdateOffline(tx);
                    return (await tx.AlertsNewestFirst()).ToArray();
                });
            }
        );

        app.MapPost(
            "/api/alerts/{id}/ack",
            async (HttpContext c, string id) =>
            {
                var u = Require(c, "Operator");
                return await s.Tx(async tx =>
                {
                    var a = await tx.GetAlert(id) ?? throw new ApiError(404, "Alert not found");
                    await tx.Lock(ComplianceService.DeviceLock(a.DeviceId));
                    await tx.AcknowledgeAlert(id);
                    await tx.Audit(u.Username, "AcknowledgeAlert", id, s.Now);
                    return new { ok = true };
                });
            }
        );

        app.MapPost(
            "/api/enrollment-codes",
            async (HttpContext c) =>
            {
                var u = Require(c, "Operator");
                var request = await Body<CodeRequest>(c);
                var minutes = request.ExpiresMinutes ?? 15;
                if (minutes is < 1 or > 60)
                    throw new ApiError(400, "Expiry must be 1..60 minutes");
                var code = Secrets.Token();
                var expiry = s.Now.AddMinutes(minutes);
                await s.Tx(async tx =>
                {
                    await tx.InsertCode(Secrets.Hash(code), new CodeRecord(expiry, false));
                    await tx.Audit(u.Username, "CreateEnrollmentCode", "[redacted]", s.Now);
                    return true;
                });
                return new { code, expiresAt = expiry };
            }
        );
    }

    static void MapPolicies(WebApplication app, ComplianceService s)
    {
        app.MapGet(
            "/api/policies/current",
            async (HttpContext c) =>
            {
                Require(c, "Reader");
                return await s.Tx(tx => s.CurrentRelease(tx));
            }
        );

        app.MapGet(
            "/api/policies/drafts",
            async (HttpContext c) =>
            {
                Require(c, "Reader");
                return await s.Tx(async tx => (await tx.Drafts()).ToArray());
            }
        );

        app.MapPost(
            "/api/policies/drafts",
            async (HttpContext c) =>
            {
                var u = Require(c, "Publisher");
                var r = await Body<DraftRequest>(c);
                var doc = r.Document ?? throw new ApiError(400, "Policy required");
                if (
                    doc.SchemaVersion != 1
                    || doc.Mode is not ("Audit" or "Enforce")
                    || doc.RequiredModules == null
                    || doc.RequiredControls == null
                    || doc.TargetDeviceIds == null
                    || doc.Products == null
                    || doc.ApplicationRules == null
                    || doc.BlockDomains == null
                    || !doc.DenyInstalled
                    || !doc.DenyProxy
                    || doc.RequiredModules.Length == 0
                    || doc.Products.Length > 5000
                    || doc.BlockDomains.Length > 1000
                    || doc.ApplicationRules.Length > 1000
                )
                    throw new ApiError(400, "Invalid or incomplete policy");
                try
                {
                    PolicyCrypto.Validate(doc);
                }
                catch (ArgumentException)
                {
                    throw new ApiError(400, "Invalid policy content");
                }
                return await s.Tx(async tx =>
                {
                    var draft = new DraftRecord(
                        Guid.NewGuid().ToString(),
                        doc,
                        u.Username,
                        null,
                        false,
                        r.ImpactReviewed
                    );
                    await tx.InsertDraft(draft, s.Now);
                    await tx.Audit(u.Username, "CreatePolicyDraft", draft.Id, s.Now);
                    return draft;
                });
            }
        );

        app.MapPost(
            "/api/policies/{id}/approve",
            async (HttpContext c, string id) =>
            {
                var u = Require(c, "Reviewer");
                return await s.Tx(async tx =>
                {
                    await tx.Lock(ComplianceService.PolicyLock);
                    var d = await tx.GetDraft(id) ?? throw new ApiError(404, "Draft not found");
                    if (d.Published || d.CreatedBy == u.Username || !d.ImpactReviewed)
                        throw new ApiError(409, "Independent reviewer and impact review required");
                    d = d with { ApprovedBy = u.Username };
                    await tx.UpdateDraftReview(id, d.ApprovedBy, d.Published);
                    await tx.Audit(u.Username, "ApprovePolicy", id, s.Now);
                    return d;
                });
            }
        );

        app.MapPost(
            "/api/policies/{id}/publish",
            async (HttpContext c, string id) =>
            {
                var u = Require(c, "Publisher");
                return await s.Tx(async tx =>
                {
                    await tx.Lock(ComplianceService.PolicyLock);
                    var d = await tx.GetDraft(id) ?? throw new ApiError(404, "Draft not found");
                    if (d.ApprovedBy == u.Username)
                        throw new ApiError(409, "Publisher must differ from reviewer");
                    await s.ValidatePublish(tx, d);
                    var signed = s.Sign(d.Document);
                    await tx.InsertRelease(d.Document.Version, signed, s.Now);
                    await tx.AssignPolicy(d.Document.Version, d.Document.TargetDeviceIds);
                    await tx.UpdateDraftReview(id, d.ApprovedBy, published: true);
                    await tx.Audit(u.Username, "PublishPolicy", id, s.Now);
                    return signed;
                });
            }
        );
    }

    static void MapAgent(WebApplication app, ComplianceService s)
    {
        app.MapPost(
                "/api/agent/enroll",
                async (HttpContext c) =>
                {
                    var r = await Body<EnrollmentRequest>(c);
                    if (
                        string.IsNullOrWhiteSpace(r.Code)
                        || r.Code.Length > 256
                        || string.IsNullOrWhiteSpace(r.HostName)
                        || r.HostName.Length > 256
                        || r.PublicKeyPem == null
                        || r.PublicKeyPem.Length > 2048
                    )
                        throw new ApiError(400, "Invalid enrollment");

                    string publicKey;
                    try
                    {
                        using var key = ECDsa.Create();
                        key.ImportFromPem(r.PublicKeyPem);
                        if (key.KeySize < 256)
                            throw new CryptographicException();
                        publicKey = key.ExportSubjectPublicKeyInfoPem();
                    }
                    catch (Exception e) when (e is ArgumentException or CryptographicException)
                    {
                        throw new ApiError(400, "Valid ECDSA public key required");
                    }

                    return await s.Tx(async tx =>
                    {
                        await tx.Lock(ComplianceService.EnrollmentLock);
                        var hash = Secrets.Hash(r.Code);
                        var code = await tx.GetCode(hash);
                        if (code == null || code.Used || code.ExpiresAt <= s.Now)
                            throw new ApiError(400, "Code invalid, expired or used");
                        if (await tx.DeviceKeyExists(publicKey))
                            throw new ApiError(400, "Key already enrolled");

                        var id = Guid.NewGuid().ToString();
                        var current = await s.Current(tx);
                        var target = current.TargetDeviceIds.Length == 0 ? current.Version : 1;
                        await tx.InsertDevice(
                            new DeviceRecord(
                                id,
                                EvidenceSanitizer.Clean(r.HostName),
                                publicKey,
                                TargetPolicyVersion: target
                            )
                        );
                        await tx.MarkCodeUsed(hash);
                        await tx.Audit("enrollment", "EnrollDevice", id, s.Now);
                        return new EnrollmentResponse(id, s.PublicKey, s.KeyId);
                    });
                }
            )
            .RequireRateLimiting("login");

        app.MapPost(
            "/api/agent/heartbeat",
            async (HttpContext c) =>
            {
                var r = await Body<HeartbeatRequest>(c);
                if (
                    string.IsNullOrWhiteSpace(r.HostName)
                    || r.HostName.Length > 256
                    || r.Controls == null
                    || r.Controls.Length > 100
                    || r.Controls.Any(x => x is null)
                    || r.SourceTime > s.Now.AddMinutes(5)
                    || r.SourceTime < s.Now.AddMinutes(-5)
                )
                    throw new ApiError(400, "Invalid heartbeat");
                return await s.Tx(async tx =>
                {
                    var deviceId = Agent(c);
                    await tx.Lock(ComplianceService.DeviceLock(deviceId));
                    await s.Device(tx, deviceId);
                    var controls = r
                        .Controls.Select(x => x with { Detail = EvidenceSanitizer.Clean(x.Detail) })
                        .ToArray();
                    await tx.UpdateHeartbeat(
                        deviceId,
                        EvidenceSanitizer.Clean(r.HostName),
                        s.Now,
                        r.PolicyVersion,
                        controls
                    );
                    await s.UpdateOffline(tx);
                    return new { ok = true };
                });
            }
        );

        app.MapGet(
            "/api/agent/policy",
            async Task<SignedPolicy> (HttpContext c) =>
                await s.Tx(async tx => await s.AssignedPolicy(tx, await s.Device(tx, Agent(c))))
        );

        app.MapPost(
            "/api/agent/events",
            async (HttpContext c) =>
            {
                var batch = await Body<EventBatch>(c);
                return await s.Tx(tx => s.Events(tx, Agent(c), batch));
            }
        );

        app.MapGet(
            "/api/agent/commands",
            async Task<DeviceCommand[]> (HttpContext c) =>
                await s.Tx(async tx => (await tx.PendingCommands(Agent(c), s.Now)).Select(x => x.Command).ToArray())
        );

        app.MapPost(
            "/api/agent/commands/{id}/ack",
            async (HttpContext c, string id) =>
            {
                var reply = await Body<CommandReply>(c);
                if (reply.Detail == null || reply.Detail.Length > 2048)
                    throw new ApiError(400, "Invalid reply");
                reply = reply with { Detail = EvidenceSanitizer.Clean(reply.Detail) };
                return await s.Tx(async tx =>
                {
                    var deviceId = Agent(c);
                    await tx.Lock(ComplianceService.DeviceLock(deviceId));
                    var command = await tx.GetCommand(id);
                    if (command == null || command.DeviceId != deviceId)
                        throw new ApiError(404, "Command not found");
                    if (command.Reply != null && command.Reply != reply)
                        throw new ApiError(409, "Reply already recorded");
                    if (command.Reply == null)
                    {
                        await tx.SetCommandReply(id, reply with { Detail = EvidenceSanitizer.Clean(reply.Detail) });
                        await tx.Audit(deviceId, "ScanReply", id, s.Now);
                    }
                    return new { ok = true };
                });
            }
        );
    }
}
