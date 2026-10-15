using System.Security.Cryptography;
using Compliance.Core;

namespace Compliance.Server;

static partial class Endpoints
{
    static void MapAgent(IEndpointRouteBuilder routes, ComplianceService s)
    {
        var group = routes.MapGroup("/api/agent");

        group
            .MapPost(
                "/enroll",
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
                        // Publishing reassigns only the devices it can see, so a device enrolled while a publish
                        // is uncommitted would keep the old default release. Waiting for the policy lock makes the
                        // version read below the one any concurrent publish commits.
                        await tx.Lock(ComplianceService.PolicyLock);
                        var hash = Secrets.Hash(r.Code);
                        var code = await tx.GetCode(hash);
                        if (code == null || code.Revoked || code.Uses >= code.MaxUses || code.ExpiresAt <= s.Now)
                            throw new ApiError(400, "Code invalid, expired or used");
                        if (await tx.DeviceKeyExists(publicKey))
                            throw new ApiError(400, "Key already enrolled");

                        var id = Guid.NewGuid().ToString();
                        // A new device has an id no policy lists yet, so it starts on the default policy.
                        var target = Wire.Read<PolicyDocument>((await s.CurrentRelease(tx)).Payload).Version;
                        await tx.InsertDevice(
                            new DeviceRecord(
                                id,
                                EvidenceSanitizer.Clean(r.HostName),
                                publicKey,
                                TargetPolicyVersion: target
                            )
                        );
                        await tx.CountCodeUse(hash);
                        await tx.Audit(
                            "enrollment",
                            "EnrollDevice",
                            code.Label.Length > 0 ? $"{id}（登记码“{code.Label}”）" : id,
                            s.Now
                        );
                        return new EnrollmentResponse(id, s.PublicKey, s.KeyId);
                    });
                }
            )
            .RequireRateLimiting("login");

        group.MapPost(
            "/heartbeat",
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

        group.MapGet(
            "/policy",
            async Task<SignedPolicy> (HttpContext c) =>
                await s.Tx(async tx => await s.AssignedPolicy(tx, await s.Device(tx, Agent(c))))
        );

        group.MapPost(
            "/events",
            async (HttpContext c) =>
            {
                var batch = await Body<EventBatch>(c);
                return await s.Tx(tx => s.Events(tx, Agent(c), batch));
            }
        );

        group.MapGet(
            "/commands",
            async Task<DeviceCommand[]> (HttpContext c) =>
                await s.Tx(async tx => (await tx.PendingCommands(Agent(c), s.Now)).Select(x => x.Command).ToArray())
        );

        group.MapPost(
            "/commands/{id}/ack",
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
