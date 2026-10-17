namespace Compliance.Server;

/// <param name="Rotation">The rotation under way, if any.</param>
public sealed record SigningKeyState(string KeyId, KeyRotationProgress? Rotation);

/// <param name="Ready">Devices whose client trusts the next key.</param>
/// <param name="Waiting">Up to 100 devices whose client does not trust it yet.</param>
public sealed record KeyRotationProgress(
    string NextKeyId,
    DateTimeOffset StartedAt,
    int Devices,
    int Ready,
    KeyRotationWait[] Waiting
);

public sealed record KeyRotationWait(string Id, string HostName, DateTimeOffset? LastHeartbeat);

/// <param name="Force">Complete although some devices do not trust the next key yet; they must enroll again.</param>
public sealed record CompleteRotationRequest(bool Force = false);

static partial class Endpoints
{
    static void MapSigningKey(IEndpointRouteBuilder routes, ComplianceService s)
    {
        var group = routes.MapGroup("/api/settings/signing-key");

        async Task<SigningKeyState> State(Transaction tx)
        {
            var policies = s.Policies;
            if (policies.Rotation is not { } rotation || policies.NextKeyId is not { } next)
                return new(policies.KeyId, null);
            var devices = await tx.DevicesTrustingKey(next);
            var announced = Compliance.Core.KeyRotationCrypto.Verify(rotation, policies.PublicKey);
            return new(
                policies.KeyId,
                new(
                    next,
                    announced.IssuedAt,
                    devices.Count,
                    devices.Count(d => d.Trusts),
                    devices
                        .Where(d => !d.Trusts)
                        .Take(100)
                        .Select(d => new KeyRotationWait(d.Id, d.HostName, d.LastHeartbeat))
                        .ToArray()
                )
            );
        }

        group.MapGet(
            "",
            async (HttpContext c) =>
            {
                Require(c, "Publisher");
                return await s.Tx(State);
            }
        );

        group.MapPost(
            "/rotation",
            async (HttpContext c) =>
            {
                var u = Require(c, "Publisher");
                return await s.Tx(async tx =>
                {
                    await tx.Lock(PolicyService.PolicyLock);
                    await s.Policies.StartRotation();
                    await tx.Audit(
                        u.Username,
                        "StartKeyRotation",
                        $"{s.Policies.KeyId} → {s.Policies.NextKeyId}",
                        s.Now
                    );
                    return await State(tx);
                });
            }
        );

        group.MapDelete(
            "/rotation",
            async (HttpContext c) =>
            {
                var u = Require(c, "Publisher");
                return await s.Tx(async tx =>
                {
                    await tx.Lock(PolicyService.PolicyLock);
                    var next = s.Policies.NextKeyId;
                    s.Policies.CancelRotation();
                    await tx.Audit(u.Username, "CancelKeyRotation", next ?? "", s.Now);
                    return await State(tx);
                });
            }
        );

        group
            .MapPost(
                "/rotation/complete",
                async (HttpContext c) =>
                {
                    var u = Require(c, "Publisher");
                    var r = await Body<CompleteRotationRequest>(c);
                    string? retired = null;
                    try
                    {
                        return await s.Tx(async tx =>
                        {
                            await tx.Lock(PolicyService.PolicyLock);
                            await tx.Lock(PackageService.PackageLock);
                            var state = await State(tx);
                            if (state.Rotation is not { } progress)
                                throw new ApiError(409, "没有正在进行的密钥轮换");
                            if (progress.Ready < progress.Devices && !r.Force)
                                throw new ApiError(
                                    409,
                                    $"还有 {progress.Devices - progress.Ready} 台终端没有收到新密钥，完成后它们需要重新登记"
                                );
                            var old = s.Policies.KeyId;
                            retired = await s.Policies.CompleteRotation(tx);
                            await tx.Audit(
                                u.Username,
                                "CompleteKeyRotation",
                                $"{old} → {s.Policies.KeyId}，{progress.Devices - progress.Ready} 台终端未收到新密钥",
                                s.Now
                            );
                            return await State(tx);
                        });
                    }
                    catch when (retired != null)
                    {
                        await s.Policies.UndoCompletion(retired);
                        throw;
                    }
                }
            )
            .Accepts<CompleteRotationRequest>(JsonBody);
    }
}
