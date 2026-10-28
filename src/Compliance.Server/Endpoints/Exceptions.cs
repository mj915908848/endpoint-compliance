using Compliance.Core;

namespace Compliance.Server;

static partial class Endpoints
{
    const int MaxExceptionRows = 1000;

    static void MapExceptions(IEndpointRouteBuilder routes, ComplianceService s)
    {
        var group = routes.MapGroup("/api/exceptions");

        // Requests waiting for a decision first, then decided ones and exceptions created here, newest first.
        group.MapGet(
            "",
            async (HttpContext c) =>
            {
                Require(c, "Reader");
                return await s.Tx(async tx => (await tx.Exceptions(MaxExceptionRows)).ToArray());
            }
        );

        // An exception an administrator grants without a request, in force at once.
        group
            .MapPost(
                "",
                async (HttpContext c) =>
                {
                    var u = Require(c, "Publisher");
                    var asked = await Body<NewException>(c);
                    var reason = asked.Reason?.Trim() ?? "";
                    var target = asked.Target?.Trim() ?? "";
                    if (!PolicyExceptions.Kinds.Contains(asked.Kind))
                        throw new ApiError(400, "例外类型无效");
                    if (reason.Length is 0 or > PolicyExceptions.MaxReason)
                        throw new ApiError(400, $"请填写理由，不超过 {PolicyExceptions.MaxReason} 个字符");
                    CheckDays(asked.Days);
                    return await s.Tx(async tx =>
                    {
                        await tx.Lock(PolicyService.PolicyLock);
                        var d = await s.DeviceHead(tx, asked.DeviceId ?? "");
                        string label;
                        if (asked.Kind == PolicyExceptions.Product)
                        {
                            label =
                                (await s.Policies.All(tx))
                                    .SelectMany(p => p.Document.Products)
                                    .FirstOrDefault(p => p.Id == target)
                                    ?.Name
                                ?? throw new ApiError(400, "策略中没有这个软件");
                        }
                        else
                        {
                            if (target.Length is < 4 or > 256)
                                throw new ApiError(400, "设备标识 4–256 个字符");
                            label = asked.Label?.Trim() is { Length: > 0 and <= 200 } l ? l : target;
                        }
                        var id = "x-" + Guid.NewGuid().ToString("N")[..12];
                        await tx.InsertException(
                            new StoredException(
                                id,
                                d.Id,
                                d.HostName,
                                "",
                                "",
                                asked.Kind,
                                target,
                                label,
                                reason,
                                asked.Days,
                                u.Username,
                                s.Now,
                                PolicyExceptions.Approved,
                                u.Username,
                                s.Now,
                                s.Now + TimeSpan.FromDays(asked.Days),
                                "",
                                ""
                            )
                        );
                        var created = (await tx.GetException(id))!;
                        await tx.Audit(u.Username, "CreateException", Describe(created), s.Now);
                        await s.Policies.RefreshExceptions(tx);
                        return created;
                    });
                }
            )
            .Accepts<NewException>(JsonBody);

        group
            .MapPost(
                "/{id}/approve",
                (HttpContext c, string id) =>
                    Decide(
                        c,
                        s,
                        id,
                        "ApproveException",
                        PolicyExceptions.Pending,
                        (x, d) =>
                        {
                            var days = d.Days ?? x.Days;
                            CheckDays(days);
                            return (PolicyExceptions.Approved, days, s.Now + TimeSpan.FromDays(days));
                        }
                    )
            )
            .Accepts<ExceptionDecision>(JsonBody);

        group
            .MapPost(
                "/{id}/reject",
                (HttpContext c, string id) =>
                    Decide(
                        c,
                        s,
                        id,
                        "RejectException",
                        PolicyExceptions.Pending,
                        (x, _) => (PolicyExceptions.Rejected, x.Days, null)
                    )
            )
            .Accepts<ExceptionDecision>(JsonBody);

        group
            .MapPost(
                "/{id}/revoke",
                (HttpContext c, string id) =>
                    Decide(
                        c,
                        s,
                        id,
                        "RevokeException",
                        PolicyExceptions.Approved,
                        (x, _) =>
                            x.ExpiresAt <= s.Now
                                ? throw new ApiError(409, "这项例外已经到期")
                                : (PolicyExceptions.Revoked, x.Days, x.ExpiresAt)
                    )
            )
            .Accepts<ExceptionDecision>(JsonBody);
    }

    static void CheckDays(int days)
    {
        if (days is < 1 or > PolicyExceptions.MaxDays)
            throw new ApiError(400, $"有效期为 1 到 {PolicyExceptions.MaxDays} 天");
    }

    static string Describe(StoredException x) =>
        $"{x.HostName}（{x.DeviceId}）：{PolicyExceptions.KindLabel(x.Kind)}“{x.Label}”，{x.Days} 天";

    /// <summary>
    /// Moves a request or exception from <paramref name="from"/> to the state <paramref name="decide"/> gives, audits
    /// it, closes the alert its request raised, and re-issues the policies so devices get the change.
    /// </summary>
    static async Task<StoredException> Decide(
        HttpContext c,
        ComplianceService s,
        string id,
        string action,
        string from,
        Func<StoredException, ExceptionDecision, (string Status, int Days, DateTimeOffset? ExpiresAt)> decide
    )
    {
        var u = Require(c, "Publisher");
        var decision = c.Request.HasJsonContentType() ? await Body<ExceptionDecision>(c) : new(null, null);
        var note = decision.Note?.Trim() ?? "";
        if (note.Length > PolicyExceptions.MaxReason)
            throw new ApiError(400, $"说明不超过 {PolicyExceptions.MaxReason} 个字符");
        return await s.Tx(async tx =>
        {
            await tx.Lock(PolicyService.PolicyLock);
            var x = await tx.GetException(id) ?? throw new ApiError(404, "申请不存在或终端已删除");
            if (x.Status != from)
                throw new ApiError(
                    409,
                    from == PolicyExceptions.Pending ? "这条申请已经处理过了" : "只能撤销已批准的例外"
                );
            var (status, days, expires) = decide(x, decision);
            await tx.Decide(id, status, u.Username, s.Now, expires, days, note);
            var updated = (await tx.GetException(id))!;
            await tx.Audit(u.Username, action, Describe(updated) + (note.Length > 0 ? "。说明：" + note : ""), s.Now);
            if (x.ObjectKey.Length > 0)
                await tx.ResolveAlert(x.DeviceId + ":" + Secrets.Hash(x.ObjectKey), s.Now);
            await s.Policies.RefreshExceptions(tx);
            return updated;
        });
    }
}
