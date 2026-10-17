namespace Compliance.Server;

static partial class Endpoints
{
    public const int MaxCodeUses = 500;
    public const int MaxCodeMinutes = 7 * 24 * 60;

    static void MapEnrollment(IEndpointRouteBuilder routes, ComplianceService s)
    {
        var group = routes.MapGroup("/api/enrollment-codes");

        // A code may enroll up to MaxUses devices before it expires, so one code can be handed to everyone
        // installing a batch of PCs. Only its hash is stored.
        group
            .MapPost(
                "",
                async (HttpContext c) =>
                {
                    var u = Require(c, "Operator");
                    var request = await Body<CodeRequest>(c);
                    var minutes = request.ExpiresMinutes ?? 15;
                    var uses = request.MaxUses ?? 1;
                    var label = (request.Label ?? "").Trim();
                    if (minutes is < 1 or > MaxCodeMinutes)
                        throw new ApiError(400, "有效期须在 1 分钟到 7 天之间");
                    if (uses is < 1 or > MaxCodeUses)
                        throw new ApiError(400, $"可登记台数须在 1–{MaxCodeUses} 之间");
                    if (label.Length > MaxNoteLength)
                        throw new ApiError(400, $"名称不能超过 {MaxNoteLength} 个字符");
                    var code = Secrets.Token();
                    var record = new EnrollmentCode(
                        Guid.NewGuid().ToString("N")[..12],
                        label,
                        s.Now.AddMinutes(minutes),
                        uses,
                        0,
                        s.Now,
                        u.Username,
                        false
                    );
                    await s.Tx(async tx =>
                    {
                        await tx.InsertCode(Secrets.Hash(code), record);
                        await tx.Audit(
                            u.Username,
                            "CreateEnrollmentCode",
                            $"{(label.Length > 0 ? label : record.Id)}，可登记 {uses} 台",
                            s.Now
                        );
                        return true;
                    });
                    return new NewEnrollmentCode(code, record.Id, label, record.ExpiresAt, uses);
                }
            )
            .Accepts<CodeRequest>(JsonBody);

        group.MapGet(
            "",
            async (HttpContext c) =>
            {
                Require(c, "Operator");
                return await s.Tx(tx => tx.RecentCodes(100));
            }
        );

        group.MapDelete(
            "/{id}",
            async (HttpContext c, string id) =>
            {
                var u = Require(c, "Operator");
                return await s.Tx(async tx =>
                {
                    if (await tx.RevokeCode(id) == 0)
                        throw new ApiError(404, "登记码不存在");
                    await tx.Audit(u.Username, "RevokeEnrollmentCode", id, s.Now);
                    return new CodeRevoked(id);
                });
            }
        );
    }
}
