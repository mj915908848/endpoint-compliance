namespace Compliance.Server;

static partial class Endpoints
{
    static void MapEnrollment(IEndpointRouteBuilder routes, ComplianceService s)
    {
        var group = routes.MapGroup("/api/enrollment-codes");

        group.MapPost(
            "",
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
}
