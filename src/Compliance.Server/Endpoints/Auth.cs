namespace Compliance.Server;

static partial class Endpoints
{
    static void MapAuth(IEndpointRouteBuilder routes, ComplianceService s, Settings settings)
    {
        var group = routes.MapGroup("/api");

        group.MapGet(
            "/status",
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
                            detail = "尚未实现。目前只能通过浏览器策略拦截浏览器访问；其他程序的网络访问需依靠单位的出口网关或代理拦截。",
                        },
                    },
                    policyPublicKeyPem = s.PublicKey,
                    policyKeyId = s.KeyId,
                }
        );

        group
            .MapPost(
                "/auth/login",
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

        group.MapGet(
            "/me",
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

        group.MapPost(
            "/auth/logout",
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
    }
}
