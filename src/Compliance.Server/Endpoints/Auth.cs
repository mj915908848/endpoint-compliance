namespace Compliance.Server;

static partial class Endpoints
{
    const int MinPasswordLength = 12;

    sealed record PasswordRequest(string? CurrentPassword, string? NewPassword);

    static void MapAuth(IEndpointRouteBuilder routes, ComplianceService s, Settings settings)
    {
        var throttle = new LoginThrottle();
        var group = routes.MapGroup("/api");

        group.MapGet(
            "/status",
            () =>
                new ServerStatus(
                    ComplianceService.Version,
                    settings.DemoMode ? (settings.DemoHttpLan ? "LanHttpTrial" : "LoopbackDemo") : "Production",
                    settings.Storage,
                    [
                        new(
                            "network",
                            Implemented: false,
                            Verified: false,
                            "尚未实现。目前只能通过浏览器策略拦截浏览器访问；其他程序的网络访问需依靠单位的出口网关或代理拦截。"
                        ),
                    ],
                    s.Policies.PublicKey,
                    s.Policies.KeyId
                )
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
                    if (throttle.LockedFor(login.Username, s.Now) is { } wait)
                        throw new ApiError(
                            429,
                            $"该账号密码错误次数过多，请 {Math.Ceiling(wait.TotalMinutes)} 分钟后再试"
                        );
                    var result = await s.Tx(async tx =>
                    {
                        var user = await tx.GetUser(login.Username);
                        if (!Secrets.Check(login.Password, user?.PasswordHash ?? Secrets.Unknown) || user == null)
                        {
                            throttle.Failed(login.Username, s.Now);
                            throw new ApiError(401, "Invalid credentials");
                        }
                        throttle.Succeeded(login.Username);
                        var token = Secrets.Token();
                        var session = new SessionRecord(user.Username, Secrets.Token(), s.Now.AddHours(8), s.Now);
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
                        new SessionInfo(
                            result.user.Username,
                            result.user.Roles,
                            result.session.CsrfToken,
                            s.SessionIdle?.TotalMinutes ?? 0
                        )
                    );
                }
            )
            .Accepts<LoginRequest>(JsonBody)
            .RequireRateLimiting("login");

        group.MapGet(
            "/me",
            (HttpContext c) =>
            {
                var u = (UserRecord)c.Items["user"]!;
                var session = (SessionRecord)c.Items["session"]!;
                return new SessionInfo(u.Username, u.Roles, session.CsrfToken, s.SessionIdle?.TotalMinutes ?? 0);
            }
        );

        group
            .MapPost(
                "/auth/password",
                async (HttpContext c) =>
                {
                    var user = (UserRecord)c.Items["user"]!;
                    var r = await Body<PasswordRequest>(c);
                    if (r.CurrentPassword == null || r.NewPassword == null || r.NewPassword.Length > 1024)
                        throw new ApiError(400, "Invalid request");
                    if (r.NewPassword.Length < MinPasswordLength)
                        throw new ApiError(400, $"新密码至少 {MinPasswordLength} 位");
                    if (r.NewPassword == r.CurrentPassword)
                        throw new ApiError(400, "新密码不能与当前密码相同");
                    var signedOut = await s.Tx(async tx =>
                    {
                        // 400 rather than 401, which would sign the administrator out of the page.
                        var stored = await tx.GetUser(user.Username);
                        if (stored == null || !Secrets.Check(r.CurrentPassword, stored.PasswordHash))
                            throw new ApiError(400, "当前密码不正确");
                        await tx.SetPassword(user.Username, Secrets.Password(r.NewPassword));
                        var others = await tx.DeleteOtherSessions(
                            user.Username,
                            Secrets.Hash(c.Request.Cookies["compliance-session"]!)
                        );
                        await tx.Audit(user.Username, "ChangePassword", user.Username, s.Now);
                        return others;
                    });
                    return new PasswordChanged(signedOut);
                }
            )
            .Accepts<PasswordRequest>(JsonBody)
            .RequireRateLimiting("login");

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
                return new Done();
            }
        );
    }
}
