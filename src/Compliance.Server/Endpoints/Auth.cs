namespace Compliance.Server;

static partial class Endpoints
{
    const int MinPasswordLength = 12;

    /// <summary>The login error that asks the page for the authenticator code.</summary>
    public const string TwoFactorNeeded = "TwoFactorRequired";

    /// <summary>The name authenticator apps show above the account's codes.</summary>
    const string TotpIssuer = "终端合规管控";

    sealed record PasswordRequest(string? CurrentPassword, string? NewPassword);

    static void MapAuth(IEndpointRouteBuilder routes, ComplianceService s, Settings settings)
    {
        var throttle = new LoginThrottle();
        var log = routes.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("Compliance.Server.Login");
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
                    var address = c.Connection.RemoteIpAddress?.ToString() ?? "loopback";
                    var who = $"{login.Username}（{address}）";
                    if (throttle.LockedFor(login.Username, address, s.Now) is { } wait)
                        throw new ApiError(
                            429,
                            $"该账号密码错误次数过多，请 {Math.Ceiling(wait.TotalMinutes)} 分钟后再试"
                        );
                    var result = await s.Tx<(UserRecord? user, string? token, SessionRecord? session, bool required)>(
                        async tx =>
                        {
                            var user = await tx.GetUser(login.Username);
                            if (
                                !Secrets.Check(login.Password, user?.PasswordHash ?? Secrets.Unknown)
                                || user == null
                                || user.Disabled
                            )
                                return default;
                            // Asked for only once the password is right, so it does not tell anyone which accounts use it.
                            if (user.TwoFactor && string.IsNullOrWhiteSpace(login.Code))
                                throw new ApiError(401, TwoFactorNeeded);
                            if (
                                user.TwoFactor
                                && (
                                    Totp.Verify(user.TotpSecret, login.Code, s.Now, user.TotpStep) is not { } step
                                    || !await tx.UseTotpStep(user.Username, step)
                                )
                            )
                                return (user, null, null, false);
                            throttle.Succeeded(login.Username, address);
                            var token = Secrets.Token();
                            var session = new SessionRecord(user.Username, Secrets.Token(), s.Now.AddHours(8), s.Now);
                            await tx.InsertSession(Secrets.Hash(token), session);
                            await tx.SetLastLogin(user.Username, s.Now);
                            await tx.Audit(user.Username, "Login", who, s.Now);
                            return (user, token, session, await TwoFactorRequired(tx));
                        }
                    );
                    if (result.session is null)
                    {
                        // Recorded so guessing shows in the audit log and the container log. The name typed is the
                        // target, never the actor: anyone can type any name.
                        var wrongCode = result.user is not null;
                        var locked = throttle.Failed(login.Username, address, s.Now);
                        log.LogWarning(
                            "Wrong {What} for {Username} from {Address}{Locked}",
                            wrongCode ? "authenticator code" : "password",
                            login.Username,
                            address,
                            locked ? "; sign-in from there paused" : ""
                        );
                        await s.Tx(async tx =>
                        {
                            await tx.Audit(
                                "anonymous",
                                locked ? "LoginLocked"
                                    : wrongCode ? "LoginWrongCode"
                                    : "LoginFailed",
                                who,
                                s.Now
                            );
                            return true;
                        });
                        throw new ApiError(
                            401,
                            wrongCode ? "验证码不正确或已用过，请输入验证器上的新验证码" : "Invalid credentials"
                        );
                    }
                    c.Response.Cookies.Append(
                        "compliance-session",
                        result.token!,
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
                            result.user!.Username,
                            result.user.Roles,
                            result.session.CsrfToken,
                            s.SessionIdle?.TotalMinutes ?? 0,
                            result.user.TwoFactor,
                            result.required
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
                return new SessionInfo(
                    u.Username,
                    u.Roles,
                    session.CsrfToken,
                    s.SessionIdle?.TotalMinutes ?? 0,
                    u.TwoFactor,
                    (bool)c.Items["twoFactorRequired"]!
                );
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
            "/auth/two-factor/setup",
            async (HttpContext c) =>
            {
                var user = (UserRecord)c.Items["user"]!;
                if (user.TwoFactor)
                    throw new ApiError(400, "两步验证已启用");
                var secret = Totp.NewSecret();
                await s.Tx(async tx =>
                {
                    await tx.SetPendingTotp(user.Username, secret);
                    return true;
                });
                return new TwoFactorSetup(secret, Totp.Uri(TotpIssuer, user.Username, secret));
            }
        );

        group
            .MapPost(
                "/auth/two-factor/enable",
                async (HttpContext c) =>
                {
                    var user = (UserRecord)c.Items["user"]!;
                    var r = await Body<TwoFactorCodeRequest>(c);
                    return await s.Tx(async tx =>
                    {
                        var secret =
                            await tx.GetPendingTotp(user.Username) ?? throw new ApiError(400, "请先生成二维码");
                        var step =
                            Totp.Verify(secret, r.Code, s.Now, 0)
                            ?? throw new ApiError(400, "验证码不正确，请确认手机时间准确后输入新的验证码");
                        await tx.SetTotp(user.Username, secret, step);
                        await tx.Audit(user.Username, "EnableTwoFactor", user.Username, s.Now);
                        return new Done();
                    });
                }
            )
            .Accepts<TwoFactorCodeRequest>(JsonBody)
            .RequireRateLimiting("login");

        group
            .MapPost(
                "/auth/two-factor/disable",
                async (HttpContext c) =>
                {
                    var user = (UserRecord)c.Items["user"]!;
                    var r = await Body<DisableTwoFactorRequest>(c);
                    return await s.Tx(async tx =>
                    {
                        if (await TwoFactorRequired(tx))
                            throw new ApiError(400, "单位要求所有账号使用两步验证，不能关闭");
                        var stored = await RequireAccount(tx, user.Username);
                        if (!stored.TwoFactor)
                            throw new ApiError(400, "两步验证未启用");
                        // 400 rather than 401, which would sign the administrator out of the page.
                        if (r.Password == null || !Secrets.Check(r.Password, stored.PasswordHash))
                            throw new ApiError(400, "当前密码不正确");
                        if (
                            Totp.Verify(stored.TotpSecret, r.Code, s.Now, stored.TotpStep) is not { } step
                            || !await tx.UseTotpStep(user.Username, step)
                        )
                            throw new ApiError(400, "验证码不正确或已用过");
                        await tx.SetTotp(user.Username, "", 0);
                        await tx.Audit(user.Username, "DisableTwoFactor", user.Username, s.Now);
                        return new Done();
                    });
                }
            )
            .Accepts<DisableTwoFactorRequest>(JsonBody)
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
