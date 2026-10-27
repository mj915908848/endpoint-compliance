namespace Compliance.Server;

static partial class Endpoints
{
    const string AccountsLock = "accounts";
    public const string RequireTwoFactorKey = "require-two-factor";

    public static async Task<bool> TwoFactorRequired(Transaction tx) =>
        await tx.GetSetting(RequireTwoFactorKey) == "true";

    static UserSummary Summary(UserRecord u) =>
        new(u.Username, u.Roles, u.TwoFactor, u.Disabled, u.LastLogin.UtcTicks == 0 ? null : u.LastLogin);

    static string[] CheckedRoles(string[]? roles)
    {
        if (roles is not { Length: > 0 } || roles.Any(r => !UserRoles.All.Contains(r)))
            throw new ApiError(400, "请至少选择一个有效的角色");
        return [.. roles.Distinct()];
    }

    static async Task<UserRecord> RequireAccount(Transaction tx, string username) =>
        await tx.GetUser(username) ?? throw new ApiError(404, "账号不存在");

    /// <summary>Refuses a change that would leave no enabled account able to manage accounts.</summary>
    static async Task KeepAnAdmin(Transaction tx, string username, string[] roles, bool disabled)
    {
        var admins = (await tx.Users()).Count(u =>
            u.Username == username
                ? !disabled && roles.Contains(UserRoles.Admin)
                : !u.Disabled && u.Roles.Contains(UserRoles.Admin)
        );
        if (admins == 0)
            throw new ApiError(400, "至少要保留一个可用的账号管理员");
    }

    static void MapUsers(IEndpointRouteBuilder routes, ComplianceService s)
    {
        var group = routes.MapGroup("/api/users");

        group.MapGet(
            "",
            async (HttpContext c) =>
            {
                Require(c, UserRoles.Admin);
                return await s.Tx(async tx => new UsersView(
                    [.. (await tx.Users()).Select(Summary)],
                    await TwoFactorRequired(tx)
                ));
            }
        );

        group
            .MapPost(
                "",
                async (HttpContext c) =>
                {
                    var u = Require(c, UserRoles.Admin);
                    var r = await Body<NewUserRequest>(c);
                    var name = r.Username?.Trim() ?? "";
                    if (name.Length is 0 or > 100 || name.Any(char.IsControl))
                        throw new ApiError(400, "账号名需为 1 到 100 个字符");
                    if (r.Password is not { Length: >= MinPasswordLength and <= 1024 })
                        throw new ApiError(400, $"初始密码至少 {MinPasswordLength} 位");
                    var roles = CheckedRoles(r.Roles);
                    return await s.Tx(async tx =>
                    {
                        await tx.Lock(AccountsLock);
                        if (await tx.GetUser(name) != null)
                            throw new ApiError(409, $"账号“{name}”已存在");
                        var user = new UserRecord(name, Secrets.Password(r.Password), roles);
                        await tx.InsertUser(user);
                        await tx.Audit(u.Username, "CreateUser", $"{name}：{UserRoles.Names(roles)}", s.Now);
                        return Summary(user);
                    });
                }
            )
            .Accepts<NewUserRequest>(JsonBody);

        group
            .MapPut(
                "/{username}/roles",
                async (HttpContext c, string username) =>
                {
                    var u = Require(c, UserRoles.Admin);
                    var roles = CheckedRoles((await Body<RolesRequest>(c)).Roles);
                    return await s.Tx(async tx =>
                    {
                        await tx.Lock(AccountsLock);
                        var user = await RequireAccount(tx, username);
                        await KeepAnAdmin(tx, username, roles, user.Disabled);
                        await tx.SetRoles(username, roles);
                        await tx.Audit(u.Username, "SetUserRoles", $"{username}：{UserRoles.Names(roles)}", s.Now);
                        return Summary(user with { Roles = roles });
                    });
                }
            )
            .Accepts<RolesRequest>(JsonBody);

        group
            .MapPost(
                "/{username}/password",
                async (HttpContext c, string username) =>
                {
                    var u = Require(c, UserRoles.Admin);
                    var r = await Body<ResetPasswordRequest>(c);
                    if (r.Password is not { Length: >= MinPasswordLength and <= 1024 })
                        throw new ApiError(400, $"新密码至少 {MinPasswordLength} 位");
                    if (username == u.Username)
                        throw new ApiError(400, "修改自己的密码请使用账号菜单中的“修改密码”");
                    return await s.Tx(async tx =>
                    {
                        await RequireAccount(tx, username);
                        await tx.SetPassword(username, Secrets.Password(r.Password));
                        var signedOut = await tx.DeleteSessions(username);
                        await tx.Audit(u.Username, "ResetUserPassword", username, s.Now);
                        return new PasswordChanged(signedOut);
                    });
                }
            )
            .Accepts<ResetPasswordRequest>(JsonBody);

        foreach (var disable in new[] { true, false })
            group.MapPost(
                disable ? "/{username}/disable" : "/{username}/enable",
                async (HttpContext c, string username) =>
                {
                    var u = Require(c, UserRoles.Admin);
                    if (disable && username == u.Username)
                        throw new ApiError(400, "不能停用自己的账号");
                    return await s.Tx(async tx =>
                    {
                        await tx.Lock(AccountsLock);
                        var user = await RequireAccount(tx, username);
                        if (disable)
                            await KeepAnAdmin(tx, username, user.Roles, true);
                        await tx.SetDisabled(username, disable);
                        if (disable)
                            await tx.DeleteSessions(username);
                        await tx.Audit(u.Username, disable ? "DisableUser" : "EnableUser", username, s.Now);
                        return Summary(user with { Disabled = disable });
                    });
                }
            );

        // For an administrator whose phone is lost: they sign in with the password alone and set it up again.
        group.MapDelete(
            "/{username}/two-factor",
            async (HttpContext c, string username) =>
            {
                var u = Require(c, UserRoles.Admin);
                if (username == u.Username)
                    throw new ApiError(400, "关闭自己的两步验证请使用账号菜单中的“两步验证”");
                return await s.Tx(async tx =>
                {
                    var user = await RequireAccount(tx, username);
                    await tx.SetTotp(username, "", 0);
                    await tx.DeleteSessions(username);
                    await tx.Audit(u.Username, "ResetTwoFactor", username, s.Now);
                    return Summary(user with { TotpSecret = "" });
                });
            }
        );

        routes
            .MapPut(
                "/api/settings/require-two-factor",
                async (HttpContext c) =>
                {
                    var u = Require(c, UserRoles.Admin);
                    var r = await Body<RequireTwoFactorRequest>(c);
                    if (r.Required && !u.TwoFactor)
                        throw new ApiError(400, "请先为自己的账号启用两步验证，再要求所有账号启用");
                    return await s.Tx(async tx =>
                    {
                        await tx.PutSetting(RequireTwoFactorKey, r.Required ? "true" : "false");
                        await tx.Audit(u.Username, "SetRequireTwoFactor", r.Required ? "要求" : "不要求", s.Now);
                        return new Done();
                    });
                }
            )
            .Accepts<RequireTwoFactorRequest>(JsonBody);
    }
}
