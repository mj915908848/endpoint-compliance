using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Compliance.Core;
using Xunit;

namespace Compliance.Server.Tests;

/// <summary>Accounts managed on the page and two-step sign-in with an authenticator app.</summary>
public class AccountTests
{
    const string Password = "test-admin-password-long";

    static async Task<HttpResponseMessage> SignIn(Fixture f, string username, string password, string? code = null)
    {
        f.Client.DefaultRequestHeaders.Remove("X-CSRF-Token");
        var r = await f.Client.PostAsJsonAsync(
            "/api/auth/login",
            new
            {
                username,
                password,
                code,
            }
        );
        if (r.IsSuccessStatusCode)
            f.Client.DefaultRequestHeaders.Add(
                "X-CSRF-Token",
                (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("csrfToken").GetString()
            );
        return r;
    }

    static async Task<string> Error(HttpResponseMessage r) =>
        (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString()!;

    static async Task<Dictionary<string, UserSummary>> Users(Fixture f) =>
        (await f.Client.GetFromJsonAsync<UsersView>("/api/users", Wire.Json))!.Users.ToDictionary(u => u.Username);

    static string Now(Fixture f, string secret) => Totp.Code(secret, Totp.StepAt(f.Clock.Now));

    /// <summary>Sets up two-step sign-in for the account signed in; its secret.</summary>
    static async Task<string> TurnOn(Fixture f)
    {
        var setup = (
            await (
                await f.Client.PostAsJsonAsync("/api/auth/two-factor/setup", new { })
            ).Content.ReadFromJsonAsync<TwoFactorSetup>(Wire.Json)
        )!;
        Assert.StartsWith("otpauth://totp/", setup.Uri);
        Assert.Contains("secret=" + setup.Secret, setup.Uri);
        var r = await f.Client.PostAsJsonAsync("/api/auth/two-factor/enable", new { code = Now(f, setup.Secret) });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return setup.Secret;
    }

    [Fact]
    public void Codes_match_the_rfc_6238_test_vector_and_work_once_within_a_step_either_side()
    {
        // RFC 6238 appendix B, SHA-1 key "12345678901234567890", at 59 seconds: 94287082, of which the last 6 digits.
        const string secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        var at = DateTimeOffset.FromUnixTimeSeconds(59);
        Assert.Equal("287082", Totp.Code(secret, Totp.StepAt(at)));
        Assert.Equal(1, Totp.Verify(secret, "287 082", at, 0));
        Assert.Equal(1, Totp.Verify(secret, "287082", at.AddSeconds(30), 0));
        Assert.Null(Totp.Verify(secret, "287082", at.AddSeconds(60), 0));
        Assert.Null(Totp.Verify(secret, "287082", at, 1));
        Assert.Null(Totp.Verify(secret, "28708", at, 0));
        Assert.Equal(32, Totp.NewSecret().Length);
    }

    [Fact]
    public async Task Admins_manage_accounts_but_never_leave_none_who_can()
    {
        await using var f = new Fixture();
        await f.Login();
        // Bootstrap administrators with Operator and Publisher manage accounts too.
        Assert.Contains(UserRoles.Admin, (await Users(f))["admin"].Roles);

        var created = await f.Client.PostAsJsonAsync(
            "/api/users",
            new
            {
                username = " zhang ",
                password = Password,
                roles = new[] { "Reader", "Operator" },
            }
        );
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        Assert.Equal(
            HttpStatusCode.Conflict,
            (
                await f.Client.PostAsJsonAsync(
                    "/api/users",
                    new
                    {
                        username = "zhang",
                        password = Password,
                        roles = new[] { "Reader" },
                    }
                )
            ).StatusCode
        );
        foreach (
            var bad in new object[]
            {
                new
                {
                    username = "li",
                    password = "short",
                    roles = new[] { "Reader" },
                },
                new
                {
                    username = "li",
                    password = Password,
                    roles = new[] { "Root" },
                },
                new
                {
                    username = "li",
                    password = Password,
                    roles = Array.Empty<string>(),
                },
                new
                {
                    username = "",
                    password = Password,
                    roles = new[] { "Reader" },
                },
            }
        )
            Assert.Equal(HttpStatusCode.BadRequest, (await f.Client.PostAsJsonAsync("/api/users", bad)).StatusCode);

        var zhang = (await Users(f))["zhang"];
        Assert.Equal(["Reader", "Operator"], zhang.Roles);
        Assert.Equal((false, false, null), (zhang.TwoFactor, zhang.Disabled, zhang.LastLoginAt));
        Assert.Equal(
            HttpStatusCode.OK,
            (
                await f.Client.PutAsJsonAsync("/api/users/zhang/roles", new { roles = new[] { "Reader", "Admin" } })
            ).StatusCode
        );

        // The account signs in, which is recorded; it may manage accounts now, and others may not.
        Assert.Equal(HttpStatusCode.OK, (await SignIn(f, "zhang", Password)).StatusCode);
        Assert.NotNull((await Users(f))["zhang"].LastLoginAt);
        await f.Login("reader");
        Assert.Equal(HttpStatusCode.Forbidden, (await f.Client.GetAsync("/api/users")).StatusCode);

        // Neither an administrator's own account nor the last one able to manage accounts can be taken away.
        await f.Login();
        Assert.Equal(
            HttpStatusCode.BadRequest,
            (await f.Client.PostAsync("/api/users/admin/disable", null)).StatusCode
        );
        Assert.Equal(
            HttpStatusCode.OK,
            (await f.Client.PutAsJsonAsync("/api/users/zhang/roles", new { roles = new[] { "Reader" } })).StatusCode
        );
        var last = await f.Client.PutAsJsonAsync(
            "/api/users/admin/roles",
            new { roles = new[] { "Reader", "Operator" } }
        );
        Assert.Equal(HttpStatusCode.BadRequest, last.StatusCode);
        Assert.Contains("账号管理员", await Error(last));

        // A password reset signs the account out everywhere; a disabled account cannot sign in or keep its session.
        var reset = await f.Client.PostAsJsonAsync(
            "/api/users/zhang/password",
            new { password = "a-new-password-here" }
        );
        Assert.Equal(1, (await reset.Content.ReadFromJsonAsync<PasswordChanged>(Wire.Json))!.SignedOut);
        Assert.Equal(HttpStatusCode.Unauthorized, (await SignIn(f, "zhang", Password)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SignIn(f, "zhang", "a-new-password-here")).StatusCode);
        await f.Login();
        Assert.Equal(HttpStatusCode.OK, (await f.Client.PostAsync("/api/users/zhang/disable", null)).StatusCode);
        Assert.True((await Users(f))["zhang"].Disabled);
        var refused = await SignIn(f, "zhang", "a-new-password-here");
        Assert.Equal("Invalid credentials", await Error(refused));
        await f.Login();
        Assert.Equal(HttpStatusCode.OK, (await f.Client.PostAsync("/api/users/zhang/enable", null)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SignIn(f, "zhang", "a-new-password-here")).StatusCode);

        await f.Login();
        var audit = await f.Client.GetStringAsync("/api/audit");
        foreach (var action in new[] { "CreateUser", "SetUserRoles", "ResetUserPassword", "DisableUser", "EnableUser" })
            Assert.Contains(action, audit);
    }

    [Fact]
    public async Task Two_step_sign_in_asks_for_a_fresh_code_and_can_be_required_of_everyone()
    {
        await using var f = new Fixture();
        await f.Login("operator");
        var secret = await TurnOn(f);
        Assert.True((await f.Client.GetFromJsonAsync<SessionInfo>("/api/me", Wire.Json))!.TwoFactor);
        Assert.Equal(
            HttpStatusCode.BadRequest,
            (await f.Client.PostAsJsonAsync("/api/auth/two-factor/setup", new { })).StatusCode
        );

        // The code is asked for only once the password is right, and the code that turned it on is spent.
        Assert.Equal("Invalid credentials", await Error(await SignIn(f, "operator", "wrong-password-here")));
        Assert.Equal("TwoFactorRequired", await Error(await SignIn(f, "operator", Password)));
        var spent = await SignIn(f, "operator", Password, Now(f, secret));
        Assert.Equal(HttpStatusCode.Unauthorized, spent.StatusCode);
        Assert.Contains("验证码", await Error(spent));
        f.Clock.Now += Totp.Step;
        Assert.Equal(HttpStatusCode.OK, (await SignIn(f, "operator", Password, Now(f, secret))).StatusCode);

        // An administrator resets it for someone whose phone is lost, which signs them out.
        await f.Login();
        Assert.Equal(HttpStatusCode.OK, (await f.Client.DeleteAsync("/api/users/operator/two-factor")).StatusCode);
        Assert.False((await Users(f))["operator"].TwoFactor);
        Assert.Equal(HttpStatusCode.OK, (await SignIn(f, "operator", Password)).StatusCode);

        // Requiring it of everyone needs it on the administrator's own account first.
        await f.Login();
        var early = await f.Client.PutAsJsonAsync("/api/settings/require-two-factor", new { required = true });
        Assert.Equal(HttpStatusCode.BadRequest, early.StatusCode);
        var mine = await TurnOn(f);
        Assert.Equal(
            HttpStatusCode.OK,
            (await f.Client.PutAsJsonAsync("/api/settings/require-two-factor", new { required = true })).StatusCode
        );
        Assert.True((await f.Client.GetFromJsonAsync<UsersView>("/api/users", Wire.Json))!.RequireTwoFactor);
        var off = await f.Client.PostAsJsonAsync(
            "/api/auth/two-factor/disable",
            new { password = Password, code = "000000" }
        );
        Assert.Contains("不能关闭", await Error(off));

        // An account without it signs in, but can only set it up until it has.
        await f.Login("reader");
        var me = await f.Client.GetFromJsonAsync<SessionInfo>("/api/me", Wire.Json);
        Assert.Equal((true, false), (me!.TwoFactorRequired, me.TwoFactor));
        Assert.Equal(HttpStatusCode.Forbidden, (await f.Client.GetAsync("/api/devices")).StatusCode);
        f.Clock.Now += Totp.Step;
        await TurnOn(f);
        Assert.Equal(HttpStatusCode.OK, (await f.Client.GetAsync("/api/devices")).StatusCode);

        // Turned off again, by its owner, with the password and a fresh code, once no longer required.
        f.Clock.Now += Totp.Step;
        Assert.Equal(HttpStatusCode.OK, (await SignIn(f, "admin", Password, Now(f, mine))).StatusCode);
        await f.Client.PutAsJsonAsync("/api/settings/require-two-factor", new { required = false });
        f.Clock.Now += Totp.Step;
        var wrong = await f.Client.PostAsJsonAsync(
            "/api/auth/two-factor/disable",
            new { password = "wrong-password-here", code = Now(f, mine) }
        );
        Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        Assert.Equal(
            HttpStatusCode.OK,
            (
                await f.Client.PostAsJsonAsync(
                    "/api/auth/two-factor/disable",
                    new { password = Password, code = Now(f, mine) }
                )
            ).StatusCode
        );
        Assert.Equal(HttpStatusCode.OK, (await SignIn(f, "admin", Password)).StatusCode);

        var audit = await f.Client.GetStringAsync("/api/audit");
        foreach (
            var action in new[]
            {
                "EnableTwoFactor",
                "DisableTwoFactor",
                "ResetTwoFactor",
                "SetRequireTwoFactor",
                "LoginWrongCode",
            }
        )
            Assert.Contains(action, audit);
    }
}
