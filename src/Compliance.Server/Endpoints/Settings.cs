using System.Security.Cryptography;
using System.Text;
using Compliance.Core;

namespace Compliance.Server;

/// <summary>Settings changed in the management UI: alert notifications and how long audit records are kept.</summary>
static partial class Endpoints
{
    sealed record NotificationRequest(
        bool Enabled,
        string? Channel,
        string? WebhookUrl,
        // null keeps the saved secret, "" removes it.
        string? Secret,
        string[]? Types,
        string? ConsoleUrl,
        // The version the form was filled from; null skips the check (older pages).
        string? Version = null
    );

    sealed record AuditRetentionRequest(int Days);

    /// <summary>
    /// The robot address as shown in the UI: its token is the address itself, so only the host and the last few
    /// characters are shown. Sending this form back keeps the saved address.
    /// </summary>
    internal static string MaskWebhook(string url)
    {
        if (url.Length == 0)
            return "";
        var host = Uri.TryCreate(url, UriKind.Absolute, out var u) ? $"{u.Scheme}://{u.Host}/" : "";
        return $"{host}****{url[^Math.Min(4, url.Length)..]}";
    }

    /// <summary>Identifies what is saved, so a form filled before someone else's save can be told apart.</summary>
    static async Task<string> NotificationsVersion(Transaction tx) =>
        Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(await tx.GetSetting(NotificationSettings.Key) ?? ""))
        )[..16];

    static void MapSettings(IEndpointRouteBuilder routes, ComplianceService s, AlertNotifier notifier)
    {
        var group = routes.MapGroup("/api/settings");

        group.MapGet(
            "",
            async (HttpContext c) =>
            {
                Require(c, "Operator");
                return await s.Tx(async tx =>
                {
                    var n = await AlertNotifier.Settings(tx);
                    return new AppSettings(
                        new NotificationView(
                            n.Enabled,
                            n.Channel,
                            MaskWebhook(n.WebhookUrl),
                            n.Secret.Length > 0,
                            n.Types,
                            n.ConsoleUrl,
                            await NotificationsVersion(tx)
                        ),
                        notifier.Last,
                        await Housekeeping.AuditRetentionDays(tx)
                    );
                });
            }
        );

        group
            .MapPut(
                "/notifications",
                async (HttpContext c) =>
                {
                    var u = Require(c, "Operator");
                    var r = await Body<NotificationRequest>(c);
                    var channel = r.Channel ?? "";
                    var url = (r.WebhookUrl ?? "").Trim();
                    // The masked address the UI was given means "unchanged".
                    var saved = await s.Tx(AlertNotifier.Settings);
                    var kept = saved.WebhookUrl.Length > 0 && url == MaskWebhook(saved.WebhookUrl);
                    if (kept)
                        url = saved.WebhookUrl;
                    var console = (r.ConsoleUrl ?? "").Trim().TrimEnd('/');
                    if (!NotificationSettings.Channels.Contains(channel))
                        throw new ApiError(400, "请选择推送渠道");
                    if (url.Length > 0 || r.Enabled)
                    {
                        if (
                            url.Length > 512
                            || !Uri.TryCreate(url, UriKind.Absolute, out var webhook)
                            || webhook.Scheme != Uri.UriSchemeHttps
                            || !NotificationSettings.Hosts(channel).Contains(webhook.Host)
                        )
                            throw new ApiError(
                                400,
                                $"机器人地址应以 https://{NotificationSettings.Hosts(channel)[0]}/ 开头，请从群机器人设置中复制"
                            );
                    }
                    if (r.Secret is { Length: > 256 })
                        throw new ApiError(400, "签名密钥过长");
                    var types = (r.Types ?? []).Distinct().ToArray();
                    if (types.Any(t => !NotificationSettings.AlertTypes.Contains(t)))
                        throw new ApiError(400, "告警类型无效");
                    if (r.Enabled && types.Length == 0)
                        throw new ApiError(400, "请至少选择一种要推送的告警");
                    if (
                        console.Length > 0
                        && (
                            console.Length > 256
                            || !Uri.TryCreate(console, UriKind.Absolute, out var consoleUri)
                            || consoleUri.Scheme is not ("https" or "http")
                        )
                    )
                        throw new ApiError(400, "管理端地址无效");

                    return await s.Tx(async tx =>
                    {
                        await tx.Lock(NotificationSettings.Key);
                        var current = await AlertNotifier.Settings(tx);
                        if (r.Version is { } version && version != await NotificationsVersion(tx))
                            throw new ApiError(409, "告警推送设置刚被其他人修改，请载入最新设置后再改");
                        // Changed meanwhile: the masked form now names an address nobody here has seen.
                        if (kept && current.WebhookUrl != saved.WebhookUrl)
                            throw new ApiError(409, "机器人地址刚被其他人修改，请刷新后重试");
                        var next = new NotificationSettings
                        {
                            Enabled = r.Enabled,
                            Channel = channel,
                            WebhookUrl = url,
                            Secret = (r.Secret ?? current.Secret).Trim(),
                            Types = types,
                            ConsoleUrl = console,
                        };
                        await tx.PutSetting(NotificationSettings.Key, Wire.Serialize(next));
                        await tx.Audit(
                            u.Username,
                            "SetNotifications",
                            r.Enabled ? $"开启（{channel}）" : "关闭",
                            s.Now
                        );
                        return new NotificationsSaved(await NotificationsVersion(tx));
                    });
                }
            )
            .Accepts<NotificationRequest>(JsonBody);

        group
            .MapPost(
                "/notifications/test",
                async (HttpContext c) =>
                {
                    var u = Require(c, "Operator");
                    var settings = await s.Tx(async tx =>
                    {
                        await tx.Audit(u.Username, "TestNotification", "", s.Now);
                        return await AlertNotifier.Settings(tx);
                    });
                    var error = await notifier.Test(settings, c.RequestAborted);
                    return new NotificationTested(error == null, error);
                }
            )
            .RequireRateLimiting("notify-test");

        group
            .MapPut(
                "/audit-retention",
                async (HttpContext c) =>
                {
                    // Audit records also hold operators to account, so only publishers may shorten them.
                    var u = Require(c, "Publisher");
                    var r = await Body<AuditRetentionRequest>(c);
                    if (!Housekeeping.AuditRetentionChoices.Contains(r.Days))
                        throw new ApiError(400, "保留期限无效");
                    return await s.Tx(async tx =>
                    {
                        await tx.PutSetting(Housekeeping.AuditRetentionKey, r.Days.ToString());
                        await tx.Audit(
                            u.Username,
                            "SetAuditRetention",
                            r.Days == 0 ? "永久保留" : $"{r.Days} 天",
                            s.Now
                        );
                        return new Done();
                    });
                }
            )
            .Accepts<AuditRetentionRequest>(JsonBody);
    }
}
