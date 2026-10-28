using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Compliance.Core;

namespace Compliance.Server;

/// <summary>Where new alerts are pushed: a group robot of WeCom, DingTalk or Feishu.</summary>
public sealed record NotificationSettings
{
    public bool Enabled { get; init; }
    public string Channel { get; init; } = "WeCom";
    public string WebhookUrl { get; init; } = "";

    /// <summary>DingTalk's and Feishu's signing secret; WeCom robots have none.</summary>
    public string Secret { get; init; } = "";

    /// <summary>
    /// Alert types to push. Offline is left out by default: every PC shut down after work raises one.
    /// </summary>
    public string[] Types { get; init; } = ["Violation", "SensitiveFile", "Baseline", "Tamper", "Health"];

    /// <summary>The management UI address put into messages, e.g. https://compliance.example.com.</summary>
    public string ConsoleUrl { get; init; } = "";

    public const string Key = "notifications";

    public static readonly string[] Channels = ["WeCom", "DingTalk", "Feishu"];
    public static readonly string[] AlertTypes =
    [
        "Violation",
        "SensitiveFile",
        "Baseline",
        "Tamper",
        "Health",
        "BlockedAttempt",
        "UsbBlocked",
        "Offline",
    ];

    /// <summary>Robot webhooks only go to their vendor, so a saved URL cannot reach hosts inside the network.</summary>
    public static string[] Hosts(string channel) =>
        channel switch
        {
            "WeCom" => ["qyapi.weixin.qq.com"],
            "DingTalk" => ["oapi.dingtalk.com"],
            "Feishu" => ["open.feishu.cn", "open.larksuite.com"],
            _ => [],
        };
}

public sealed record NotificationResult(DateTimeOffset At, bool Ok, string Error, int Sent);

/// <summary>
/// Pushes active alerts that have not been pushed yet, in one message per run so a burst of alerts stays one
/// message. Alerts of types not selected, acknowledged ones and all of them while pushing is off are marked as
/// handled without sending, so turning it on later does not send old alerts. A failed send is retried next run.
/// </summary>
public sealed class AlertNotifier(ComplianceService service, IHttpClientFactory http, ILogger<AlertNotifier> logger)
{
    public const string HttpClientName = "notifications";
    const int Batch = 200;
    const int Listed = 10;

    readonly SemaphoreSlim gate = new(1);

    /// <summary>The last attempt to send, shown in the settings page.</summary>
    public NotificationResult? Last { get; private set; }

    public static async Task<NotificationSettings> Settings(Transaction tx) =>
        await tx.GetSetting(NotificationSettings.Key) is { } json
            ? Wire.Read<NotificationSettings>(json)
            : new NotificationSettings();

    public async Task Run(CancellationToken ct = default)
    {
        await gate.WaitAsync(ct);
        try
        {
            var (settings, pending) = await service.Tx(async tx =>
                (await Settings(tx), await tx.PendingNotifications(Batch))
            );
            if (pending.Count == 0)
                return;
            var send = pending
                .Where(p => settings.Enabled && settings.Types.Contains(p.Alert.Type) && !p.Alert.Acknowledged)
                .ToList();
            var skipped = pending.Except(send).Select(p => (p.Alert.Id, p.Activation)).ToList();
            if (skipped.Count > 0)
                await service.Tx(async tx =>
                {
                    await tx.MarkNotified(skipped);
                    return true;
                });
            if (send.Count == 0)
                return;

            var error = await Send(settings, Message(settings, send), ct);
            Last = new(service.Now, error == null, error ?? "", error == null ? send.Count : 0);
            if (error != null)
            {
                logger.LogWarning("Pushing {Count} alerts failed: {Error}", send.Count, error);
                return;
            }
            await service.Tx(async tx =>
            {
                await tx.MarkNotified(send.Select(p => (p.Alert.Id, p.Activation)));
                return true;
            });
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>Sends a test message with <paramref name="settings"/>; returns null or why it failed.</summary>
    public async Task<string?> Test(NotificationSettings settings, CancellationToken ct = default)
    {
        var text = "【终端合规】测试消息\n告警推送已配置成功，出现新告警时会发到这个群。";
        if (settings.ConsoleUrl.Length > 0)
            text += "\n管理端：" + settings.ConsoleUrl;
        var error = await Send(settings, text, ct);
        Last = new(service.Now, error == null, error ?? "", 0);
        return error;
    }

    static string Message(
        NotificationSettings settings,
        List<(AlertSummary Alert, string Note, long Activation)> alerts
    )
    {
        var b = new StringBuilder($"【终端合规】新告警 {alerts.Count} 条");
        foreach (var (a, note, _) in alerts.Take(Listed))
        {
            var device = note.Length > 0 ? $"{a.HostName}（{note}）" : a.HostName;
            var summary = a.Summary.ReplaceLineEndings(" ");
            if (summary.Length > 120)
                summary = summary[..120] + "…";
            b.Append($"\n\n[{Labels.AlertType(a.Type)}] {device}\n{summary}\n{a.FirstSeen.ToLocalTime():MM-dd HH:mm}");
        }
        if (alerts.Count > Listed)
            b.Append($"\n\n另有 {alerts.Count - Listed} 条未列出");
        if (settings.ConsoleUrl.Length > 0)
            b.Append($"\n\n查看详情：{settings.ConsoleUrl.TrimEnd('/')}/alerts");
        return b.ToString();
    }

    async Task<string?> Send(NotificationSettings settings, string text, CancellationToken ct)
    {
        if (settings.WebhookUrl.Length == 0)
            return "未填写机器人地址";
        try
        {
            var client = http.CreateClient(HttpClientName);
            using var response = await client.SendAsync(Request(settings, text, service.Now), ct);
            var body = await response.Content.ReadAsStringAsync(ct);
            if (!response.IsSuccessStatusCode)
                return $"HTTP {(int)response.StatusCode}";
            return VendorError(body);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            return "无法连接机器人地址：" + e.Message;
        }
    }

    /// <summary>The request each vendor's group robot expects, signed when a secret is set.</summary>
    public static HttpRequestMessage Request(NotificationSettings settings, string text, DateTimeOffset now)
    {
        var url = settings.WebhookUrl;
        object body;
        switch (settings.Channel)
        {
            case "DingTalk":
                if (settings.Secret.Length > 0)
                {
                    var ms = now.ToUnixTimeMilliseconds().ToString();
                    var sign = Convert.ToBase64String(
                        HMACSHA256.HashData(
                            Encoding.UTF8.GetBytes(settings.Secret),
                            Encoding.UTF8.GetBytes(ms + "\n" + settings.Secret)
                        )
                    );
                    url += (url.Contains('?') ? "&" : "?") + $"timestamp={ms}&sign={Uri.EscapeDataString(sign)}";
                }
                body = new { msgtype = "text", text = new { content = text } };
                break;
            case "Feishu":
                if (settings.Secret.Length > 0)
                {
                    var seconds = now.ToUnixTimeSeconds().ToString();
                    var sign = Convert.ToBase64String(
                        HMACSHA256.HashData(
                            Encoding.UTF8.GetBytes(seconds + "\n" + settings.Secret),
                            Array.Empty<byte>()
                        )
                    );
                    body = new
                    {
                        timestamp = seconds,
                        sign,
                        msg_type = "text",
                        content = new { text },
                    };
                }
                else
                    body = new { msg_type = "text", content = new { text } };
                break;
            default:
                body = new { msgtype = "text", text = new { content = text } };
                break;
        }
        return new HttpRequestMessage(HttpMethod.Post, url) { Content = JsonContent.Create(body) };
    }

    /// <summary>The robots answer HTTP 200 with an error code in the body; WeCom and DingTalk use errcode, Feishu code.</summary>
    static string? VendorError(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            foreach (
                var (code, message) in new[] { ("errcode", "errmsg"), ("code", "msg"), ("StatusCode", "StatusMessage") }
            )
                if (root.TryGetProperty(code, out var c) && c.ValueKind == JsonValueKind.Number)
                    return c.GetInt64() == 0
                        ? null
                        : $"机器人返回错误 {c.GetInt64()}："
                            + (root.TryGetProperty(message, out var m) ? m.ToString() : "");
            return null;
        }
        catch (JsonException)
        {
            return "机器人返回了无法识别的内容";
        }
    }
}

public sealed class NotificationService(AlertNotifier notifier, ILogger<NotificationService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(30));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await notifier.Run(stoppingToken);
            }
            catch (Exception e) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogError(e, "Alert notification failed");
            }
        }
    }
}
