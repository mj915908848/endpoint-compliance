using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;
using System.Windows;
using System.Windows.Threading;
using Forms = System.Windows.Forms;

namespace Compliance.Tray;

public partial class App : System.Windows.Application
{
    private const string PipeName = "ComplianceAgent.Notifications.v1";

    private Forms.NotifyIcon? icon;
    private NoticeWindow? window;
    private readonly HashSet<string> displayed = [];
    private readonly DispatcherTimer timer = new() { Interval = TimeSpan.FromSeconds(20) };
    private string? state;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        if (e.Args.Contains(LogWindow.Argument))
        {
            ShutdownMode = ShutdownMode.OnLastWindowClose;
            new LogWindow().Show();
            return;
        }
        ShutdownMode = ShutdownMode.OnExplicitShutdown;
        icon = new Forms.NotifyIcon { Text = "终端合规", Visible = true };
        SetState(Icons.App, "终端合规 · 正在连接客户端服务");
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("打开通知中心", null, (_, _) => ShowWindow());
        menu.Items.Add("运行日志（需管理员）", null, (_, _) => LogWindow.OpenElevated());
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("退出托盘", null, (_, _) => Shutdown());
        icon.ContextMenuStrip = menu;
        icon.MouseClick += (_, args) =>
        {
            if (args.Button == Forms.MouseButtons.Left)
                ShowWindow();
        };
        icon.BalloonTipClicked += (_, _) => ShowWindow();
        timer.Tick += async (_, _) => await RefreshAsync();
        timer.Start();
        // Opened at start for a quick look (and for screenshots in CI).
        if (e.Args.Contains("--notices"))
            ShowWindow();
        _ = RefreshAsync();
    }

    private void ShowWindow()
    {
        if (window is null)
        {
            window = new NoticeWindow(AcknowledgeAsync, RefreshAsync);
            window.Closed += (_, _) => window = null;
        }
        window.Show();
        window.Activate();
        _ = RefreshAsync();
    }

    private async Task RefreshAsync()
    {
        Notice[] notices;
        try
        {
            notices = Parse(await PipeRequestAsync("{\"action\":\"list\"}"));
        }
        catch (Exception ex)
            when (ex is IOException or TimeoutException or JsonException or UnauthorizedAccessException)
        {
            SetState(Icons.Offline, "终端合规 · 未连接客户端服务");
            window?.ShowDisconnected();
            return;
        }
        var unread = notices.Where(n => !n.Acknowledged).ToArray();
        SetState(
            unread.Length > 0 ? Icons.Alert : Icons.App,
            unread.Length > 0 ? $"终端合规 · {unread.Length} 条未读通知" : "终端合规 · 运行正常"
        );
        foreach (var notice in unread.Where(n => displayed.Add(n.Id)))
        {
            var (label, _, text) = notice.Parse();
            icon?.ShowBalloonTip(
                5000,
                "终端合规 · " + label,
                text[..Math.Min(text.Length, 200)],
                label == "已恢复" ? Forms.ToolTipIcon.Info : Forms.ToolTipIcon.Warning
            );
        }
        window?.ShowNotices(notices);
    }

    private static Notice[] Parse(string reply)
    {
        using var json = JsonDocument.Parse(reply);
        if (json.RootElement.ValueKind != JsonValueKind.Array)
            throw new JsonException("Service refused the request: " + reply);
        return json
            .RootElement.EnumerateArray()
            .Select(n => new Notice(
                n.GetProperty("eventId").GetString()!,
                n.GetProperty("message").GetString() ?? "",
                n.TryGetProperty("at", out var at) && at.TryGetDateTimeOffset(out var time) ? time : DateTimeOffset.Now,
                n.GetProperty("acknowledged").GetBoolean()
            ))
            .ToArray();
    }

    private async Task AcknowledgeAsync(string id)
    {
        try
        {
            await PipeRequestAsync(JsonSerializer.Serialize(new { action = "ack", eventId = id }));
        }
        catch (Exception ex) when (ex is IOException or TimeoutException or UnauthorizedAccessException) { }
    }

    /// <summary>Changes the tray icon only when the state changes, so the icon does not flicker every refresh.</summary>
    private void SetState(string name, string tooltip)
    {
        if (icon is null)
            return;
        icon.Text = tooltip.Length > 63 ? tooltip[..63] : tooltip;
        if (state == name)
            return;
        var previous = icon.Icon;
        icon.Icon = Icons.Tray(name);
        previous?.Dispose();
        state = name;
    }

    private static async Task<string> PipeRequestAsync(string request)
    {
        using var pipe = new NamedPipeClientStream(
            ".",
            PipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous,
            TokenImpersonationLevel.Identification
        );
        await pipe.ConnectAsync(2000);
        using var writer = new StreamWriter(pipe, leaveOpen: true) { AutoFlush = true };
        using var reader = new StreamReader(pipe, leaveOpen: true);
        await writer.WriteLineAsync(request);
        return await reader.ReadLineAsync() ?? throw new IOException("Empty service response");
    }

    protected override void OnExit(ExitEventArgs e)
    {
        timer.Stop();
        if (icon is not null)
        {
            icon.Visible = false;
            icon.Icon?.Dispose();
            icon.Dispose();
        }
        base.OnExit(e);
    }
}
