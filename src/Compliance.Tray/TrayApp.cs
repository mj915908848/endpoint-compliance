using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;
using Timer = System.Windows.Forms.Timer;

namespace Compliance.Tray;

public static class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        Application.SetHighDpiMode(HighDpiMode.SystemAware);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        if (args.Contains(LogWindow.Argument))
        {
            using var single = new Mutex(true, LogWindow.MutexName, out var first);
            if (first)
                Application.Run(new LogWindow());
            else
                LogWindow.ActivateExisting();
        }
        else
            Application.Run(new TrayApp(args.Contains("--notices")));
    }
}

/// <summary>The notification-area icon: polls the service for notices, shows new ones as balloons and opens the notification center.</summary>
public sealed class TrayApp : ApplicationContext
{
    private const string PipeName = "ComplianceAgent.Notifications.v1";

    private readonly NotifyIcon icon;
    private NoticeWindow? window;
    private readonly HashSet<string> displayed = [];
    private readonly Timer timer = new() { Interval = 20_000 };
    private string? state;

    public TrayApp(bool showNotices)
    {
        var menu = new ContextMenuStrip { Font = Theme.Body };
        menu.Items.Add("打开通知中心", null, (_, _) => ShowWindow());
        menu.Items.Add("运行日志", null, (_, _) => LogWindow.Open());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("退出托盘", null, (_, _) => ExitThread());
        icon = new NotifyIcon
        {
            Text = "终端合规",
            ContextMenuStrip = menu,
            Visible = true,
        };
        SetState(Icons.App, "终端合规 · 正在连接客户端服务");
        icon.MouseClick += (_, args) =>
        {
            if (args.Button == MouseButtons.Left)
                ShowWindow();
        };
        icon.BalloonTipClicked += (_, _) => ShowWindow();
        timer.Tick += async (_, _) => await RefreshAsync();
        timer.Start();
        // Opened at start for a quick look (and for screenshots in CI).
        if (showNotices)
            ShowWindow();
        _ = RefreshAsync();
    }

    private void ShowWindow()
    {
        if (window is null)
        {
            window = new NoticeWindow(AcknowledgeAsync, RefreshAsync);
            window.FormClosed += (_, _) => window = null;
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
            icon.ShowBalloonTip(
                5000,
                "终端合规 · " + label,
                text[..Math.Min(text.Length, 200)],
                label == "已恢复" ? ToolTipIcon.Info : ToolTipIcon.Warning
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

    protected override void ExitThreadCore()
    {
        timer.Stop();
        window?.Close();
        icon.Visible = false;
        icon.Icon?.Dispose();
        icon.Dispose();
        base.ExitThreadCore();
    }
}
