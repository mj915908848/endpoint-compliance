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
        {
            // --setup [the MSI's path]: opened by the MSI after installing; enrolls unless the service already is.
            var setup = Array.IndexOf(args, "--setup");
            Application.Run(
                new TrayApp(
                    args.Contains("--notices"),
                    setup < 0 ? null
                        : setup + 1 < args.Length && !args[setup + 1].StartsWith("--", StringComparison.Ordinal)
                            ? args[setup + 1]
                        : ""
                )
            );
        }
    }
}

/// <summary>The notification-area icon: polls the service for notices, shows new ones as balloons and opens the notification center.</summary>
public sealed class TrayApp : ApplicationContext
{
    private const string PipeName = "ComplianceAgent.Notifications.v1";

    private readonly NotifyIcon icon;
    private NoticeWindow? window;
    private SetupWindow? setup;
    private readonly ToolStripItem enrollItem;

    /// <summary>Opening the enrollment window was asked for and waits for the first refresh; null otherwise.</summary>
    private string? setupSource;
    private bool notEnrolledShown;

    /// <summary>The notices from the last refresh; null while the service is unreachable.</summary>
    private Notice[]? latest;
    private readonly HashSet<string> displayed = [];
    private readonly Timer timer = new() { Interval = 20_000 };
    private string? state;

    public TrayApp(bool showNotices, string? setupSource = null)
    {
        this.setupSource = setupSource;
        var menu = new ContextMenuStrip { Font = Theme.Body };
        enrollItem = menu.Items.Add("登记到管理端…", null, (_, _) => ShowSetup(null));
        enrollItem.Visible = false;
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
        icon.BalloonTipClicked += (_, _) =>
        {
            if (enrollItem.Visible)
                ShowSetup(null);
            else
                ShowWindow();
        };
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
            // Opens on what the tray already knows rather than flashing "connecting" first.
            if (latest is not null)
                window.ShowNotices(latest);
        }
        window.Show();
        window.Activate();
        _ = RefreshAsync();
    }

    private void ShowSetup(string? source)
    {
        if (setup is null)
        {
            setup = new SetupWindow(source);
            setup.FormClosed += (_, _) => setup = null;
            setup.Enrolled += async (_, _) => await RefreshAsync();
        }
        setup.Show();
        setup.Activate();
    }

    private bool refreshing;
    private bool again;

    /// <summary>
    /// Refreshes run one at a time: clicks, the timer and acknowledgements can ask while one is waiting on the
    /// service, and those asks become a single further refresh rather than overlapping updates of the window.
    /// </summary>
    private async Task RefreshAsync()
    {
        if (refreshing)
        {
            again = true;
            return;
        }
        refreshing = true;
        try
        {
            do
            {
                again = false;
                await RefreshOnceAsync();
            } while (again);
        }
        finally
        {
            refreshing = false;
        }
    }

    private async Task RefreshOnceAsync()
    {
        Notice[]? notices;
        try
        {
            notices = Parse(await PipeRequestAsync("{\"action\":\"list\"}"));
        }
        catch (Exception ex)
            when (ex is IOException or TimeoutException or JsonException or UnauthorizedAccessException)
        {
            latest = null;
            enrollItem.Visible = false;
            SetState(Icons.Offline, "终端合规 · 未连接客户端服务");
            window?.ShowDisconnected();
            // Enrolling does not need the service running; it picks the enrollment up when it starts.
            OpenRequestedSetup();
            return;
        }
        enrollItem.Visible = notices is null;
        if (notices is null)
        {
            latest = null;
            SetState(Icons.Offline, "终端合规 · 尚未登记到管理端");
            window?.ShowNotEnrolled(() => ShowSetup(null));
            if (!OpenRequestedSetup() && !notEnrolledShown && setup is null)
                icon.ShowBalloonTip(
                    10000,
                    "终端合规 · 尚未登记",
                    "本机尚未登记到管理端，点这里填写管理端地址和登记码。",
                    ToolTipIcon.Info
                );
            notEnrolledShown = true;
            return;
        }
        setupSource = null;
        notEnrolledShown = false;
        latest = notices;
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

    private bool OpenRequestedSetup()
    {
        if (setupSource is null)
            return false;
        ShowSetup(setupSource);
        setupSource = null;
        return true;
    }

    /// <summary>The notices, or null when the service waits for an enrollment.</summary>
    private static Notice[]? Parse(string reply)
    {
        using var json = JsonDocument.Parse(reply);
        if (
            json.RootElement.ValueKind == JsonValueKind.Object
            && json.RootElement.TryGetProperty("error", out var error)
            && error.GetString() == "not-enrolled"
        )
            return null;
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
        setup?.Close();
        icon.Visible = false;
        icon.Icon?.Dispose();
        icon.Dispose();
        base.ExitThreadCore();
    }
}
