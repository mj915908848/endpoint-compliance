using System.IO;
using System.Runtime.InteropServices;
using Compliance.Core;
using Timer = System.Windows.Forms.Timer;

namespace Compliance.Tray;

public static class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        // Notifications then carry the name and icon of the MSI's Start menu shortcut with this id.
        SetCurrentProcessExplicitAppUserModelID(TrayApp.AppUserModelId);
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
            // One tray per sign-in session: the Run key, the install scripts and the MSI all start one. A second
            // start opens the running tray's notification center instead, which also offers enrolling.
            using var single = new Mutex(true, TrayApp.MutexName, out var first);
            using var show = new EventWaitHandle(false, EventResetMode.AutoReset, TrayApp.ShowEventName);
            if (!first)
            {
                show.Set();
                return;
            }
            // --setup [the MSI's path]: opened by the MSI after installing; enrolls unless the service already is.
            var setup = Array.IndexOf(args, "--setup");
            Application.Run(
                new TrayApp(
                    args.Contains("--notices"),
                    setup < 0 ? null
                        : setup + 1 < args.Length && !args[setup + 1].StartsWith("--", StringComparison.Ordinal)
                            ? args[setup + 1]
                        : "",
                    show
                )
            );
        }
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SetCurrentProcessExplicitAppUserModelID(string appId);
}

/// <summary>The notification-area icon: polls the service for notices, shows new ones as balloons and opens the notification center.</summary>
public sealed class TrayApp : ApplicationContext
{
    public const string MutexName = @"Local\ComplianceAgent.Tray";

    /// <summary>The tray's AppUserModelID, also set on the MSI's Start menu shortcut (Package.wxs).</summary>
    public const string AppUserModelId = "ComplianceAgent.Tray";
    public const string ShowEventName = @"Local\ComplianceAgent.Tray.Show";

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

    private RegisteredWaitHandle? showRequests;

    public TrayApp(bool showNotices, string? setupSource = null, EventWaitHandle? show = null)
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
        if (show is not null)
        {
            // The wait completes on a pool thread; the window opens on the UI thread.
            var ui = SynchronizationContext.Current ?? new WindowsFormsSynchronizationContext();
            showRequests = ThreadPool.RegisterWaitForSingleObject(
                show,
                (_, _) => ui.Post(_ => ShowWindow(), null),
                null,
                Timeout.Infinite,
                false
            );
        }
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
            notices = (await TrayPipe.ListAsync())
                ?.Select(n => new Notice(n.EventId, n.Message, n.At, n.Acknowledged))
                .ToArray();
        }
        // Anything else, such as a reply from a service of another version, must not end the tray either: this
        // runs from the timer's async void handler, where an escaping exception closes the process.
        catch (Exception)
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

    private async Task AcknowledgeAsync(string id)
    {
        try
        {
            await TrayPipe.AcknowledgeAsync(id);
        }
        // A failed acknowledgement leaves the notice unread; the refresh that follows shows it again.
        catch (Exception) { }
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

    protected override void ExitThreadCore()
    {
        timer.Stop();
        showRequests?.Unregister(null);
        window?.Close();
        setup?.Close();
        icon.Visible = false;
        icon.Icon?.Dispose();
        icon.Dispose();
        base.ExitThreadCore();
    }
}
