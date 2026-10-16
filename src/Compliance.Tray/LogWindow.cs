using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Timer = System.Windows.Forms.Timer;

namespace Compliance.Tray;

/// <summary>
/// The resident service's log for administrators testing the client. It lives in the service's data folder, which only
/// administrators can read, so the tray opens this window in a separate elevated process.
/// </summary>
public sealed class LogWindow : Form
{
    public const string Argument = "--log";
    private const int MaxLines = 3000;

    private static readonly string Folder = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "ComplianceAgent"
    );
    private static readonly string LogPath = Path.Combine(Folder, "agent.log");

    // A rich edit control rather than a text box: it falls back to a Chinese font for the monospaced log.
    private readonly RichTextBox text;
    private readonly TextBox filter;
    private readonly CheckBox scansOnly;
    private readonly Label status;
    private readonly Timer timer = new() { Interval = 5000 };
    private string shown = "";

    /// <summary>Starts an elevated copy of the tray showing the log; nothing happens if the UAC prompt is declined.</summary>
    public static void OpenElevated()
    {
        try
        {
            Process.Start(
                new ProcessStartInfo(Environment.ProcessPath!, Argument) { UseShellExecute = true, Verb = "runas" }
            );
        }
        catch (System.ComponentModel.Win32Exception) { }
    }

    public LogWindow()
    {
        int S(int v) => LogicalToDeviceUnits(v);
        Icon = Icons.Window(Icons.App);
        Text = "终端合规客户端 · 运行日志";
        Font = Theme.Body;
        ForeColor = Theme.Text;
        BackColor = Theme.Page;
        Size = new Size(S(900), S(600));
        MinimumSize = new Size(S(560), S(360));
        StartPosition = FormStartPosition.CenterScreen;

        var open = Theme.Link("打开日志文件夹");
        open.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        open.LinkClicked += (_, _) =>
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{Folder}\"") { UseShellExecute = true });
        var header = new Theme.Bar(lineAtTop: false) { Dock = DockStyle.Top, Height = S(69) };
        var logo = new PictureBox
        {
            Image = Icons.Image(Icons.App, S(36)),
            SizeMode = PictureBoxSizeMode.Zoom,
            Bounds = new Rectangle(S(20), S(16), S(36), S(36)),
        };
        var title = Theme.Label("运行日志", Theme.Title, Theme.Text);
        title.Location = new Point(S(66), S(13));
        var subtitle = Theme.Label(
            "客户端服务的检查、上报和敏感文件扫描记录，每 5 秒自动刷新",
            Theme.Small,
            Theme.Muted
        );
        subtitle.Location = new Point(S(67), S(38));
        header.Controls.AddRange([logo, title, subtitle, open]);
        header.Layout += (_, _) => open.Location = new Point(header.Width - open.Width - S(20), S(25));

        var bar = new Panel { Dock = DockStyle.Top, Height = S(52) };
        var caption = Theme.Label("筛选", Theme.Body, Theme.Text);
        caption.Location = new Point(S(20), S(18));
        filter = new TextBox { Bounds = new Rectangle(S(56), S(14), S(220), S(26)) };
        new ToolTip().SetToolTip(filter, "只显示包含这段文字的行");
        scansOnly = new CheckBox
        {
            Text = "只看敏感文件扫描",
            AutoSize = true,
            Location = new Point(S(292), S(17)),
            UseMnemonic = false,
        };
        bar.Controls.AddRange([caption, filter, scansOnly]);
        filter.TextChanged += (_, _) => Reload(force: true);
        scansOnly.CheckedChanged += (_, _) => Reload(force: true);

        text = new RichTextBox
        {
            ReadOnly = true,
            BorderStyle = BorderStyle.None,
            BackColor = Theme.Surface,
            Font = new Font("Consolas", 9f),
            WordWrap = false,
            DetectUrls = false,
            ScrollBars = RichTextBoxScrollBars.Both,
            Dock = DockStyle.Fill,
        };
        var sheet = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Theme.Surface,
            BorderStyle = BorderStyle.FixedSingle,
            Padding = new Padding(S(10), S(6), S(2), S(6)),
        };
        sheet.Controls.Add(text);
        var frame = new Panel { Dock = DockStyle.Fill, Padding = new Padding(S(20), 0, S(20), 0) };
        frame.Controls.Add(sheet);

        status = new Label
        {
            Dock = DockStyle.Bottom,
            Height = S(34),
            Padding = new Padding(S(20), 0, S(20), 0),
            TextAlign = ContentAlignment.MiddleLeft,
            Font = Theme.Small,
            ForeColor = Theme.Muted,
            AutoEllipsis = true,
            UseMnemonic = false,
        };

        // Docked controls are laid out from the last added, so the filling area goes first.
        Controls.AddRange([frame, status, bar, header]);

        timer.Tick += (_, _) => Reload(force: false);
        Shown += (_, _) =>
        {
            Reload(force: true);
            timer.Start();
        };
        FormClosed += (_, _) => timer.Stop();
    }

    private void Reload(bool force)
    {
        string[] lines;
        try
        {
            lines = ReadLines();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            status.Text = $"无法读取 {LogPath}：{ex.Message}";
            return;
        }
        if (lines.Length == 0)
        {
            text.Clear();
            shown = "";
            status.Text =
                $"还没有日志：{LogPath}。客户端服务更新到新版本并启动后开始记录（每 5 分钟检查一次，每次一行摘要）。";
            return;
        }
        var keyword = filter.Text.Trim();
        var selected = lines
            .Where(l => !scansOnly.Checked || l.Contains("敏感文件扫描"))
            .Where(l => keyword.Length == 0 || l.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            .TakeLast(MaxLines)
            .ToArray();
        var content = string.Join("\n", selected);
        if (force || content != shown)
        {
            // Keep the reader's place unless they are following the end.
            var following = force || AtEnd();
            var position = Point.Empty;
            SendMessage(text.Handle, EM_GETSCROLLPOS, 0, ref position);
            shown = content;
            text.Text = content;
            if (following)
            {
                text.SelectionStart = text.TextLength;
                text.ScrollToCaret();
            }
            else
                SendMessage(text.Handle, EM_SETSCROLLPOS, 0, ref position);
        }
        status.Text =
            $"{LogPath} · 显示 {selected.Length} / {lines.Length} 行 · 最后写入 {File.GetLastWriteTime(LogPath):HH:mm:ss}";
    }

    private bool AtEnd()
    {
        var info = new ScrollInfo { Size = Marshal.SizeOf<ScrollInfo>(), Mask = SIF_ALL };
        if (!GetScrollInfo(text.Handle, SB_VERT, ref info) || info.Page == 0)
            return true;
        return info.Position + info.Page >= info.Max - 4;
    }

    /// <summary>The rotated file followed by the current one; opened shared because the service keeps appending.</summary>
    private static string[] ReadLines()
    {
        var lines = new List<string>();
        foreach (var path in new[] { LogPath + ".1", LogPath })
        {
            if (!File.Exists(path))
                continue;
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete
            );
            using var reader = new StreamReader(stream, Encoding.UTF8);
            while (reader.ReadLine() is { } line)
                lines.Add(line);
        }
        return lines.ToArray();
    }

    private const int EM_GETSCROLLPOS = 0x0400 + 221;
    private const int EM_SETSCROLLPOS = 0x0400 + 222;
    private const int SB_VERT = 1;
    private const int SIF_ALL = 0x17;

    [StructLayout(LayoutKind.Sequential)]
    private struct ScrollInfo
    {
        public int Size;
        public int Mask;
        public int Min;
        public int Max;
        public int Page;
        public int Position;
        public int TrackPosition;
    }

    [DllImport("user32.dll", EntryPoint = "SendMessageW")]
    private static extern nint SendMessage(nint window, int message, nint wParam, ref Point lParam);

    [DllImport("user32.dll")]
    private static extern bool GetScrollInfo(nint window, int bar, ref ScrollInfo info);
}
