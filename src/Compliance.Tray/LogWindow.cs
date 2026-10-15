using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace Compliance.Tray;

/// <summary>
/// The resident service's log. It lives in its own folder that everyone may read, apart from the data folder that
/// only administrators may open.
/// </summary>
public sealed class LogWindow : Window
{
    public const string Argument = "--log";
    private const int MaxLines = 3000;

    private static readonly string Folder = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "ComplianceAgentLogs"
    );
    private static readonly string LogPath = Path.Combine(Folder, "agent.log");

    private readonly System.Windows.Controls.TextBox text;
    private readonly System.Windows.Controls.TextBox filter;
    private readonly System.Windows.Controls.CheckBox scansOnly;
    private readonly TextBlock status;
    private readonly DispatcherTimer timer = new() { Interval = TimeSpan.FromSeconds(5) };
    private string shown = "";

    private static LogWindow? open;

    /// <summary>Shows the log window, bringing back the one already open.</summary>
    public static void Open()
    {
        if (open is null)
        {
            open = new LogWindow();
            open.Closed += (_, _) => open = null;
            open.Show();
        }
        if (open.WindowState == WindowState.Minimized)
            open.WindowState = WindowState.Normal;
        open.Activate();
    }

    public LogWindow()
    {
        Style = (Style)System.Windows.Application.Current.FindResource(typeof(Window));
        Icon = Icons.Image(Icons.App, 32);
        Title = "终端合规客户端 · 运行日志";
        Width = 900;
        Height = 600;
        var page = (System.Windows.Media.Brush)FindResource("Surface");
        var line = (System.Windows.Media.Brush)FindResource("Line");
        var muted = (System.Windows.Media.Brush)FindResource("Muted");
        filter = new System.Windows.Controls.TextBox
        {
            Width = 220,
            Padding = new Thickness(6, 4, 6, 4),
            BorderBrush = line,
            VerticalContentAlignment = VerticalAlignment.Center,
            ToolTip = "只显示包含这段文字的行",
        };
        scansOnly = new System.Windows.Controls.CheckBox
        {
            Content = "只看敏感文件扫描",
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(16, 0, 0, 0),
        };
        var open = new System.Windows.Controls.Button
        {
            Content = "打开日志文件夹",
            Style = (Style)FindResource("Link"),
            VerticalAlignment = VerticalAlignment.Center,
        };
        filter.TextChanged += (_, _) => Load(force: true);
        scansOnly.Click += (_, _) => Load(force: true);
        open.Click += (_, _) =>
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{Folder}\"") { UseShellExecute = true });

        var heading = new StackPanel
        {
            Margin = new Thickness(12, 0, 0, 0),
            VerticalAlignment = VerticalAlignment.Center,
        };
        heading.Children.Add(
            new TextBlock
            {
                Text = "运行日志",
                FontSize = 16,
                FontWeight = FontWeights.SemiBold,
            }
        );
        heading.Children.Add(
            new TextBlock
            {
                Text = "客户端服务的检查、上报和敏感文件扫描记录，每 5 秒自动刷新",
                FontSize = 12,
                Foreground = muted,
            }
        );
        var header = new DockPanel { Margin = new Thickness(20, 16, 20, 16) };
        DockPanel.SetDock(open, Dock.Right);
        header.Children.Add(open);
        var logo = new System.Windows.Controls.Image
        {
            Source = Icons.Image(Icons.App, 64),
            Width = 36,
            Height = 36,
        };
        DockPanel.SetDock(logo, Dock.Left);
        header.Children.Add(logo);
        header.Children.Add(heading);
        var top = new Border
        {
            Background = page,
            BorderBrush = line,
            BorderThickness = new Thickness(0, 0, 0, 1),
            Child = header,
        };

        var bar = new StackPanel
        {
            Orientation = System.Windows.Controls.Orientation.Horizontal,
            Margin = new Thickness(20, 14, 20, 10),
        };
        bar.Children.Add(
            new TextBlock
            {
                Text = "筛选",
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 8, 0),
            }
        );
        bar.Children.Add(filter);
        bar.Children.Add(scansOnly);

        text = new System.Windows.Controls.TextBox
        {
            IsReadOnly = true,
            BorderThickness = new Thickness(0),
            Background = System.Windows.Media.Brushes.Transparent,
            FontFamily = new System.Windows.Media.FontFamily("Cascadia Mono, Consolas, Microsoft YaHei UI"),
            FontSize = 12,
            TextWrapping = TextWrapping.NoWrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
        };
        var sheet = new Border
        {
            Background = page,
            BorderBrush = line,
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(12, 8, 4, 8),
            Margin = new Thickness(20, 0, 20, 0),
            Child = text,
        };
        status = new TextBlock
        {
            Margin = new Thickness(20, 8, 20, 12),
            Foreground = muted,
            FontSize = 12,
            TextTrimming = TextTrimming.CharacterEllipsis,
        };

        var layout = new DockPanel();
        DockPanel.SetDock(top, Dock.Top);
        DockPanel.SetDock(bar, Dock.Top);
        DockPanel.SetDock(status, Dock.Bottom);
        layout.Children.Add(top);
        layout.Children.Add(bar);
        layout.Children.Add(status);
        layout.Children.Add(sheet);
        Content = layout;

        timer.Tick += (_, _) => Load(force: false);
        Loaded += (_, _) =>
        {
            Load(force: true);
            timer.Start();
        };
        Closed += (_, _) => timer.Stop();
    }

    private void Load(bool force)
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
            text.Text = "";
            status.Text = $"还没有日志：{LogPath}。客户端服务启动后开始记录（每次检查一行摘要）。";
            return;
        }
        var keyword = filter.Text.Trim();
        var selected = lines
            .Where(l => scansOnly.IsChecked != true || l.Contains("敏感文件扫描"))
            .Where(l => keyword.Length == 0 || l.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            .TakeLast(MaxLines)
            .ToArray();
        var content = string.Join(Environment.NewLine, selected);
        if (force || content != shown)
        {
            // Keep the reader's place unless they are following the end.
            var following = text.VerticalOffset + text.ViewportHeight >= text.ExtentHeight - 4;
            shown = content;
            text.Text = content;
            if (following || force)
                text.ScrollToEnd();
        }
        status.Text =
            $"{LogPath} · 显示 {selected.Length} / {lines.Length} 行 · 最后写入 {File.GetLastWriteTime(LogPath):HH:mm:ss}";
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
}
