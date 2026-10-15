using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace Compliance.Tray;

/// <summary>
/// The resident service's log for administrators testing the client. It lives in the service's data folder, which only
/// administrators can read, so the tray opens this window in a separate elevated process.
/// </summary>
public sealed class LogWindow : Window
{
    public const string Argument = "--log";
    private const int MaxLines = 3000;

    private static readonly string Folder = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "ComplianceAgent"
    );
    private static readonly string LogPath = Path.Combine(Folder, "agent.log");

    private readonly System.Windows.Controls.TextBox text;
    private readonly System.Windows.Controls.TextBox filter;
    private readonly System.Windows.Controls.CheckBox scansOnly;
    private readonly TextBlock status;
    private readonly DispatcherTimer timer = new() { Interval = TimeSpan.FromSeconds(5) };
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
        Title = "终端合规客户端 · 运行日志";
        Width = 900;
        Height = 600;
        filter = new System.Windows.Controls.TextBox { Width = 220, Margin = new Thickness(6, 0, 12, 0) };
        scansOnly = new System.Windows.Controls.CheckBox
        {
            Content = "只看敏感文件扫描",
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 12, 0),
        };
        var refresh = new System.Windows.Controls.Button
        {
            Content = "刷新",
            Padding = new Thickness(10, 2, 10, 2),
            Margin = new Thickness(0, 0, 8, 0),
        };
        var open = new System.Windows.Controls.Button
        {
            Content = "打开日志文件夹",
            Padding = new Thickness(10, 2, 10, 2),
        };
        filter.TextChanged += (_, _) => Load(force: true);
        scansOnly.Click += (_, _) => Load(force: true);
        refresh.Click += (_, _) => Load(force: true);
        open.Click += (_, _) =>
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{Folder}\"") { UseShellExecute = true });

        var bar = new StackPanel
        {
            Orientation = System.Windows.Controls.Orientation.Horizontal,
            Margin = new Thickness(10),
        };
        bar.Children.Add(new TextBlock { Text = "筛选", VerticalAlignment = VerticalAlignment.Center });
        bar.Children.Add(filter);
        bar.Children.Add(scansOnly);
        bar.Children.Add(refresh);
        bar.Children.Add(open);

        text = new System.Windows.Controls.TextBox
        {
            IsReadOnly = true,
            FontFamily = new System.Windows.Media.FontFamily("Consolas, Microsoft YaHei UI"),
            FontSize = 12,
            TextWrapping = TextWrapping.NoWrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
            Margin = new Thickness(10, 0, 10, 0),
        };
        status = new TextBlock
        {
            Margin = new Thickness(10, 6, 10, 10),
            Foreground = System.Windows.Media.Brushes.Gray,
        };

        var layout = new DockPanel();
        DockPanel.SetDock(bar, Dock.Top);
        DockPanel.SetDock(status, Dock.Bottom);
        layout.Children.Add(bar);
        layout.Children.Add(status);
        layout.Children.Add(text);
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
            status.Text =
                $"还没有日志：{LogPath}。客户端服务更新到新版本并启动后开始记录（每 5 分钟检查一次，每次一行摘要）。";
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
            $"{LogPath} · 显示 {selected.Length} / {lines.Length} 行 · 每 5 秒自动刷新 · 最后更新 {File.GetLastWriteTime(LogPath):HH:mm:ss}";
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
