using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Brush = System.Windows.Media.Brush;
using Button = System.Windows.Controls.Button;
using Color = System.Windows.Media.Color;
using Image = System.Windows.Controls.Image;
using Orientation = System.Windows.Controls.Orientation;

namespace Compliance.Tray;

/// <summary>A notice from the service. Messages are stored as "Type: detail" (Violation, Reminder, Recovered, Blocked) or plain text.</summary>
public sealed record Notice(string Id, string Message, DateTimeOffset At, bool Acknowledged)
{
    public (string Label, Color Color, string Text) Parse()
    {
        foreach (
            var (prefix, label, color) in new[]
            {
                ("Violation: ", "需要处理", Color.FromRgb(0xF5, 0x3F, 0x3F)),
                ("Reminder: ", "仍未处理", Color.FromRgb(0xFF, 0x7D, 0x00)),
                ("Blocked: ", "已拦截", Color.FromRgb(0xF5, 0x3F, 0x3F)),
                ("Recovered: ", "已恢复", Color.FromRgb(0x00, 0xB4, 0x2A)),
            }
        )
            if (Message.StartsWith(prefix, StringComparison.Ordinal))
                return (label, color, Message[prefix.Length..]);
        return ("通知", Color.FromRgb(0x16, 0x64, 0xFF), Message);
    }
}

/// <summary>The notification center opened from the tray: what the administrator asked this user to know or fix.</summary>
public sealed class NoticeWindow : Window
{
    private readonly TextBlock status = new() { FontSize = 12 };
    private readonly Button readAll;
    private readonly StackPanel list = new() { Margin = new Thickness(16, 12, 16, 4) };
    private readonly Func<string, Task> acknowledge;
    private readonly Func<Task> refresh;
    private Notice[] shown = [];

    public NoticeWindow(Func<string, Task> acknowledge, Func<Task> refresh)
    {
        this.acknowledge = acknowledge;
        this.refresh = refresh;
        // Implicit styles apply to Window itself, not to subclasses.
        Style = (Style)System.Windows.Application.Current.FindResource(typeof(Window));
        Title = "终端合规";
        Icon = Icons.Image(Icons.App, 32);
        Width = 460;
        Height = 580;
        MinWidth = 380;
        MinHeight = 360;
        WindowStartupLocation = WindowStartupLocation.Manual;
        var area = SystemParameters.WorkArea;
        Left = area.Right - Width - 16;
        Top = area.Bottom - Height - 16;

        readAll = new Button
        {
            Content = "全部标为已读",
            Style = Styled("Link"),
            VerticalAlignment = VerticalAlignment.Center,
        };
        readAll.Click += async (_, _) =>
        {
            readAll.IsEnabled = false;
            foreach (var notice in shown.Where(n => !n.Acknowledged))
                await acknowledge(notice.Id);
            await refresh();
        };

        var title = new StackPanel
        {
            Margin = new Thickness(12, 0, 0, 0),
            VerticalAlignment = VerticalAlignment.Center,
        };
        title.Children.Add(
            new TextBlock
            {
                Text = "终端合规",
                FontSize = 16,
                FontWeight = FontWeights.SemiBold,
            }
        );
        title.Children.Add(status);
        var header = new DockPanel { Margin = new Thickness(20, 16, 20, 16) };
        DockPanel.SetDock(readAll, Dock.Right);
        header.Children.Add(readAll);
        var logo = new Image
        {
            Source = Icons.Image(Icons.App, 64),
            Width = 36,
            Height = 36,
        };
        DockPanel.SetDock(logo, Dock.Left);
        header.Children.Add(logo);
        header.Children.Add(title);
        var top = new Border
        {
            Background = Brush("Surface"),
            BorderBrush = Brush("Line"),
            BorderThickness = new Thickness(0, 0, 0, 1),
            Child = header,
        };

        var log = new Button
        {
            Content = "运行日志",
            Style = Styled("Link"),
            FontSize = 12,
        };
        log.Click += (_, _) => LogWindow.Open();
        var footer = new DockPanel { Margin = new Thickness(20, 10, 20, 12) };
        footer.Children.Add(
            new TextBlock
            {
                Text = "检查在后台自动进行，不读取文件内容",
                Foreground = Brush("Muted"),
                FontSize = 12,
            }
        );
        DockPanel.SetDock(log, Dock.Right);
        footer.Children.Insert(0, log);
        var bottom = new Border
        {
            Background = Brush("Surface"),
            BorderBrush = Brush("Line"),
            BorderThickness = new Thickness(0, 1, 0, 0),
            Child = footer,
        };

        var layout = new DockPanel();
        DockPanel.SetDock(top, Dock.Top);
        DockPanel.SetDock(bottom, Dock.Bottom);
        layout.Children.Add(top);
        layout.Children.Add(bottom);
        layout.Children.Add(
            new ScrollViewer { Content = list, VerticalScrollBarVisibility = ScrollBarVisibility.Auto }
        );
        Content = layout;
        ShowLoading();
    }

    private void ShowLoading()
    {
        status.Text = "正在连接客户端服务…";
        status.Foreground = Brush("Muted");
        readAll.Visibility = Visibility.Collapsed;
    }

    public void ShowNotices(Notice[] notices)
    {
        shown = notices;
        var unread = notices.Count(n => !n.Acknowledged);
        status.Text = unread > 0 ? $"客户端运行正常 · {unread} 条未读" : "客户端运行正常";
        status.Foreground = Brush("Muted");
        readAll.Visibility = unread > 0 ? Visibility.Visible : Visibility.Collapsed;
        readAll.IsEnabled = true;
        list.Children.Clear();
        if (notices.Length == 0)
        {
            list.Children.Add(
                State(
                    Icons.App,
                    "暂无通知",
                    "本机目前没有需要你处理的事项。如有情况，会在这里和屏幕右下角提醒你。",
                    null
                )
            );
            return;
        }
        foreach (var notice in notices.OrderBy(n => n.Acknowledged).ThenByDescending(n => n.At))
            list.Children.Add(Card(notice));
    }

    public void ShowDisconnected()
    {
        shown = [];
        status.Text = "未连接客户端服务";
        status.Foreground = new SolidColorBrush(Color.FromRgb(0xF5, 0x3F, 0x3F));
        readAll.Visibility = Visibility.Collapsed;
        list.Children.Clear();
        var retry = new Button { Content = "重试", Style = Styled("PrimaryButton") };
        retry.Click += async (_, _) =>
        {
            ShowLoading();
            await refresh();
        };
        list.Children.Add(
            State(
                Icons.Offline,
                "暂时连不上客户端服务",
                "客户端服务可能正在启动或已停止，托盘会每 20 秒自动重试。如果一直出现，请联系 IT 管理员。",
                retry
            )
        );
    }

    private UIElement Card(Notice notice)
    {
        var (label, color, text) = notice.Parse();
        var tag = new Border
        {
            Background = new SolidColorBrush(Color.FromArgb(0x1F, color.R, color.G, color.B)),
            CornerRadius = new CornerRadius(4),
            Padding = new Thickness(6, 1, 6, 2),
            Child = new TextBlock
            {
                Text = label,
                FontSize = 12,
                Foreground = new SolidColorBrush(color),
            },
        };
        var time = new TextBlock
        {
            Text = notice.At.ToLocalTime().ToString("M月d日 HH:mm"),
            Foreground = Brush("Muted"),
            FontSize = 12,
            VerticalAlignment = VerticalAlignment.Center,
        };
        var head = new DockPanel { Margin = new Thickness(0, 0, 0, 8) };
        DockPanel.SetDock(time, Dock.Right);
        head.Children.Add(time);
        var left = new StackPanel { Orientation = Orientation.Horizontal };
        left.Children.Add(tag);
        if (!notice.Acknowledged)
            left.Children.Add(
                new TextBlock
                {
                    Text = "● 未读",
                    FontSize = 12,
                    Foreground = Brush("Primary"),
                    Margin = new Thickness(8, 1, 0, 0),
                }
            );
        head.Children.Add(left);

        var body = new StackPanel();
        body.Children.Add(head);
        body.Children.Add(
            new TextBlock
            {
                Text = text,
                TextWrapping = TextWrapping.Wrap,
                LineHeight = 20,
            }
        );
        if (!notice.Acknowledged)
        {
            var read = new Button
            {
                Content = "标为已读",
                Style = Styled("Link"),
                FontSize = 12,
                HorizontalAlignment = System.Windows.HorizontalAlignment.Right,
                Margin = new Thickness(0, 8, 0, 0),
            };
            read.Click += async (_, _) =>
            {
                read.IsEnabled = false;
                await acknowledge(notice.Id);
                await refresh();
            };
            body.Children.Add(read);
        }
        var card = new Border { Style = Styled("Card"), Child = body };
        if (notice.Acknowledged)
            card.Opacity = 0.65;
        else
            card.BorderBrush = new SolidColorBrush(Color.FromArgb(0x66, color.R, color.G, color.B));
        return card;
    }

    private UIElement State(string icon, string heading, string detail, UIElement? action)
    {
        var panel = new StackPanel
        {
            HorizontalAlignment = System.Windows.HorizontalAlignment.Center,
            Margin = new Thickness(24, 72, 24, 24),
            MaxWidth = 320,
        };
        panel.Children.Add(
            new Image
            {
                Source = Icons.Image(icon, 64),
                Width = 56,
                Height = 56,
            }
        );
        panel.Children.Add(
            new TextBlock
            {
                Text = heading,
                FontSize = 15,
                FontWeight = FontWeights.SemiBold,
                HorizontalAlignment = System.Windows.HorizontalAlignment.Center,
                Margin = new Thickness(0, 16, 0, 6),
            }
        );
        panel.Children.Add(
            new TextBlock
            {
                Text = detail,
                Foreground = Brush("Muted"),
                TextWrapping = TextWrapping.Wrap,
                TextAlignment = TextAlignment.Center,
                LineHeight = 20,
            }
        );
        if (action is FrameworkElement element)
        {
            element.HorizontalAlignment = System.Windows.HorizontalAlignment.Center;
            element.Margin = new Thickness(0, 16, 0, 0);
            panel.Children.Add(element);
        }
        return panel;
    }

    private static Style Styled(string key) => (Style)System.Windows.Application.Current.FindResource(key);

    private static Brush Brush(string key) => (Brush)System.Windows.Application.Current.FindResource(key);
}
