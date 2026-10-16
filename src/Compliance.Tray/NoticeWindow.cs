using System.Drawing.Drawing2D;

namespace Compliance.Tray;

/// <summary>A notice from the service. Messages are stored as "Type: detail" (Violation, Reminder, Recovered, Blocked) or plain text.</summary>
public sealed record Notice(string Id, string Message, DateTimeOffset At, bool Acknowledged)
{
    public (string Label, Color Color, string Text) Parse()
    {
        foreach (
            var (prefix, label, color) in new[]
            {
                ("Violation: ", "需要处理", Color.FromArgb(0xF5, 0x3F, 0x3F)),
                ("Reminder: ", "仍未处理", Color.FromArgb(0xFF, 0x7D, 0x00)),
                ("Blocked: ", "已拦截", Color.FromArgb(0xF5, 0x3F, 0x3F)),
                ("Recovered: ", "已恢复", Color.FromArgb(0x00, 0xB4, 0x2A)),
            }
        )
            if (Message.StartsWith(prefix, StringComparison.Ordinal))
                return (label, color, Message[prefix.Length..]);
        return ("通知", Theme.Primary, Message);
    }
}

/// <summary>The notification center opened from the tray: what the administrator asked this user to know or fix.</summary>
public sealed class NoticeWindow : Form
{
    private readonly Label status;
    private readonly LinkLabel readAll;
    private readonly Panel list;
    private readonly Func<string, Task> acknowledge;
    private readonly Func<Task> refresh;
    private Notice[] shown = [];

    public NoticeWindow(Func<string, Task> acknowledge, Func<Task> refresh)
    {
        this.acknowledge = acknowledge;
        this.refresh = refresh;
        int S(int v) => LogicalToDeviceUnits(v);
        Text = "终端合规";
        Icon = Icons.Window(Icons.App);
        Font = Theme.Body;
        ForeColor = Theme.Text;
        BackColor = Theme.Page;
        Size = new Size(S(460), S(580));
        MinimumSize = new Size(S(380), S(360));
        StartPosition = FormStartPosition.Manual;
        var area = Screen.PrimaryScreen?.WorkingArea ?? SystemInformation.WorkingArea;
        Location = new Point(area.Right - Width - S(16), area.Bottom - Height - S(16));

        readAll = Theme.Link("全部标为已读");
        readAll.LinkClicked += async (_, _) =>
        {
            readAll.Enabled = false;
            foreach (var notice in shown.Where(n => !n.Acknowledged))
                await acknowledge(notice.Id);
            await refresh();
        };
        var header = new Theme.Bar(lineAtTop: false) { Dock = DockStyle.Top, Height = S(69) };
        var logo = new PictureBox
        {
            Image = Icons.Image(Icons.App, S(36)),
            SizeMode = PictureBoxSizeMode.Zoom,
            Bounds = new Rectangle(S(20), S(16), S(36), S(36)),
        };
        var title = Theme.Label("终端合规", Theme.Title, Theme.Text);
        title.Location = new Point(S(66), S(13));
        status = Theme.Label("", Theme.Small, Theme.Muted);
        status.Location = new Point(S(67), S(38));
        header.Controls.AddRange([logo, title, status, readAll]);
        header.Layout += (_, _) => readAll.Location = new Point(header.Width - readAll.Width - S(20), S(25));

        var log = Theme.Link("运行日志（需管理员）", Theme.Small);
        log.LinkClicked += (_, _) => LogWindow.OpenElevated();
        var footer = new Theme.Bar(lineAtTop: true) { Dock = DockStyle.Bottom, Height = S(41) };
        var note = Theme.Label("检查在后台自动进行，不读取文件内容", Theme.Small, Theme.Muted);
        note.Location = new Point(S(20), S(12));
        footer.Controls.AddRange([note, log]);
        footer.Layout += (_, _) => log.Location = new Point(footer.Width - log.Width - S(20), S(12));

        list = new Panel { Dock = DockStyle.Fill, AutoScroll = true };
        list.Resize += (_, _) => Arrange();

        Controls.AddRange([list, footer, header]);
        ShowLoading();
    }

    private void ShowLoading()
    {
        status.Text = "正在连接客户端服务…";
        status.ForeColor = Theme.Muted;
        readAll.Visible = false;
    }

    public void ShowNotices(Notice[] notices)
    {
        shown = notices;
        var unread = notices.Count(n => !n.Acknowledged);
        status.Text = unread > 0 ? $"客户端运行正常 · {unread} 条未读" : "客户端运行正常";
        status.ForeColor = Theme.Muted;
        readAll.Visible = unread > 0;
        readAll.Enabled = true;
        if (notices.Length == 0)
        {
            Fill(
                new StateView(
                    Icons.App,
                    "暂无通知",
                    "本机目前没有需要你处理的事项。如有情况，会在这里和屏幕右下角提醒你。",
                    null
                )
            );
            return;
        }
        Fill(
            notices
                .OrderBy(n => n.Acknowledged)
                .ThenByDescending(n => n.At)
                .Select(n => new NoticeCard(n, Acknowledge))
                .ToArray()
        );
    }

    public void ShowDisconnected()
    {
        shown = [];
        status.Text = "未连接客户端服务";
        status.ForeColor = Theme.Danger;
        readAll.Visible = false;
        var retry = new Button
        {
            Text = "重试",
            FlatStyle = FlatStyle.Flat,
            BackColor = Theme.Primary,
            ForeColor = Color.White,
            AutoSize = true,
            Padding = new Padding(
                LogicalToDeviceUnits(12),
                LogicalToDeviceUnits(2),
                LogicalToDeviceUnits(12),
                LogicalToDeviceUnits(2)
            ),
            Cursor = Cursors.Hand,
            UseMnemonic = false,
        };
        retry.FlatAppearance.BorderSize = 0;
        retry.Click += async (_, _) =>
        {
            ShowLoading();
            await refresh();
        };
        Fill(
            new StateView(
                Icons.Offline,
                "暂时连不上客户端服务",
                "客户端服务可能正在启动或已停止，托盘会每 20 秒自动重试。如果一直出现，请联系 IT 管理员。",
                retry
            )
        );
    }

    private async Task Acknowledge(string id)
    {
        await acknowledge(id);
        await refresh();
    }

    private void Fill(params Control[] items)
    {
        list.SuspendLayout();
        var old = list.Controls.Cast<Control>().ToArray();
        list.Controls.Clear();
        foreach (var control in old)
            control.Dispose();
        list.Controls.AddRange(items);
        list.ResumeLayout();
        Arrange();
    }

    /// <summary>Stacks the cards at the list's width, leaving room for the scroll bar once they overflow.</summary>
    private void Arrange()
    {
        int S(int v) => LogicalToDeviceUnits(v);
        var items = list.Controls.Cast<IMeasured>().ToArray();
        if (items.Length == 0)
            return;
        int Stack(int width, bool place)
        {
            var y = S(12);
            foreach (var item in items)
            {
                var height = item.Measure(width);
                if (place)
                    ((Control)item).Bounds = new Rectangle(
                        S(16) + list.AutoScrollPosition.X,
                        y + list.AutoScrollPosition.Y,
                        width,
                        height
                    );
                y += height + S(10);
            }
            return y;
        }
        var full = list.Width - S(32);
        var width = Stack(full, false) > list.Height ? full - SystemInformation.VerticalScrollBarWidth : full;
        list.SuspendLayout();
        Stack(Math.Max(width, S(100)), true);
        list.ResumeLayout();
    }

    private interface IMeasured
    {
        /// <summary>The height this item needs at <paramref name="width"/>; also lays out its own children.</summary>
        int Measure(int width);
    }

    private const TextFormatFlags Wrap =
        TextFormatFlags.WordBreak | TextFormatFlags.NoPrefix | TextFormatFlags.TextBoxControl;

    /// <summary>One notice: a colored tag, its time, the text and, while unread, a link to mark it read.</summary>
    private sealed class NoticeCard : Control, IMeasured
    {
        private readonly Notice notice;
        private readonly string label;
        private readonly Color color;
        private readonly string body;
        private readonly LinkLabel? read;

        public NoticeCard(Notice notice, Func<string, Task> acknowledge)
        {
            this.notice = notice;
            (label, color, body) = notice.Parse();
            SetStyle(
                ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw,
                true
            );
            BackColor = Theme.Page;
            if (!notice.Acknowledged)
            {
                read = Theme.Link("标为已读", Theme.Small);
                read.BackColor = Theme.Surface;
                read.LinkClicked += async (_, _) =>
                {
                    read.Enabled = false;
                    await acknowledge(notice.Id);
                };
                Controls.Add(read);
            }
        }

        private int S(int v) => LogicalToDeviceUnits(v);

        private int TextHeight(int width) =>
            TextRenderer.MeasureText(body, Theme.Body, new Size(width - S(28), int.MaxValue), Wrap).Height;

        public int Measure(int width)
        {
            var height = S(12) + S(22) + S(8) + TextHeight(width) + S(12);
            if (read is not null)
            {
                read.Size = read.PreferredSize;
                read.Location = new Point(width - S(14) - read.Width, height);
                height += read.Height + S(10);
            }
            return height;
        }

        /// <summary>Read notices are drawn faded, as if at 65% opacity.</summary>
        private Color Ink(Color c) => notice.Acknowledged ? Theme.Blend(c, Theme.Page, 0.65) : c;

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (var path = Theme.Rounded(new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f), S(8)))
            using (var fill = new SolidBrush(Ink(Theme.Surface)))
            using (var pen = new Pen(notice.Acknowledged ? Ink(Theme.Line) : Theme.Blend(color, Theme.Surface, 0.4)))
            {
                g.FillPath(fill, path);
                g.DrawPath(pen, path);
            }

            var x = S(14);
            var y = S(12);
            var tagText = TextRenderer.MeasureText(label, Theme.Small, Size.Empty, TextFormatFlags.NoPrefix);
            var tag = new Rectangle(x, y, tagText.Width + S(8), S(22));
            using (var path = Theme.Rounded(tag, S(4)))
            using (var fill = new SolidBrush(Ink(Theme.Blend(color, Theme.Surface, 0.12))))
                g.FillPath(fill, path);
            var center = TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix;
            TextRenderer.DrawText(g, label, Theme.Small, tag, Ink(color), center);
            if (!notice.Acknowledged)
                TextRenderer.DrawText(
                    g,
                    "● 未读",
                    Theme.Small,
                    new Rectangle(tag.Right + S(8), y, S(80), tag.Height),
                    Theme.Primary,
                    TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix
                );
            TextRenderer.DrawText(
                g,
                notice.At.ToLocalTime().ToString("M月d日 HH:mm"),
                Theme.Small,
                new Rectangle(x, y, Width - 2 * x, tag.Height),
                Ink(Theme.Muted),
                TextFormatFlags.Right | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix
            );
            y = tag.Bottom + S(8);
            TextRenderer.DrawText(
                g,
                body,
                Theme.Body,
                new Rectangle(x, y, Width - 2 * x, TextHeight(Width)),
                Ink(Theme.Text),
                Wrap
            );
        }
    }

    /// <summary>A centered icon, heading and explanation for an empty or disconnected list, with an optional action.</summary>
    private sealed class StateView : Control, IMeasured
    {
        private readonly Bitmap image;
        private readonly string heading;
        private readonly string detail;
        private readonly Control? action;

        public StateView(string icon, string heading, string detail, Control? action)
        {
            SetStyle(
                ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw,
                true
            );
            BackColor = Theme.Page;
            image = Icons.Image(icon, LogicalToDeviceUnits(56));
            this.heading = heading;
            this.detail = detail;
            this.action = action;
            if (action is not null)
                Controls.Add(action);
        }

        private int S(int v) => LogicalToDeviceUnits(v);

        private Rectangle Column(int width)
        {
            var column = Math.Min(width - S(32), S(320));
            return new Rectangle((width - column) / 2, S(60), column, 0);
        }

        private int HeadingHeight(int width) =>
            TextRenderer.MeasureText(heading, Theme.Heading, new Size(width, int.MaxValue), Wrap).Height;

        private int DetailHeight(int width) =>
            TextRenderer.MeasureText(detail, Theme.Body, new Size(width, int.MaxValue), Wrap).Height;

        public int Measure(int width)
        {
            var column = Column(width);
            var y = column.Top + S(56) + S(16) + HeadingHeight(column.Width) + S(6) + DetailHeight(column.Width);
            if (action is not null)
            {
                action.Location = new Point((width - action.Width) / 2, y + S(16));
                y = action.Bottom;
            }
            return y + S(24);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            var column = Column(Width);
            var size = S(56);
            g.InterpolationMode = InterpolationMode.HighQualityBicubic;
            g.DrawImage(image, new Rectangle((Width - size) / 2, column.Top, size, size));
            var y = column.Top + size + S(16);
            var center = Wrap | TextFormatFlags.HorizontalCenter;
            var headingHeight = HeadingHeight(column.Width);
            TextRenderer.DrawText(
                g,
                heading,
                Theme.Heading,
                new Rectangle(column.Left, y, column.Width, headingHeight),
                Theme.Text,
                center
            );
            y += headingHeight + S(6);
            TextRenderer.DrawText(
                g,
                detail,
                Theme.Body,
                new Rectangle(column.Left, y, column.Width, DetailHeight(column.Width)),
                Theme.Muted,
                center
            );
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                image.Dispose();
            base.Dispose(disposing);
        }
    }
}
