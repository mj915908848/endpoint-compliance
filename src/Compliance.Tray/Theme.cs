using System.Drawing.Drawing2D;

namespace Compliance.Tray;

/// <summary>The colors and fonts the tray's windows share, matching the management UI.</summary>
public static class Theme
{
    public static readonly Color Page = Color.FromArgb(0xEE, 0xF1, 0xF6);
    public static readonly Color Surface = Color.White;
    public static readonly Color Line = Color.FromArgb(0xE6, 0xE9, 0xF0);
    public static readonly Color Text = Color.FromArgb(0x1F, 0x26, 0x33);
    public static readonly Color Muted = Color.FromArgb(0x86, 0x8E, 0x9C);
    public static readonly Color Primary = Color.FromArgb(0x24, 0x57, 0xE6);
    public static readonly Color Good = Color.FromArgb(0x1F, 0x9D, 0x55);
    public static readonly Color Warning = Color.FromArgb(0xE8, 0x89, 0x0C);
    public static readonly Color Danger = Color.FromArgb(0xE5, 0x48, 0x4D);

    private const string Family = "Microsoft YaHei UI";

    /// <summary>Sizes are in pixels at 96 DPI, as in the management UI; fonts in points scale with the display.</summary>
    public static readonly Font Body = Px(13);
    public static readonly Font Small = Px(12);
    public static readonly Font Title = Px(16, FontStyle.Bold);
    public static readonly Font Heading = Px(15, FontStyle.Bold);

    private static Font Px(float px, FontStyle style = FontStyle.Regular) => new(Family, px * 0.75f, style);

    /// <summary><paramref name="color"/> laid over <paramref name="background"/> at <paramref name="alpha"/>.</summary>
    public static Color Blend(Color color, Color background, double alpha) =>
        Color.FromArgb(
            (int)Math.Round(color.R * alpha + background.R * (1 - alpha)),
            (int)Math.Round(color.G * alpha + background.G * (1 - alpha)),
            (int)Math.Round(color.B * alpha + background.B * (1 - alpha))
        );

    public static GraphicsPath Rounded(RectangleF bounds, float radius)
    {
        var path = new GraphicsPath();
        var d = radius * 2;
        path.AddArc(bounds.Left, bounds.Top, d, d, 180, 90);
        path.AddArc(bounds.Right - d, bounds.Top, d, d, 270, 90);
        path.AddArc(bounds.Right - d, bounds.Bottom - d, d, d, 0, 90);
        path.AddArc(bounds.Left, bounds.Bottom - d, d, d, 90, 90);
        path.CloseFigure();
        return path;
    }

    /// <summary>A text-only button for secondary actions.</summary>
    public static LinkLabel Link(string text, Font? font = null) =>
        new()
        {
            Text = text,
            Font = font ?? Body,
            AutoSize = true,
            UseMnemonic = false,
            LinkColor = Primary,
            ActiveLinkColor = Primary,
            VisitedLinkColor = Primary,
            DisabledLinkColor = Muted,
            LinkBehavior = LinkBehavior.HoverUnderline,
            BackColor = Color.Transparent,
        };

    public static Label Label(string text, Font font, Color color) =>
        new()
        {
            Text = text,
            Font = font,
            ForeColor = color,
            AutoSize = true,
            UseMnemonic = false,
            BackColor = Color.Transparent,
        };

    /// <summary>A strip with a one-pixel line along one edge, for window headers and footers.</summary>
    public sealed class Bar : Panel
    {
        private readonly bool lineAtTop;

        public Bar(bool lineAtTop)
        {
            this.lineAtTop = lineAtTop;
            BackColor = Surface;
            DoubleBuffered = true;
            ResizeRedraw = true;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            using var pen = new Pen(Line);
            var y = lineAtTop ? 0 : Height - 1;
            e.Graphics.DrawLine(pen, 0, y, Width, y);
        }
    }
}
