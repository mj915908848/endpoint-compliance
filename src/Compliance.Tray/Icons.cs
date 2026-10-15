using System.IO;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace Compliance.Tray;

/// <summary>Icons drawn by scripts/make_tray_icons.py and embedded in the executable.</summary>
public static class Icons
{
    public const string App = "app.ico";
    public const string Alert = "tray-alert.ico";
    public const string Offline = "tray-offline.ico";

    private static Stream Open(string name) =>
        typeof(Icons).Assembly.GetManifestResourceStream("Compliance.Tray.Assets." + name)
        ?? throw new FileNotFoundException("Embedded icon missing", name);

    /// <summary>The notification-area icon at the size Windows uses there.</summary>
    public static System.Drawing.Icon Tray(string name)
    {
        using var stream = Open(name);
        return new System.Drawing.Icon(stream, System.Windows.Forms.SystemInformation.SmallIconSize);
    }

    /// <summary>The frame closest to <paramref name="size"/> pixels, for window titles and headers.</summary>
    public static ImageSource Image(string name, int size)
    {
        using var stream = Open(name);
        var decoder = new IconBitmapDecoder(stream, BitmapCreateOptions.None, BitmapCacheOption.OnLoad);
        return decoder.Frames.OrderBy(f => Math.Abs(f.PixelWidth - size)).ThenByDescending(f => f.PixelWidth).First();
    }
}
