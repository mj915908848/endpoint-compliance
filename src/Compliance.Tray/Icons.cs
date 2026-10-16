using System.IO;

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
    public static Icon Tray(string name)
    {
        using var stream = Open(name);
        return new Icon(stream, SystemInformation.SmallIconSize);
    }

    /// <summary>All frames, for a window's title bar and taskbar button.</summary>
    public static Icon Window(string name)
    {
        using var stream = Open(name);
        return new Icon(stream);
    }

    /// <summary>The frame closest to <paramref name="size"/> pixels, for window headers.</summary>
    public static Bitmap Image(string name, int size)
    {
        using var stream = Open(name);
        using var icon = new Icon(stream, size, size);
        return icon.ToBitmap();
    }
}
