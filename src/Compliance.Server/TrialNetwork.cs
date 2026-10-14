using System.Net;
using System.Net.Sockets;

namespace Compliance.Server;

public static class TrialNetwork
{
    public static bool IsPrivateOrLoopback(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();
        if (address.AddressFamily != AddressFamily.InterNetwork)
            return IPAddress.IsLoopback(address);
        var b = address.GetAddressBytes();
        return b[0] == 127 || b[0] == 10 || b[0] == 172 && b[1] >= 16 && b[1] <= 31 || b[0] == 192 && b[1] == 168;
    }

    public static bool IsAllowedListener(string url, bool lanEnabled)
    {
        if (
            !Uri.TryCreate(url, UriKind.Absolute, out var uri)
            || uri.Scheme != Uri.UriSchemeHttp
            || uri.AbsolutePath != "/"
            || uri.Query.Length != 0
            || uri.Fragment.Length != 0
            || uri.UserInfo.Length != 0
        )
            return false;
        if (!IPAddress.TryParse(uri.Host, out var ip))
            return !lanEnabled && uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase);
        return lanEnabled ? IsPrivateOrLoopback(ip) : IPAddress.IsLoopback(ip);
    }
}
