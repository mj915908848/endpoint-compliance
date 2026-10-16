using System.Net;
using System.Text.RegularExpressions;

namespace Compliance.Core;

public static partial class NetworkAdapters
{
    public const int MaxAdapters = 8;
    const int MaxAddresses = 8;

    /// <summary>
    /// Adapters as a device reported them, with what cannot be shown dropped: a hardware address that is not six
    /// bytes, or is all zeros, or an address that does not parse. Hardware addresses come out as AA-BB-CC-DD-EE-FF,
    /// IP addresses in their canonical form, the primary adapters first.
    /// </summary>
    public static NetworkAdapter[] Normalize(IEnumerable<NetworkAdapter?>? adapters)
    {
        var result = new List<NetworkAdapter>();
        foreach (var a in adapters ?? [])
        {
            if (a?.Mac is null || Mac(a.Mac) is not { } mac || result.Any(r => r.Mac == mac))
                continue;
            var addresses = (a.Addresses ?? [])
                .Select(x => IPAddress.TryParse(x, out var ip) ? Address(ip) : null)
                .OfType<string>()
                .Distinct()
                .Take(MaxAddresses)
                .ToArray();
            var name = EvidenceSanitizer.Clean(a.Name);
            result.Add(new(name.Length > 128 ? name[..128] : name, mac, addresses, a.Primary));
            if (result.Count == MaxAdapters)
                break;
        }
        return [.. result.OrderByDescending(a => a.Primary)];
    }

    /// <summary>AA-BB-CC-DD-EE-FF for a six-byte hardware address written with dashes, colons or no separator.</summary>
    public static string? Mac(string value)
    {
        var hex = Separators().Replace(value.Trim(), "").ToUpperInvariant();
        if (!HexMac().IsMatch(hex) || hex == "000000000000")
            return null;
        return string.Join("-", Enumerable.Range(0, 6).Select(i => hex.Substring(i * 2, 2)));
    }

    /// <summary>An address as people write it: IPv4 for IPv4-mapped IPv6, no scope id.</summary>
    public static string Address(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6)
            ip = ip.MapToIPv4();
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && ip.ScopeId != 0)
            ip = new IPAddress(ip.GetAddressBytes());
        return ip.ToString();
    }

    [GeneratedRegex("[-:.]")]
    private static partial Regex Separators();

    [GeneratedRegex("^[0-9A-F]{12}$")]
    private static partial Regex HexMac();
}
