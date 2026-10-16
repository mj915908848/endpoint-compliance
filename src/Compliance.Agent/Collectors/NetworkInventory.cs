using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Compliance.Core;

namespace Compliance.Agent;

/// <summary>The device's physical network adapters, reported with each heartbeat so administrators see its IP and MAC.</summary>
public static partial class NetworkInventory
{
    /// <summary>What <see cref="Select"/> needs to know of one adapter.</summary>
    public sealed record Candidate(
        string Name,
        string Description,
        NetworkInterfaceType Type,
        OperationalStatus Status,
        byte[] Mac,
        IPAddress[] Addresses,
        bool HasGateway
    );

    public static NetworkAdapter[] Read()
    {
        try
        {
            return Select(
                NetworkInterface
                    .GetAllNetworkInterfaces()
                    .Select(nic =>
                    {
                        var ip = nic.GetIPProperties();
                        return new Candidate(
                            nic.Name,
                            nic.Description,
                            nic.NetworkInterfaceType,
                            nic.OperationalStatus,
                            nic.GetPhysicalAddress().GetAddressBytes(),
                            [.. ip.UnicastAddresses.Select(u => u.Address)],
                            ip.GatewayAddresses.Any(g =>
                                !g.Address.Equals(IPAddress.Any) && !g.Address.Equals(IPAddress.IPv6Any)
                            )
                        );
                    })
            );
        }
        catch (NetworkInformationException)
        {
            return [];
        }
    }

    /// <summary>
    /// Connected physical adapters with an address others can reach: no loopback, tunnels, or virtual switches of
    /// hypervisors and containers, and no link-local addresses. Adapters with a default gateway come first, IPv4
    /// before IPv6.
    /// </summary>
    public static NetworkAdapter[] Select(IEnumerable<Candidate> candidates) =>
        NetworkAdapters.Normalize(
            candidates
                .Where(c =>
                    c.Status == OperationalStatus.Up
                    && c.Type is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                    && c.Mac.Length == 6
                    && !Virtual().IsMatch(c.Name + " " + c.Description)
                )
                .Select(c => new NetworkAdapter(
                    c.Name,
                    Convert.ToHexString(c.Mac),
                    [
                        .. c
                            .Addresses.Where(Reachable)
                            .OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1)
                            .Select(NetworkAdapters.Address),
                    ],
                    c.HasGateway
                ))
                .Where(a => a.Addresses.Length > 0)
                .OrderByDescending(a => a.Primary)
                .ThenBy(a => a.Name, StringComparer.OrdinalIgnoreCase)
        );

    static bool Reachable(IPAddress a) =>
        !IPAddress.IsLoopback(a)
        && !a.IsIPv6LinkLocal
        && !(a.AddressFamily == AddressFamily.InterNetwork && a.GetAddressBytes() is [169, 254, ..]);

    [GeneratedRegex(
        @"(?i)virtual|hyper-v|vmware|virtualbox|vethernet|docker|wsl|tap-|tun\b|wintun|wireguard|npcap|loopback|bluetooth"
    )]
    private static partial Regex Virtual();
}
