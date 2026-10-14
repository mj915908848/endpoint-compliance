using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using Compliance.Core;

namespace Compliance.Agent;

/// <summary>Running processes whose executable name matches a product; confirmed only when the file's product name agrees.</summary>
[SupportedOSPlatform("windows")]
internal sealed class ProcessesCollector : ICollector
{
    public string Module => "processes";
    public bool Inventory => false;

    public IEnumerable<CollectorScope> Scopes(ScanContext context) => [CollectorScope.Machine];

    public Task CollectAsync(ScanContext context, CollectorScope scope, List<Evidence> evidence, CancellationToken ct)
    {
        foreach (var p in Process.GetProcesses())
        {
            using var _ = p;
            var name = p.ProcessName + ".exe";
            var candidates = context
                .Policy.Products.Where(r =>
                    r.ExecutableNames.Any(x => string.Equals(x, name, StringComparison.OrdinalIgnoreCase))
                )
                .ToArray();
            if (candidates.Length == 0)
                continue;
            string? product = null;
            try
            {
                product = FileVersionInfo.GetVersionInfo(p.MainModule!.FileName).ProductName;
            }
            catch
            {
                // Exited, protected or otherwise unreadable: it stays a filename clue.
            }
            foreach (var rule in candidates)
            {
                bool confirmed =
                    string.Equals(product, rule.Name, StringComparison.OrdinalIgnoreCase)
                    || rule.DisplayNames.Any(x => string.Equals(product, x, StringComparison.OrdinalIgnoreCase));
                evidence.Add(
                    new(
                        rule.Id,
                        rule.Name,
                        confirmed ? EvidenceKind.Process : EvidenceKind.Clue,
                        "pid:" + p.Id,
                        "运行进程",
                        confirmed ? $"产品信息已核实，进程号 {p.Id}" : $"仅文件名匹配，进程号 {p.Id}",
                        null,
                        confirmed
                    )
                );
            }
        }
        return Task.CompletedTask;
    }
}

/// <summary>Common local proxy ports and tunnel adapters. These are clues only and never confirm a violation.</summary>
[SupportedOSPlatform("windows")]
internal sealed class PortsCollector : ICollector
{
    private static readonly int[] ProxyPorts = [1080, 7890, 7897, 8080];

    public string Module => "ports";
    public bool Inventory => false;

    public IEnumerable<CollectorScope> Scopes(ScanContext context) => [CollectorScope.Machine];

    public Task CollectAsync(ScanContext context, CollectorScope scope, List<Evidence> evidence, CancellationToken ct)
    {
        foreach (
            var ep in IPGlobalProperties
                .GetIPGlobalProperties()
                .GetActiveTcpListeners()
                .Where(x => ProxyPorts.Contains(x.Port))
        )
            evidence.Add(
                new(
                    "port-clue",
                    "监听端口",
                    EvidenceKind.Clue,
                    "tcp:" + ep.Address + ":" + ep.Port,
                    "TCP",
                    $"本机正在监听常见代理端口 {ep.Port}，所属进程和用途未核实",
                    null,
                    false
                )
            );
        foreach (
            var nic in NetworkInterface
                .GetAllNetworkInterfaces()
                .Where(n =>
                    WindowsCollector.IsTunnelClue(
                        n.Name,
                        n.Description,
                        n.NetworkInterfaceType == NetworkInterfaceType.Tunnel
                    )
                )
        )
            evidence.Add(
                new(
                    "interface-clue",
                    "隧道网卡",
                    EvidenceKind.Clue,
                    "nic:" + nic.Id,
                    "网络接口",
                    $"发现隧道类网卡“{nic.Name}”（{nic.Description}），归属和用途未核实",
                    null,
                    false
                )
            );
        return Task.CompletedTask;
    }
}
