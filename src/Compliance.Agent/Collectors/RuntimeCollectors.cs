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

/// <summary>
/// Listening ports with their owning process, and tunnel adapters. These are clues only and never confirm a
/// violation; naming the process lets an administrator see which program holds a proxy port.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class PortsCollector : ICollector
{
    public string Module => "ports";
    public bool Inventory => false;

    public IEnumerable<CollectorScope> Scopes(ScanContext context) => [CollectorScope.Machine];

    public Task CollectAsync(ScanContext context, CollectorScope scope, List<Evidence> evidence, CancellationToken ct)
    {
        foreach (var listener in TcpListeners.Read())
        {
            var clue = WindowsCollector.PortEvidence(listener, context.Policy);
            if (clue is not null && evidence.All(e => e.ObjectKey != clue.ObjectKey))
                evidence.Add(clue);
        }
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            var clue = WindowsCollector.TunnelEvidence(
                nic.Id,
                nic.Name,
                nic.Description,
                nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel,
                context.Policy
            );
            if (clue is not null)
                evidence.Add(clue);
        }
        return Task.CompletedTask;
    }
}
