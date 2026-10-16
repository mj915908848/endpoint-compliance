using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using Compliance.Core;

namespace Compliance.Agent;

/// <summary>Running processes of a product, confirmed as the process measure confirms them before ending one.</summary>
[SupportedOSPlatform("windows")]
internal sealed class ProcessesCollector : ICollector
{
    public string Module => "processes";

    public IEnumerable<CollectorScope> Scopes(ScanContext context) => [CollectorScope.Machine];

    public Task CollectAsync(ScanContext context, CollectorScope scope, List<Evidence> evidence, CancellationToken ct)
    {
        foreach (var p in new WindowsProcessTable().Running())
        {
            var confirmed = ProcessEnforcer.Confirmed(p, context.Policy);
            if (confirmed is not null)
            {
                evidence.Add(
                    new(
                        confirmed.Id,
                        confirmed.Name,
                        EvidenceKind.Process,
                        "pid:" + p.Pid,
                        "运行进程",
                        $"产品信息已核实，进程号 {p.Pid}",
                        null,
                        true
                    )
                );
                continue;
            }
            foreach (
                var rule in context.Policy.Products.Where(r =>
                    r.ExecutableNames.Any(x => string.Equals(x, p.Name, StringComparison.OrdinalIgnoreCase))
                )
            )
                evidence.Add(
                    new(
                        rule.Id,
                        rule.Name,
                        EvidenceKind.Clue,
                        "pid:" + p.Pid,
                        "运行进程",
                        $"仅文件名匹配，进程号 {p.Pid}",
                        null,
                        false
                    )
                );
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
