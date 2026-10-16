using Compliance.Core;

namespace Compliance.Agent;

public static class EdgePolicyCompiler
{
    public static string[] Compile(IEnumerable<string> domains)
    {
        try
        {
            return DomainRules.CompileEdge(domains);
        }
        catch (ArgumentException e) when (e.Message.Contains("limit", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Edge URLBlocklist exceeds 1000 entries", e);
        }
    }
}

/// <summary>Control states where no measure can run (simulation, or not Windows).</summary>
public static class UnavailableControls
{
    public static ControlState[] For(PolicyDocument policy, string reason) =>
        [.. Controls.All.Select(id => new ControlState(id, policy.Serial, "Uncovered", reason))];
}
