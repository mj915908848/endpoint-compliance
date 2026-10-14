using System.Security.Cryptography;
using System.Text;
using Compliance.Core;
using Microsoft.Win32;

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

public static class WindowsControls
{
    public static ControlState[] Inspect(PolicyDocument policy)
    {
        var states = new List<ControlState>();
        var appRules = policy.ApplicationRules;
        if (appRules.Length == 0)
            states.Add(
                new(
                    "application",
                    policy.Version,
                    "Uncovered",
                    "No precise application hash rules; AppLocker not managed",
                    false
                )
            );
        else
            states.Add(
                new(
                    "application",
                    policy.Version,
                    "PendingManualApplication",
                    "Reviewed SHA-256 rules require AppLocker/WDAC compatibility and safe merge on a Windows pilot",
                    false
                )
            );
        var patterns = EdgePolicyCompiler.Compile(policy.BlockDomains);
        if (!OperatingSystem.IsWindows())
            states.Add(
                new(
                    "edge",
                    policy.Version,
                    "Uncovered",
                    "Native Edge policy cannot be inspected outside Windows",
                    false
                )
            );
        else
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Edge\URLBlocklist");
                var loaded = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                if (key is not null)
                    foreach (var valueName in key.GetValueNames())
                        if (key.GetValue(valueName) is string value)
                            loaded.Add(value);
                bool configured = patterns.Length > 0 && patterns.All(loaded.Contains);
                states.Add(
                    new(
                        "edge",
                        policy.Version,
                        configured ? "AppliedUnverified" : "PendingManualApplication",
                        configured
                            ? "Registry entries present; browser policy/actual block not verified"
                            : "Edge policy entries absent; requires reviewed application",
                        false
                    )
                );
            }
            catch (Exception ex)
            {
                states.Add(new("edge", policy.Version, "Error", "Edge readback failed: " + ex.GetType().Name, false));
            }
        }
        states.Add(
            new(
                "network",
                policy.Version,
                "Uncovered",
                "No approved endpoint/gateway network adapter; arbitrary API paths unverified",
                false
            )
        );
        return states.ToArray();
    }

    public static void WriteReviewArtifacts(PolicyDocument policy, string folder)
    {
        Directory.CreateDirectory(folder);
        var edge = EdgePolicyCompiler.Compile(policy.BlockDomains);
        File.WriteAllLines(Path.Combine(folder, "edge-urlblocklist.review.txt"), edge);
        var hashes = policy.ApplicationRules.Select(r => $"{r.ProductId}\t{r.Name}\t{r.Type}\t{r.Sha256}");
        foreach (var rule in policy.ApplicationRules)
            if (rule.Sha256.Length != 64 || !rule.Sha256.All(Uri.IsHexDigit))
                throw new InvalidOperationException("Application rule needs exact SHA-256");
        File.WriteAllLines(
            Path.Combine(folder, "applocker-hashes.review.tsv"),
            ["ProductId\tName\tType\tSHA256", .. hashes]
        );
        File.WriteAllText(
            Path.Combine(folder, "STATUS.txt"),
            "PendingManualApplication. "
                + "Review business allow rules, existing AppLocker/WDAC policy and recovery path on a Windows pilot. "
                + "These artifacts do not prove enforcement.\n"
        );
    }
}
