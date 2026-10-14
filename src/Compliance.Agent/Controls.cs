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
                    "策略中没有按文件哈希定义的应用规则，未接管 AppLocker",
                    false
                )
            );
        else
            states.Add(
                new(
                    "application",
                    policy.Version,
                    "PendingManualApplication",
                    "已审核的 SHA-256 规则需先在 Windows 试点机上确认与 AppLocker/WDAC 兼容并安全合并",
                    false
                )
            );
        var patterns = EdgePolicyCompiler.Compile(policy.BlockDomains);
        if (!OperatingSystem.IsWindows())
            states.Add(new("edge", policy.Version, "Uncovered", "非 Windows 环境无法读取 Edge 策略", false));
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
                            ? "注册表中已存在拦截规则，但浏览器是否实际拦截尚未验证"
                            : "注册表中没有对应的 Edge 拦截规则，需要按审核流程部署",
                        false
                    )
                );
            }
            catch (Exception ex)
            {
                states.Add(new("edge", policy.Version, "Error", "读取 Edge 策略失败：" + ex.GetType().Name, false));
            }
        }
        states.Add(
            new(
                "network",
                policy.Version,
                "Uncovered",
                "未接入经批准的终端或网关网络拦截组件，其他程序的网络访问无法验证",
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
