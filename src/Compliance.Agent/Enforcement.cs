using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Compliance.Core;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace Compliance.Agent;

public sealed record RunningProcess(int Pid, string Name, Func<string?> ProductName, Func<string?> UserSid);

public sealed record BlockedProcess(string ProductId, string ProductName, string Executable, int Pid, string? UserSid);

/// <summary>Where the process measure finds and ends processes; the Windows implementation uses the live process table.</summary>
public interface IProcessTable
{
    IEnumerable<RunningProcess> Running();

    /// <summary>Ends the process and its children; false when it could not be ended.</summary>
    bool Kill(int pid);

    /// <summary>Whether this agent may end other users' and services' processes (it runs as SYSTEM).</summary>
    bool CanTerminate { get; }
}

/// <summary>The browsers' URLBlocklist policy values, by browser name.</summary>
public interface IBlocklistStore
{
    IReadOnlyList<string> Browsers { get; }

    /// <summary>Values named 1..N in order; browsers stop reading at the first missing number.</summary>
    List<string> Read(string browser);

    void Write(string browser, IReadOnlyList<string> values);

    bool CanWrite { get; }
}

/// <summary>"发现即结束进程": ends running programs that the policy forbids, confirmed by the file's product name.</summary>
public sealed class ProcessEnforcer(IProcessTable table)
{
    private int ended;
    private string? lastFailure;
    private (string Name, DateTimeOffset At)? lastEnded;

    /// <summary>Products whose executable names and product name both match, as the processes check confirms them.</summary>
    public static ProductRule? Confirmed(RunningProcess process, PolicyDocument policy)
    {
        var candidates = policy
            .Products.Where(r =>
                r.ExecutableNames.Any(x => string.Equals(x, process.Name, StringComparison.OrdinalIgnoreCase))
            )
            .ToArray();
        if (candidates.Length == 0)
            return null;
        var product = process.ProductName();
        return candidates.FirstOrDefault(r => ProductMatches(r, product));
    }

    public static bool ProductMatches(ProductRule rule, string? product) =>
        string.Equals(product, rule.Name, StringComparison.OrdinalIgnoreCase)
        || rule.DisplayNames.Any(x => string.Equals(product, x, StringComparison.OrdinalIgnoreCase));

    /// <summary>Ends every confirmed forbidden process when the policy enforces this measure.</summary>
    public List<BlockedProcess> Sweep(PolicyDocument policy, DateTimeOffset now)
    {
        var blocked = new List<BlockedProcess>();
        if (!Controls.Enforced(policy, Controls.Process))
            return blocked;
        lastFailure = null;
        foreach (var process in table.Running())
        {
            var rule = Confirmed(process, policy);
            if (rule is null)
                continue;
            var sid = process.UserSid();
            if (table.Kill(process.Pid))
            {
                ended++;
                lastEnded = (rule.Name, now);
                blocked.Add(new(rule.Id, rule.Name, process.Name, process.Pid, sid));
            }
            else
                lastFailure = $"{process.Name}（进程号 {process.Pid}）无法结束";
        }
        return blocked;
    }

    public ControlState State(PolicyDocument policy)
    {
        var watched = policy.Products.Count(p => p.ExecutableNames.Length > 0);
        if (watched == 0)
            return new(Controls.Process, policy.Version, "Uncovered", "策略中没有填写程序文件名的产品，无可结束的进程");
        if (!table.CanTerminate)
            return new(Controls.Process, policy.Version, "Uncovered", "客户端未以系统权限运行，无法结束其他用户的进程");
        if (!Controls.Enforced(policy, Controls.Process))
            return new(
                Controls.Process,
                policy.Version,
                "Ready",
                $"可启用：客户端以系统权限运行，强制模式下会结束 {watched} 个产品的进程",
                true
            );
        if (lastFailure is not null)
            return new(Controls.Process, policy.Version, "Error", lastFailure);
        var detail = lastEnded is { } last
            ? $"已生效：每 2 秒检查一次，已结束 {ended} 次，最近一次 {last.Name}（{last.At.ToLocalTime():MM-dd HH:mm}）"
            : "已生效：每 2 秒检查一次，尚未发现禁用程序运行";
        return new(Controls.Process, policy.Version, "Applied", detail, true);
    }
}

/// <summary>
/// "浏览器网址拦截": keeps the policy's blocked domains in Edge's and Chrome's URLBlocklist and reads them back.
/// Entries written by others (group policy, Intune) are kept; this agent removes only what it added, which it
/// remembers in <paramref name="statePath"/>.
/// </summary>
public sealed class BrowserBlocklist(IBlocklistStore store, string statePath)
{
    private string? lastError;

    private Dictionary<string, string[]> Owned()
    {
        try
        {
            return File.Exists(statePath)
                ? Wire.Read<Dictionary<string, string[]>>(File.ReadAllText(statePath)) ?? []
                : [];
        }
        catch (Exception e) when (e is IOException or System.Text.Json.JsonException)
        {
            return [];
        }
    }

    private void Save(Dictionary<string, string[]> owned)
    {
        var temp = statePath + ".tmp";
        File.WriteAllText(temp, Wire.Serialize(owned));
        File.Move(temp, statePath, true);
    }

    /// <summary>Writes the rules when the policy enforces this measure, otherwise removes the ones this agent added.</summary>
    public void Apply(PolicyDocument policy)
    {
        var wanted = Controls.Enforced(policy, Controls.Browser) ? EdgePolicyCompiler.Compile(policy.BlockDomains) : [];
        var owned = Owned();
        if (wanted.Length == 0 && owned.Count == 0)
            return;
        lastError = null;
        try
        {
            foreach (var browser in store.Browsers)
            {
                var ours = owned.GetValueOrDefault(browser, []);
                var current = store.Read(browser);
                var others = current.Where(v => !ours.Contains(v, StringComparer.OrdinalIgnoreCase)).ToList();
                var added = wanted.Where(w => !others.Contains(w, StringComparer.OrdinalIgnoreCase)).ToArray();
                var values = others.Concat(added).ToList();
                if (values.Count > 1000)
                    throw new InvalidOperationException($"{browser} 的网址拦截规则超过 1000 条");
                if (!values.SequenceEqual(current))
                    store.Write(browser, values);
                owned[browser] = added;
            }
            Save(owned.Where(o => o.Value.Length > 0).ToDictionary());
        }
        catch (Exception e)
            when (e
                    is IOException
                        or UnauthorizedAccessException
                        or InvalidOperationException
                        or System.Security.SecurityException
            )
        {
            lastError = "写入浏览器策略失败：" + e.Message;
        }
    }

    public ControlState State(PolicyDocument policy)
    {
        if (policy.BlockDomains.Length == 0)
            return new(Controls.Browser, policy.Version, "Uncovered", "策略中没有禁止访问的域名");
        if (!store.CanWrite)
            return new(Controls.Browser, policy.Version, "Uncovered", "客户端没有写入浏览器策略的权限");
        var wanted = EdgePolicyCompiler.Compile(policy.BlockDomains);
        var names = string.Join("、", store.Browsers);
        if (!Controls.Enforced(policy, Controls.Browser))
            return new(
                Controls.Browser,
                policy.Version,
                "Ready",
                $"可启用：可写入 {names} 的网址拦截策略，强制模式下拦截 {wanted.Length} 条规则",
                true
            );
        if (lastError is not null)
            return new(Controls.Browser, policy.Version, "Error", lastError);
        var missing = store
            .Browsers.Where(b =>
            {
                var loaded = store.Read(b);
                return wanted.Any(w => !loaded.Contains(w, StringComparer.OrdinalIgnoreCase));
            })
            .ToArray();
        return missing.Length == 0
            ? new(
                Controls.Browser,
                policy.Version,
                "Applied",
                $"已生效：{names} 已写入 {wanted.Length} 条网址拦截规则并读回核对；浏览器自动加载，已打开的页面刷新后被拦截",
                true
            )
            : new(
                Controls.Browser,
                policy.Version,
                "Error",
                $"{string.Join("、", missing)} 的拦截规则读回不一致，可能被组策略覆盖，下次检查时重新写入"
            );
    }
}

[SupportedOSPlatform("windows")]
public sealed class WindowsProcessTable : IProcessTable
{
    public bool CanTerminate { get; } = WindowsIdentity.GetCurrent().IsSystem;

    public IEnumerable<RunningProcess> Running()
    {
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                if (p.Id is 0 or 4)
                    continue;
                var pid = p.Id;
                string name;
                try
                {
                    name = p.ProcessName + ".exe";
                }
                catch (InvalidOperationException)
                {
                    continue; // exited
                }
                yield return new(pid, name, () => ProductName(pid), () => Owner(pid));
            }
        }
    }

    public static string? ProductName(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return FileVersionInfo.GetVersionInfo(p.MainModule!.FileName).ProductName;
        }
        catch
        {
            // Exited, protected or otherwise unreadable: not confirmed, so never ended.
            return null;
        }
    }

    public bool Kill(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            p.Kill(entireProcessTree: true);
            return true;
        }
        catch (ArgumentException)
        {
            return true; // already exited
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return false;
        }
    }

    /// <summary>The SID of the account running the process, so the notice reaches that user's tray.</summary>
    public static string? Owner(int pid)
    {
        const uint QueryLimitedInformation = 0x1000;
        const uint TokenQuery = 0x0008;
        var process = OpenProcess(QueryLimitedInformation, false, pid);
        if (process == IntPtr.Zero)
            return null;
        try
        {
            if (!OpenProcessToken(process, TokenQuery, out var token))
                return null;
            using (token)
            using (var identity = new WindowsIdentity(token.DangerousGetHandle()))
                return identity.User?.Value;
        }
        catch (Exception e)
            when (e is UnauthorizedAccessException or ArgumentException or System.Security.SecurityException)
        {
            return null;
        }
        finally
        {
            CloseHandle(process);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);
}

[SupportedOSPlatform("windows")]
public sealed class WindowsBlocklistStore : IBlocklistStore
{
    private static readonly (string Name, string Key)[] Keys =
    [
        ("Edge", @"SOFTWARE\Policies\Microsoft\Edge\URLBlocklist"),
        ("Chrome", @"SOFTWARE\Policies\Google\Chrome\URLBlocklist"),
    ];

    public IReadOnlyList<string> Browsers { get; } = Keys.Select(k => k.Name).ToArray();

    private static string KeyOf(string browser) => Keys.First(k => k.Name == browser).Key;

    public List<string> Read(string browser)
    {
        using var key = Registry.LocalMachine.OpenSubKey(KeyOf(browser));
        var values = new List<string>();
        for (var i = 1; key?.GetValue(i.ToString()) is string value; i++)
            values.Add(value);
        return values;
    }

    public void Write(string browser, IReadOnlyList<string> values)
    {
        using var key = Registry.LocalMachine.CreateSubKey(KeyOf(browser), writable: true);
        // Browsers read only the numbered values; other names are left alone.
        foreach (var name in key.GetValueNames().Where(n => int.TryParse(n, out _)))
            key.DeleteValue(name, false);
        for (var i = 0; i < values.Count; i++)
            key.SetValue((i + 1).ToString(), values[i], RegistryValueKind.String);
    }

    public bool CanWrite
    {
        get
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies", writable: true);
                return key is not null;
            }
            catch (Exception e) when (e is UnauthorizedAccessException or System.Security.SecurityException)
            {
                return false;
            }
        }
    }
}
