using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Compliance.Core;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace Compliance.Agent;

/// <summary>
/// A running program; <paramref name="ImagePath"/> is the full path of its executable when readable,
/// <paramref name="OriginalName"/> the file name its version information gives (kept when the file is renamed) and
/// <paramref name="Sha256"/> the hash of its contents, both read only when asked.
/// </summary>
public sealed record RunningProcess(
    int Pid,
    string Name,
    Func<string?> ProductName,
    Func<string?> UserSid,
    Func<string?>? ImagePath = null,
    Func<string?>? OriginalName = null,
    Func<string?>? Sha256 = null
);

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

    /// <summary>Executables whose name matched a product but could not be confirmed, each reported once.</summary>
    private readonly HashSet<string> skipped = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The product a process belongs to: an executable whose contents match an application rule's SHA-256, a
    /// Microsoft Store app running from its protected install folder whose package name the product lists, or an
    /// executable whose file name and product name both match. A renamed copy is matched by the original file name in
    /// its version information.
    /// </summary>
    public static ProductRule? Confirmed(RunningProcess process, PolicyDocument policy) =>
        Confirm(process, policy, out _);

    private static ProductRule? Confirm(RunningProcess process, PolicyDocument policy, out string? reason)
    {
        reason = null;
        if (
            policy.ApplicationRules.Length > 0
            && process.Sha256?.Invoke() is { } hash
            && policy.ApplicationRules.FirstOrDefault(r =>
                r.Type == "Exe" && string.Equals(r.Sha256, hash, StringComparison.OrdinalIgnoreCase)
            )
                is { } byHash
            && policy.Products.FirstOrDefault(p => p.Id == byHash.ProductId) is { } hashed
        )
            return hashed;
        var path = process.ImagePath?.Invoke();
        if (PackageName(path) is { } package)
        {
            var packaged = policy.Products.FirstOrDefault(r =>
                r.PackageIds.Any(x => string.Equals(x, package, StringComparison.OrdinalIgnoreCase))
            );
            if (packaged is not null)
                return packaged;
        }
        ProductRule[] Named(string? name) =>
            name is null
                ? []
                : policy
                    .Products.Where(r =>
                        r.ExecutableNames.Any(x => string.Equals(x, name, StringComparison.OrdinalIgnoreCase))
                    )
                    .ToArray();
        var candidates = Named(process.Name);
        // Copied under another name, the file still carries its original name; the product name must match as well.
        if (candidates.Length == 0 && policy.Products.Any(r => r.ExecutableNames.Length > 0))
            candidates = Named(process.OriginalName?.Invoke());
        if (candidates.Length == 0)
            return null;
        var product = process.ProductName();
        var rule = candidates.FirstOrDefault(r => ProductMatches(r, product));
        if (rule is null)
            reason = product is null
                ? $"{process.Name} 无法读取产品信息（{path ?? "路径不可读"}），未结束"
                : $"{process.Name} 的产品名为“{product}”，与策略中的 {candidates[0].Name} 不符（{path ?? "路径不可读"}），未结束";
        return rule;
    }

    /// <summary>"OpenAI.ChatGPT-Desktop" for a path under "\WindowsApps\OpenAI.ChatGPT-Desktop_1.0.0.0_x64__8wekyb3d8bbwe\".</summary>
    public static string? PackageName(string? path)
    {
        if (path is null)
            return null;
        var parts = path.Split('\\', '/');
        var at = Array.FindIndex(parts, p => string.Equals(p, "WindowsApps", StringComparison.OrdinalIgnoreCase));
        if (at < 0 || at + 2 >= parts.Length)
            return null;
        var folder = parts[at + 1];
        var end = folder.IndexOf('_');
        return end > 0 && folder.Contains("__", StringComparison.Ordinal) ? folder[..end] : null;
    }

    public static bool ProductMatches(ProductRule rule, string? product) =>
        string.Equals(product, rule.Name, StringComparison.OrdinalIgnoreCase)
        || rule.DisplayNames.Any(x => string.Equals(product, x, StringComparison.OrdinalIgnoreCase));

    /// <summary>Why matching executables were left running, once per executable and product name.</summary>
    public List<string> Skipped { get; } = [];

    /// <summary>Ends every confirmed forbidden process when the policy enforces this measure.</summary>
    public List<BlockedProcess> Sweep(PolicyDocument policy, DateTimeOffset now)
    {
        var blocked = new List<BlockedProcess>();
        if (!Controls.Enforced(policy, Controls.Process))
            return blocked;
        lastFailure = null;
        foreach (var process in table.Running())
        {
            // One process that cannot be inspected or ended must not shield the ones after it.
            try
            {
                var rule = Confirm(process, policy, out var reason);
                if (rule is null)
                {
                    if (reason is not null && skipped.Add(reason))
                        Skipped.Add(reason);
                    continue;
                }
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
            catch (Exception e) when (e is not OperationCanceledException)
            {
                lastFailure = $"{process.Name}（进程号 {process.Pid}）检查或结束时出错：{e.GetType().Name}";
            }
        }
        return blocked;
    }

    public ControlState State(PolicyDocument policy)
    {
        var watched = policy.Products.Count(p => p.ExecutableNames.Length > 0);
        if (watched == 0)
            return new(Controls.Process, policy.Serial, "Uncovered", "策略中没有填写程序文件名的产品，无可结束的进程");
        if (!table.CanTerminate)
            return new(Controls.Process, policy.Serial, "Uncovered", "客户端未以系统权限运行，无法结束其他用户的进程");
        if (!Controls.Enforced(policy, Controls.Process))
            return new(
                Controls.Process,
                policy.Serial,
                "Ready",
                $"可启用：客户端以系统权限运行，强制模式下会结束 {watched} 个产品的进程",
                true
            );
        if (lastFailure is not null)
            return new(Controls.Process, policy.Serial, "Error", lastFailure);
        var detail = lastEnded is { } last
            ? $"已生效：每 2 秒检查一次，已结束 {ended} 次，最近一次 {last.Name}（{last.At.ToLocalTime():MM-dd HH:mm}）"
            : "已生效：每 2 秒检查一次，尚未发现禁用程序运行";
        return new(Controls.Process, policy.Serial, "Applied", detail, true);
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
            return DurableFile.Exists(statePath)
                ? DurableFile.Read(statePath, Wire.Read<Dictionary<string, string[]>>) ?? []
                : [];
        }
        catch (Exception e) when (e is IOException or System.Text.Json.JsonException)
        {
            return [];
        }
    }

    private void Save(Dictionary<string, string[]> owned)
    {
        DurableFile.Write(statePath, Wire.Serialize(owned));
    }

    /// <summary>Writes the rules when the policy enforces this measure, otherwise removes the ones this agent added.</summary>
    public void Apply(PolicyDocument policy) =>
        Keep(Controls.Enforced(policy, Controls.Browser) ? EdgePolicyCompiler.Compile(policy.BlockDomains) : []);

    /// <summary>
    /// Removes the rules this agent added, for the MSI to run when the client is uninstalled; null when that worked.
    /// </summary>
    public string? RemoveOwn()
    {
        Keep([]);
        return lastError;
    }

    private void Keep(string[] wanted)
    {
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
                {
                    // Claimed before writing: if this or the next browser's write fails, the rules already written
                    // must not look like someone else's on the next attempt, or turning enforcement off would keep them.
                    owned[browser] = ours.Union(added, StringComparer.OrdinalIgnoreCase).ToArray();
                    Save(owned.Where(o => o.Value.Length > 0).ToDictionary());
                    store.Write(browser, values);
                }
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
            return new(Controls.Browser, policy.Serial, "Uncovered", "策略中没有禁止访问的域名");
        if (!store.CanWrite)
            return new(Controls.Browser, policy.Serial, "Uncovered", "客户端没有写入浏览器策略的权限");
        var wanted = EdgePolicyCompiler.Compile(policy.BlockDomains);
        var names = string.Join("、", store.Browsers);
        if (!Controls.Enforced(policy, Controls.Browser))
            return new(
                Controls.Browser,
                policy.Serial,
                "Ready",
                $"可启用：可写入 {names} 的网址拦截策略，强制模式下拦截 {wanted.Length} 条规则",
                true
            );
        if (lastError is not null)
            return new(Controls.Browser, policy.Serial, "Error", lastError);
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
                policy.Serial,
                "Applied",
                $"已生效：{names} 已写入 {wanted.Length} 条网址拦截规则并读回核对；浏览器自动加载，已打开的页面刷新后被拦截",
                true
            )
            : new(
                Controls.Browser,
                policy.Serial,
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
                string? path = null;
                var read = false;
                string? Path()
                {
                    if (!read)
                        (path, read) = (ImagePath(pid), true);
                    return path;
                }
                yield return new(
                    pid,
                    name,
                    () => Facts(Path(), true)?.ProductName,
                    () => Owner(pid),
                    Path,
                    () => Facts(Path())?.OriginalName,
                    () => Facts(Path())?.Sha256.Value
                );
            }
        }
    }

    sealed record FileFacts(string? ProductName, string? OriginalName, Lazy<string?> Sha256);

    // By path, size and time written, so a program running all day is read and hashed once, not every 2 seconds.
    readonly Dictionary<(string, long, DateTime), FileFacts> facts = [];

    static readonly string[] SystemFolders =
    [
        Environment.GetFolderPath(Environment.SpecialFolder.System) + System.IO.Path.DirectorySeparatorChar,
        Environment.GetFolderPath(Environment.SpecialFolder.SystemX86) + System.IO.Path.DirectorySeparatorChar,
        System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "WinSxS")
            + System.IO.Path.DirectorySeparatorChar,
    ];

    /// <summary>
    /// What the file says about itself beyond its name. Only the product name is read for programs in Windows' own
    /// folders, which users cannot write. Null when the file cannot be read.
    /// </summary>
    FileFacts? Facts(string? path, bool productOnly = false)
    {
        if (path is null)
            return null;
        var system = SystemFolders.Any(f => f.Length > 1 && path.StartsWith(f, StringComparison.OrdinalIgnoreCase));
        if (system && !productOnly)
            return null;
        try
        {
            var info = new FileInfo(path);
            var key = (path.ToUpperInvariant(), info.Length, info.LastWriteTimeUtc);
            if (facts.TryGetValue(key, out var known))
                return known;
            if (facts.Count >= 2000)
                facts.Clear();
            var version = FileVersionInfo.GetVersionInfo(path);
            return facts[key] = new(
                version.ProductName,
                system ? null : System.IO.Path.GetFileName(version.OriginalFilename),
                new(() => system ? null : Hash(path))
            );
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return null;
        }
    }

    static string? Hash(string path)
    {
        try
        {
            using var file = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete
            );
            return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(file));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// The executable's full path. Unlike Process.MainModule this needs only limited query access, so it also
    /// works for Microsoft Store apps and processes of other users.
    /// </summary>
    public static string? ImagePath(int pid)
    {
        const int InsufficientBuffer = 122;
        const uint QueryLimitedInformation = 0x1000;
        var process = OpenProcess(QueryLimitedInformation, false, pid);
        if (process == IntPtr.Zero)
            return null;
        // Runs for every process every 2 seconds: a pooled buffer, long enough for nearly every path, instead of a
        // fresh 64 KB one each time.
        var buffer = System.Buffers.ArrayPool<char>.Shared.Rent(1024);
        try
        {
            var size = buffer.Length;
            if (QueryFullProcessImageName(process, 0, buffer, ref size))
                return new string(buffer, 0, size);
            if (Marshal.GetLastWin32Error() != InsufficientBuffer)
                return null;
            var large = new char[32768];
            size = large.Length;
            return QueryFullProcessImageName(process, 0, large, ref size) ? new string(large, 0, size) : null;
        }
        finally
        {
            System.Buffers.ArrayPool<char>.Shared.Return(buffer);
            CloseHandle(process);
        }
    }

    public bool Kill(int pid)
    {
        Process p;
        try
        {
            p = Process.GetProcessById(pid);
        }
        catch (ArgumentException)
        {
            return true; // already exited
        }
        using (p)
        {
            try
            {
                p.Kill(entireProcessTree: true);
                return true;
            }
            catch (AggregateException)
            {
                // Some processes of the tree could not be ended; what counts is whether the program itself was.
                return Exited(p);
            }
            catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException)
            {
                return false;
            }
        }
    }

    private static bool Exited(Process p)
    {
        try
        {
            return p.WaitForExit(TimeSpan.FromSeconds(1));
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

    [DllImport(
        "kernel32.dll",
        SetLastError = true,
        CharSet = CharSet.Unicode,
        EntryPoint = "QueryFullProcessImageNameW"
    )]
    private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, char[] name, ref int size);

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
        if (key is null)
            return [];
        // Browsers read every numbered value, gaps included (another admin may have set 1, 2 and 4),
        // and Write renumbers from what is read here, so stopping at the first gap would drop entries.
        return key.GetValueNames()
            .Select(name => (Name: name, Index: int.TryParse(name, out var i) ? i : 0))
            .Where(v => v.Index > 0)
            .OrderBy(v => v.Index)
            .Select(v => key.GetValue(v.Name))
            .OfType<string>()
            .ToList();
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
