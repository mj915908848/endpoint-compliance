using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Compliance.Core;
using Microsoft.Win32;

namespace Compliance.Agent;

/// <summary>
/// Proxy settings: each user's Internet Settings and persistent environment, plus the machine WinHTTP proxy
/// read through <c>WinHttpGetDefaultProxyConfiguration</c>. Addresses are never recorded.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class UserProxyCollector : ICollector
{
    public string Module => "proxy";

    public IEnumerable<CollectorScope> Scopes(ScanContext context) =>
        [.. CollectorScope.Users(context, needsHive: true), CollectorScope.Machine];

    public Task CollectAsync(ScanContext context, CollectorScope scope, List<Evidence> evidence, CancellationToken ct)
    {
        // Naming the program behind a loopback proxy is extra detail; without the socket table the proxy is
        // still reported, just without an owner.
        PortListener[] listeners;
        try
        {
            listeners = TcpListeners.Read();
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException)
        {
            listeners = [];
        }
        if (scope.Profile is { } p)
            ForUser(p.Sid, evidence, listeners, context.Policy);
        else
            WinHttp(evidence, listeners, context.Policy);
        return Task.CompletedTask;
    }

    private static void ForUser(string sid, List<Evidence> evidence, PortListener[] listeners, PolicyDocument policy)
    {
        using var settings =
            Registry.Users.OpenSubKey(sid + @"\Software\Microsoft\Windows\CurrentVersion\Internet Settings")
            ?? throw new IOException("User proxy registry key unreadable");
        var enabled = Convert.ToInt32(settings.GetValue("ProxyEnable") ?? 0) != 0;
        var server = settings.GetValue("ProxyServer") as string;
        var pac = settings.GetValue("AutoConfigURL") as string;
        if (enabled && !string.IsNullOrWhiteSpace(server))
            evidence.Add(
                new(
                    "proxy",
                    "系统代理",
                    EvidenceKind.Proxy,
                    "proxy:" + sid,
                    "用户代理设置",
                    WindowsCollector.ProxySummary("已启用代理服务器", server, listeners, policy),
                    sid
                )
            );
        if (!string.IsNullOrWhiteSpace(pac))
            evidence.Add(
                new(
                    "proxy",
                    "自动配置脚本（PAC）",
                    EvidenceKind.Proxy,
                    "pac:" + sid,
                    "用户代理设置",
                    "已设置自动配置脚本（不记录地址）",
                    sid
                )
            );
        using var env = Registry.Users.OpenSubKey(sid + @"\Environment");
        if (env is null)
            return;
        foreach (var name in env.GetValueNames())
        {
            var hit = WindowsCollector.ProxyEnvironmentEvidence(name, env.GetValue(name) as string, sid);
            if (hit is not null)
                evidence.Add(hit);
        }
    }

    private static void WinHttp(List<Evidence> evidence, PortListener[] listeners, PolicyDocument policy)
    {
        if (!WinHttpGetDefaultProxyConfiguration(out var info))
            throw new IOException("WinHTTP proxy inspection failed: " + Marshal.GetLastWin32Error());
        try
        {
            const int NoProxy = 1,
                NamedProxy = 3;
            if (info.AccessType == NamedProxy && info.Proxy != IntPtr.Zero)
                evidence.Add(
                    new(
                        "proxy",
                        "WinHTTP 代理",
                        EvidenceKind.Proxy,
                        "winhttp",
                        "WinHTTP",
                        WindowsCollector.ProxySummary(
                            "已设置 WinHTTP 代理",
                            Marshal.PtrToStringUni(info.Proxy),
                            listeners,
                            policy
                        ) + "，需核查是否属于例外"
                    )
                );
            else if (info.AccessType is not NoProxy and not NamedProxy)
                throw new IOException("Unsupported WinHTTP proxy mode: " + info.AccessType);
        }
        finally
        {
            if (info.Proxy != IntPtr.Zero)
                GlobalFree(info.Proxy);
            if (info.ProxyBypass != IntPtr.Zero)
                GlobalFree(info.ProxyBypass);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinHttpProxyInfo
    {
        public int AccessType;
        public IntPtr Proxy;
        public IntPtr ProxyBypass;
    }

    [DllImport("winhttp.dll", SetLastError = true)]
    private static extern bool WinHttpGetDefaultProxyConfiguration(out WinHttpProxyInfo info);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GlobalFree(IntPtr memory);
}

/// <summary>HTTP(S)_PROXY / ALL_PROXY in the machine environment and, as a clue only, in this process.</summary>
[SupportedOSPlatform("windows")]
internal sealed class ProxyEnvironmentCollector : ICollector
{
    public string Module => "proxy-env";

    public IEnumerable<CollectorScope> Scopes(ScanContext context) => [CollectorScope.Machine];

    public Task CollectAsync(ScanContext context, CollectorScope scope, List<Evidence> evidence, CancellationToken ct)
    {
        using var env =
            Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")
            ?? throw new IOException("Machine environment registry unreadable");
        foreach (var name in env.GetValueNames())
        {
            var hit = WindowsCollector.ProxyEnvironmentEvidence(name, env.GetValue(name) as string, null);
            if (hit is not null)
                evidence.Add(hit);
        }
        foreach (var name in new[] { "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY" })
        {
            var clue = WindowsCollector.ProcessProxyEnvironmentClue(name, Environment.GetEnvironmentVariable(name));
            if (clue is not null)
                evidence.Add(clue);
        }
        return Task.CompletedTask;
    }
}

/// <summary>
/// Machine-level proxy, PAC and auto-detect settings stored as WinINet connection settings: the machine-wide
/// copy used when "per-user proxy" is disabled by policy, and the LocalSystem copy that services and WinHTTP
/// automatic proxy use. Replaces the former <c>netsh winhttp show advproxy</c> call.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class SystemProxyCollector : ICollector
{
    private const string Connections = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";

    public string Module => "proxy-advanced";

    public IEnumerable<CollectorScope> Scopes(ScanContext context) => [CollectorScope.Machine];

    public Task CollectAsync(ScanContext context, CollectorScope scope, List<Evidence> evidence, CancellationToken ct)
    {
        foreach (
            var (root, path, label) in new[]
            {
                (Registry.LocalMachine, Connections, "整机连接设置"),
                (Registry.Users, @"S-1-5-18\" + Connections, "系统账户连接设置"),
            }
        )
        {
            using var key = root.OpenSubKey(path);
            if (key?.GetValue("DefaultConnectionSettings") is not byte[] blob)
                continue;
            var state = WindowsCollector.ParseConnectionSettings(blob);
            var objectKey = "connection-settings:" + (root == Registry.LocalMachine ? "machine" : "system");
            if (state.Proxy || state.Pac)
                evidence.Add(
                    new(
                        "proxy",
                        "系统级代理设置",
                        EvidenceKind.Proxy,
                        objectKey,
                        label,
                        state.Pac ? "已设置自动配置脚本（PAC，不记录地址）" : "已设置代理服务器（不记录地址）"
                    )
                );
            else if (state.AutoDetect)
                evidence.Add(
                    new(
                        "proxy-clue",
                        "代理自动检测",
                        EvidenceKind.Clue,
                        objectKey + ":autodetect",
                        label,
                        "已启用代理自动检测，但未发现具体代理配置",
                        null,
                        false
                    )
                );
        }
        return Task.CompletedTask;
    }
}
