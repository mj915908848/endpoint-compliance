using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using Compliance.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Win32;

namespace Compliance.Agent;

/// <summary>Why the service is stopping, as Windows told it.</summary>
public enum StopReason
{
    None,

    /// <summary>Someone stopped the service (services.msc, sc stop, an installer).</summary>
    Stopped,

    /// <summary>Windows is shutting down or restarting.</summary>
    Shutdown,
}

/// <summary>Something done to the client that it reports as a Tamper event.</summary>
public sealed record TamperFinding(string ObjectKey, string Detail);

/// <summary>What the guard reads and repairs about the client's own start-up; Windows in the service.</summary>
public interface ITamperSystem
{
    /// <summary>The service's start type (2 automatic, 3 manual, 4 disabled); null when it cannot be read.</summary>
    int? ServiceStartType();

    void SetServiceAutoStart();

    /// <summary>The tray's Run command the MSI wrote; null when this is not an MSI install.</summary>
    string? ExpectedTrayCommand();

    string? TrayCommand();

    void SetTrayCommand(string command);

    /// <summary>Turned off in Task Manager's start-up apps.</summary>
    bool TrayStartupDisabled();

    void EnableTrayStartup();
}

/// <summary>
/// Notices attempts to keep the client from running and undoes those it can: a service set to manual or disabled
/// is set back to automatic, and the tray's start at sign-in is restored. Each finding is reported to the server as a
/// Tamper event; one that keeps coming back is reported at most once an hour. Local administrators can still get
/// around all of it (design-v1 §11): this makes it visible, not impossible.
/// </summary>
public static class TamperGuard
{
    /// <summary>Set by the service lifetime when Windows asks the service to stop.</summary>
    public static volatile StopReason Stopping = StopReason.None;

    /// <summary>Written while the service runs, removed when it stops normally.</summary>
    public const string RunningMarker = "service-running";

    /// <summary>Notes another process (the uninstall check) leaves for the service to report.</summary>
    public const string NotesDirectory = "tamper-notes";

    /// <summary>Left by a successful uninstall password check for the uninstall report.</summary>
    public const string UninstallAuthorizedMarker = "uninstall-authorized";

    public static string StartTypeName(int? start) =>
        start switch
        {
            2 => "自动",
            3 => "手动",
            4 => "禁用",
            null => "无法读取",
            _ => start.Value.ToString(),
        };

    /// <summary>Repairs what it can and returns what it found.</summary>
    public static List<TamperFinding> Check(ITamperSystem system)
    {
        var found = new List<TamperFinding>();
        var start = system.ServiceStartType();
        if (start is not null and not 2)
            found.Add(
                new(
                    "tamper:service-start",
                    $"客户端服务的启动类型被改为“{StartTypeName(start)}”，"
                        + Repair(system.SetServiceAutoStart, "已恢复为自动启动")
                )
            );
        if (system.ExpectedTrayCommand() is { } expected)
        {
            if (!string.Equals(system.TrayCommand()?.Trim(), expected, StringComparison.OrdinalIgnoreCase))
                found.Add(
                    new(
                        "tamper:tray-autostart",
                        "托盘程序的登录自启动项被删除或改动，" + Repair(() => system.SetTrayCommand(expected), "已恢复")
                    )
                );
            if (system.TrayStartupDisabled())
                found.Add(
                    new(
                        "tamper:tray-autostart-disabled",
                        "托盘程序的登录自启动在任务管理器中被禁用，" + Repair(system.EnableTrayStartup, "已重新启用")
                    )
                );
        }
        return found;
    }

    static string Repair(Action repair, string done)
    {
        try
        {
            repair();
            return done;
        }
        catch (Exception e)
            when (e is UnauthorizedAccessException or IOException or Win32Exception or SecurityException)
        {
            return $"未能恢复（{e.GetType().Name}）";
        }
    }

    /// <summary>
    /// Records that the service runs since <paramref name="boot"/>; returns a finding when the marker from an earlier
    /// run in the same boot is still there, i.e. that run ended without stopping (ended in Task Manager, or crashed).
    /// A marker from an earlier boot only means the power went off.
    /// </summary>
    public static TamperFinding? MarkRunning(string dataDirectory, DateTimeOffset boot)
    {
        var path = Path.Combine(dataDirectory, RunningMarker);
        TamperFinding? found = null;
        try
        {
            if (
                File.Exists(path)
                && long.TryParse(File.ReadAllText(path).Trim(), out var ticks)
                && (new DateTimeOffset(ticks, TimeSpan.Zero) - boot).Duration() < TimeSpan.FromMinutes(2)
            )
                found = new(
                    "tamper:service-killed",
                    "客户端服务上次没有正常停止，可能被强制结束（例如在任务管理器中结束进程），已重新启动"
                );
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        File.WriteAllText(path, boot.UtcTicks.ToString());
        return found;
    }

    public static void ClearRunning(string dataDirectory)
    {
        try
        {
            File.Delete(Path.Combine(dataDirectory, RunningMarker));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>When this boot started, to the second or so.</summary>
    public static DateTimeOffset BootTime() =>
        DateTimeOffset.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);

    public static void LeaveNote(string dataDirectory, TamperFinding finding)
    {
        var dir = Path.Combine(dataDirectory, NotesDirectory);
        Directory.CreateDirectory(dir);
        File.WriteAllText(
            Path.Combine(dir, Guid.NewGuid().ToString("N") + ".txt"),
            finding.ObjectKey + "\n" + finding.Detail
        );
    }

    /// <summary>The notes left so far; each is deleted once <paramref name="report"/> took it.</summary>
    public static async Task TakeNotesAsync(string dataDirectory, Func<TamperFinding, Task> report)
    {
        var dir = Path.Combine(dataDirectory, NotesDirectory);
        if (!Directory.Exists(dir))
            return;
        foreach (var file in Directory.GetFiles(dir, "*.txt"))
        {
            var lines = (await File.ReadAllTextAsync(file)).Split('\n', 2);
            if (lines.Length == 2 && lines[0].StartsWith("tamper:", StringComparison.Ordinal))
                await report(new(lines[0], lines[1]));
            File.Delete(file);
        }
    }
}

/// <summary>
/// The uninstall password check the MSI runs before it removes the client (not when an upgrade replaces it). Without
/// an enrollment, a policy or a password the removal goes ahead.
/// </summary>
public static class UninstallCheck
{
    public static int Run(AgentConfiguration? config, string configPath, bool simulated, string? password)
    {
        if (config is not { DeviceId.Length: > 0, PolicyPublicKeyPem.Length: > 0 })
            return 0;
        var policy = new AgentRuntime(config, configPath, simulated, null).CachedPolicy();
        var stored = policy?.Tamper?.UninstallPassword ?? "";
        if (stored.Length == 0)
            return 0;
        if (UninstallPassword.Verify(stored, password))
        {
            File.WriteAllText(
                Path.Combine(config.DataDirectory, TamperGuard.UninstallAuthorizedMarker),
                DateTimeOffset.UtcNow.UtcTicks.ToString()
            );
            Console.WriteLine("卸载密码正确");
            return 0;
        }
        TamperGuard.LeaveNote(
            config.DataDirectory,
            new(
                "tamper:uninstall-refused",
                string.IsNullOrEmpty(password)
                    ? "有人尝试卸载客户端，因未提供卸载密码已阻止"
                    : "有人尝试卸载客户端，因卸载密码不正确已阻止"
            )
        );
        Console.Error.WriteLine("卸载需要管理员设置的卸载密码：msiexec /x 安装包 UNINSTALLPASSWORD=密码。");
        return 1;
    }

    /// <summary>Whether the password check passed during this removal, i.e. in the last hour.</summary>
    public static bool Authorized(string dataDirectory)
    {
        try
        {
            var path = Path.Combine(dataDirectory, TamperGuard.UninstallAuthorizedMarker);
            return File.Exists(path)
                && long.TryParse(File.ReadAllText(path).Trim(), out var ticks)
                && DateTimeOffset.UtcNow - new DateTimeOffset(ticks, TimeSpan.Zero) < TimeSpan.FromHours(1);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}

[SupportedOSPlatform("windows")]
public sealed class WindowsTamperSystem : ITamperSystem
{
    const string ServiceName = "ComplianceAgent";
    const string ServiceKey = @"SYSTEM\CurrentControlSet\Services\" + ServiceName;
    const string RunKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    const string ApprovedKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    const string RunValue = "ComplianceTray";

    public int? ServiceStartType() => Registry.LocalMachine.OpenSubKey(ServiceKey)?.GetValue("Start") as int?;

    public void SetServiceAutoStart()
    {
        // Through the service manager, which holds the setting in memory: the registry alone takes effect at reboot.
        var manager = OpenSCManager(null, null, 0x0001);
        if (manager == 0)
            throw new Win32Exception();
        try
        {
            var service = OpenService(manager, ServiceName, 0x0002);
            if (service == 0)
                throw new Win32Exception();
            try
            {
                const uint noChange = 0xFFFFFFFF;
                if (!ChangeServiceConfig(service, noChange, 2, noChange, null, null, 0, null, null, null, null))
                    throw new Win32Exception();
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    /// <summary>Only for MSI installs, which remember their folder; the earlier install scripts wrote no Run value.</summary>
    public string? ExpectedTrayCommand()
    {
        if (Registry.LocalMachine.OpenSubKey(@"SOFTWARE\ComplianceAgent")?.GetValue("InstallFolder") is not string dir)
            return null;
        var here = AppContext.BaseDirectory;
        if (!string.Equals(Path.GetFullPath(dir).TrimEnd('\\'), here.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
            return null;
        var tray = Path.Combine(here, "Compliance.Tray.exe");
        return File.Exists(tray) ? $"\"{tray}\"" : null;
    }

    public string? TrayCommand() => Registry.LocalMachine.OpenSubKey(RunKey)?.GetValue(RunValue) as string;

    public void SetTrayCommand(string command)
    {
        using var key = Registry.LocalMachine.CreateSubKey(RunKey);
        key.SetValue(RunValue, command, RegistryValueKind.String);
    }

    // Task Manager keeps 12 bytes per entry; an odd first byte means turned off.
    public bool TrayStartupDisabled() =>
        Registry.LocalMachine.OpenSubKey(ApprovedKey)?.GetValue(RunValue) is byte[] { Length: > 0 } state
        && (state[0] & 1) == 1;

    public void EnableTrayStartup()
    {
        using var key = Registry.LocalMachine.OpenSubKey(ApprovedKey, writable: true);
        key?.DeleteValue(RunValue, throwOnMissingValue: false);
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "OpenSCManagerW")]
    static extern nint OpenSCManager(string? machine, string? database, uint access);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "OpenServiceW")]
    static extern nint OpenService(nint manager, string name, uint access);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "ChangeServiceConfigW")]
    static extern bool ChangeServiceConfig(
        nint service,
        uint type,
        uint start,
        uint errorControl,
        string? binary,
        string? loadOrderGroup,
        nint tagId,
        string? dependencies,
        string? account,
        string? password,
        string? displayName
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CloseServiceHandle(nint handle);
}

/// <summary>Tells the agent why Windows stops the service, so a shutdown is not reported as someone stopping it.</summary>
[SupportedOSPlatform("windows")]
public sealed class AgentServiceLifetime(
    IHostEnvironment environment,
    IHostApplicationLifetime lifetime,
    ILoggerFactory loggerFactory,
    IOptions<HostOptions> options,
    IOptions<WindowsServiceLifetimeOptions> serviceOptions
) : WindowsServiceLifetime(environment, lifetime, loggerFactory, options, serviceOptions)
{
    protected override void OnStop()
    {
        if (TamperGuard.Stopping == StopReason.None)
            TamperGuard.Stopping = StopReason.Stopped;
        base.OnStop();
    }

    protected override void OnShutdown()
    {
        TamperGuard.Stopping = StopReason.Shutdown;
        base.OnShutdown();
    }
}
