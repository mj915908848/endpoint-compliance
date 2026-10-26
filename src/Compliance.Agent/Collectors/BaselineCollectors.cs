using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Compliance.Core;
using Microsoft.Win32;

namespace Compliance.Agent;

/// <summary>A baseline requirement the device does not meet, before it becomes evidence.</summary>
/// <param name="Key">Tells findings of one check apart, e.g. the user or account; "" when there is only one.</param>
public sealed record BaselineFinding(string Key, string Summary, string? UserSid = null);

/// <summary>What Windows Security Center reports for a kind of protection.</summary>
public enum SecurityHealth
{
    Good = 0,
    NotMonitored = 1,
    Poor = 2,
    Snooze = 3,
}

/// <summary>One user's screen saver settings, policy values already taking precedence over the user's own.</summary>
/// <param name="TimeoutSeconds">ScreenSaveTimeOut; null when unset or unreadable.</param>
/// <param name="HasScreenSaver">A screen saver is chosen (SCRNSAVE.EXE); with "none" Windows never locks.</param>
public sealed record ScreenSaverSettings(
    string Sid,
    bool Active,
    bool Secure,
    int? TimeoutSeconds,
    bool HasScreenSaver
);

/// <summary>A member of the local Administrators group.</summary>
/// <param name="IsUser">A user account rather than a group, alias or SID Windows cannot resolve.</param>
public sealed record GroupMember(string Sid, string Name, bool IsUser);

/// <summary>Where SMBv1 can still run: the server driver (srv) and the client driver (mrxsmb10).</summary>
/// <param name="ServerStart">The srv driver's Start value; null when the driver is not installed.</param>
/// <param name="ServerSmb1">LanmanServer's SMB1 value; 0 turns the server side off.</param>
/// <param name="ClientStart">The mrxsmb10 driver's Start value; null when the driver is not installed.</param>
public sealed record Smb1State(int? ServerStart, int? ServerSmb1, int? ClientStart);

/// <summary>
/// Judges what the baseline collectors read. Kept apart from the Windows calls so every rule can be tested anywhere;
/// each returns the requirements not met, or throws <see cref="NotCoveredException"/> when the device cannot tell.
/// </summary>
public static class BaselineRules
{
    private const int Disabled = 4; // Service Start value

    public static IEnumerable<BaselineFinding> Antivirus(SecurityHealth? health, IReadOnlyList<string> products)
    {
        var named = products.Count > 0 ? $"（{string.Join("、", products)}）" : "";
        return health switch
        {
            SecurityHealth.Good => [],
            SecurityHealth.Poor or SecurityHealth.Snooze =>
            [
                new("", products.Count == 0 ? "未安装杀毒软件" : $"杀毒软件{named}未开启实时防护或病毒库已过期"),
            ],
            SecurityHealth.NotMonitored => throw new NotCoveredException("Windows 安全中心未监视杀毒软件状态"),
            _ => throw new NotCoveredException("无法读取 Windows 安全中心，可能是服务器版系统"),
        };
    }

    /// <param name="profiles">Each Windows Firewall profile and whether it is on; used when Security Center cannot tell.</param>
    public static IEnumerable<BaselineFinding> Firewall(
        SecurityHealth? health,
        IReadOnlyDictionary<string, bool?> profiles
    )
    {
        if (health == SecurityHealth.Good)
            return [];
        var off = profiles.Where(p => p.Value == false).Select(p => p.Key).ToArray();
        if (health is SecurityHealth.Poor or SecurityHealth.Snooze)
            return
            [
                new(
                    "",
                    off.Length > 0
                        ? $"Windows 防火墙的{string.Join("、", off)}网络已关闭"
                        : "Windows 安全中心报告防火墙未开启"
                ),
            ];
        // Without Security Center (Windows Server) all three Windows Firewall profiles must be on.
        if (off.Length > 0)
            return [new("", $"Windows 防火墙的{string.Join("、", off)}网络已关闭")];
        if (profiles.Count == 0 || profiles.Values.Any(v => v is null))
            throw new NotCoveredException("无法读取防火墙状态");
        return [];
    }

    public static IEnumerable<BaselineFinding> Updates(DateTimeOffset? lastInstalled, DateTimeOffset now, int days)
    {
        if (lastInstalled is not { } at)
            throw new NotCoveredException("未找到累积更新的安装记录");
        var age = (int)Math.Floor((now - at).TotalDays);
        return age > days
            ? [new("", $"最近一次安装累积更新是 {at.ToLocalTime():yyyy-MM-dd}，已有 {age} 天，超过 {days} 天")]
            : [];
    }

    /// <param name="protection">Win32_EncryptableVolume.ProtectionStatus: 0 off, 1 on, 2 unknown (locked).</param>
    /// <param name="conversion">ConversionStatus: 0 decrypted, 1 encrypted, 2 encrypting, 3 decrypting, 4/5 paused.</param>
    public static IEnumerable<BaselineFinding> BitLocker(string drive, int? protection, int? conversion)
    {
        if (protection == 1)
            return [];
        if (protection is null or 2)
            throw new NotCoveredException($"无法读取系统盘 {drive} 的 BitLocker 状态");
        return
        [
            new(
                "",
                conversion switch
                {
                    1 => $"系统盘 {drive} 已加密，但 BitLocker 保护已暂停",
                    2 or 4 => $"系统盘 {drive} 正在加密，尚未完成",
                    3 or 5 => $"系统盘 {drive} 正在解除加密",
                    _ => $"系统盘 {drive} 未开启 BitLocker 加密",
                }
            ),
        ];
    }

    /// <param name="machineSeconds">The machine's InactivityTimeoutSecs policy, which locks every user's session.</param>
    /// <param name="users">Users whose settings could be read: those with a loaded registry, i.e. signed in.</param>
    public static IEnumerable<BaselineFinding> ScreenLock(
        int? machineSeconds,
        IReadOnlyList<ScreenSaverSettings> users,
        int minutes
    )
    {
        var limit = minutes * 60;
        if (machineSeconds is > 0 && machineSeconds <= limit)
            return [];
        if (users.Count == 0)
            throw new NotCoveredException("没有已登录的用户，整机也未设置无操作锁定；用户登录后再检查");
        var findings = new List<BaselineFinding>();
        foreach (var u in users)
        {
            string? problem =
                !u.Active || !u.HasScreenSaver ? "未启用屏幕保护，无操作时不会锁屏"
                : !u.Secure ? "屏幕保护恢复时不要求密码"
                : u.TimeoutSeconds is not > 0 ? "屏幕保护的等待时间未设置"
                : u.TimeoutSeconds > limit
                    ? $"屏幕保护等待 {(u.TimeoutSeconds.Value + 59) / 60} 分钟，超过 {minutes} 分钟"
                : null;
            if (problem is not null)
                findings.Add(new(u.Sid, problem, u.Sid));
        }
        return findings;
    }

    /// <param name="disabled">Whether the account with RID 501 is disabled; null when the device has none.</param>
    public static IEnumerable<BaselineFinding> Guest(string? name, bool? disabled) =>
        disabled == false ? [new("", $"来宾账户 {name ?? "Guest"} 已启用")] : [];

    /// <summary>
    /// User accounts in the Administrators group other than the built-in Administrator (RID 500) and the accounts
    /// the rule allows, by full ("PC\it") or short ("it") name. Groups such as Domain Admins are left alone.
    /// </summary>
    public static IEnumerable<BaselineFinding> Admins(IEnumerable<GroupMember> members, IReadOnlyList<string> exempt)
    {
        bool Allowed(GroupMember m)
        {
            var shortName = m.Name[(m.Name.LastIndexOf('\\') + 1)..];
            return exempt.Any(x =>
                x.Equals(m.Name, StringComparison.OrdinalIgnoreCase)
                || x.Equals(shortName, StringComparison.OrdinalIgnoreCase)
            );
        }
        return members
            .Where(m => m.IsUser && !m.Sid.EndsWith("-500", StringComparison.Ordinal) && !Allowed(m))
            .Select(m => new BaselineFinding(m.Sid, $"账户 {m.Name} 是本地管理员组成员"));
    }

    /// <param name="policyDeny">fDenyTSConnections set by group policy, which wins over the local setting.</param>
    public static IEnumerable<BaselineFinding> Rdp(int? policyDeny, int? localDeny) =>
        (policyDeny ?? localDeny ?? 1) == 0
            ? [new("", policyDeny is null ? "远程桌面已开启" : "远程桌面已由组策略开启")]
            : [];

    public static IEnumerable<BaselineFinding> Smb1(Smb1State state)
    {
        var on = new List<string>();
        if (state.ServerStart is { } server && server != Disabled && state.ServerSmb1 != 0)
            on.Add("服务端");
        if (state.ClientStart is { } client && client != Disabled)
            on.Add("客户端");
        return on.Count > 0 ? [new("", $"SMBv1 {string.Join("和", on)}未关闭")] : [];
    }
}

/// <summary>
/// One security baseline check as a module of its own ("baseline:&lt;id&gt;"), run with full checks while the policy
/// enables it. Each check reads the machine; checks of users' settings name the user in their findings.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class BaselineCollector(string id, Func<ScanContext, BaselineRule, IEnumerable<BaselineFinding>> check)
    : ICollector
{
    public static readonly ICollector[] All =
    [
        new BaselineCollector("antivirus", (_, _) => BaselineRules.Antivirus(Wsc(AntivirusProvider), AntivirusNames())),
        new BaselineCollector("firewall", (_, _) => BaselineRules.Firewall(Wsc(FirewallProvider), FirewallProfiles())),
        new BaselineCollector(
            "updates",
            (_, rule) => BaselineRules.Updates(LastCumulativeUpdate(), DateTimeOffset.UtcNow, Baseline.Limit(rule))
        ),
        new BaselineCollector("bitlocker", (_, _) => BitLockerState()),
        new BaselineCollector(
            "screenlock",
            (context, rule) =>
                BaselineRules.ScreenLock(
                    Dword(
                        Registry.LocalMachine,
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                        "InactivityTimeoutSecs"
                    ),
                    context.Profiles.Where(p => p.HiveLoaded).Select(ScreenSaver).ToArray(),
                    Baseline.Limit(rule)
                )
        ),
        new BaselineCollector("guest", (_, _) => GuestState()),
        new BaselineCollector("admins", (_, rule) => BaselineRules.Admins(Administrators(), rule.Exempt)),
        new BaselineCollector(
            "rdp",
            (_, _) =>
                BaselineRules.Rdp(
                    Dword(
                        Registry.LocalMachine,
                        @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
                        "fDenyTSConnections"
                    ),
                    Dword(
                        Registry.LocalMachine,
                        @"SYSTEM\CurrentControlSet\Control\Terminal Server",
                        "fDenyTSConnections"
                    )
                )
        ),
        new BaselineCollector(
            "smb1",
            (_, _) =>
                BaselineRules.Smb1(
                    new(
                        Dword(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\srv", "Start"),
                        Dword(
                            Registry.LocalMachine,
                            @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                            "SMB1"
                        ),
                        Dword(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start")
                    )
                )
        ),
    ];

    public string Module => Baseline.Module(id);

    public bool Inventory => true;

    public IEnumerable<CollectorScope> Scopes(ScanContext context) => [CollectorScope.Machine];

    public Task CollectAsync(ScanContext context, CollectorScope scope, List<Evidence> evidence, CancellationToken ct)
    {
        var rule = Baseline.Rule(context.Policy, id) ?? new BaselineRule(id);
        foreach (var f in check(context, rule))
            evidence.Add(
                new(
                    id,
                    Baseline.Name(id),
                    EvidenceKind.Baseline,
                    "baseline:" + id + (f.Key.Length > 0 ? ":" + f.Key : ""),
                    "安全基线",
                    f.Summary,
                    f.UserSid,
                    true
                )
            );
        return Task.CompletedTask;
    }

    private static int? Dword(RegistryKey root, string path, string name)
    {
        using var key = root.OpenSubKey(path);
        return key?.GetValue(name) switch
        {
            int i => i,
            string s when int.TryParse(s, out var parsed) => parsed,
            _ => null,
        };
    }

    // WSC_SECURITY_PROVIDER values.
    private const int FirewallProvider = 0x1,
        AntivirusProvider = 0x4;

    [DllImport("wscapi.dll")]
    private static extern int WscGetSecurityProviderHealth(int providers, out int health);

    /// <summary>Security Center's health for a provider; null when it cannot be asked, as on Windows Server.</summary>
    private static SecurityHealth? Wsc(int provider)
    {
        try
        {
            return WscGetSecurityProviderHealth(provider, out var health) == 0 && Enum.IsDefined((SecurityHealth)health)
                ? (SecurityHealth)health
                : null;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return null;
        }
    }

    /// <summary>Names of the antivirus products Security Center knows, only to word the finding.</summary>
    private static string[] AntivirusNames()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"root\SecurityCenter2",
                "SELECT displayName FROM AntiVirusProduct"
            );
            return searcher
                .Get()
                .Cast<ManagementBaseObject>()
                .Select(o => o["displayName"] as string)
                .OfType<string>()
                .Where(n => n.Length > 0)
                .Distinct()
                .ToArray();
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    /// <summary>Each Windows Firewall profile and whether it is on; a group policy value wins over the local one.</summary>
    private static Dictionary<string, bool?> FirewallProfiles()
    {
        (string Label, string Policy, string Local)[] profiles =
        [
            ("域", "DomainProfile", "DomainProfile"),
            ("专用", "PrivateProfile", "StandardProfile"),
            ("公用", "PublicProfile", "PublicProfile"),
        ];
        return profiles.ToDictionary(
            p => p.Label,
            p =>
                (
                    Dword(
                        Registry.LocalMachine,
                        @"SOFTWARE\Policies\Microsoft\WindowsFirewall\" + p.Policy,
                        "EnableFirewall"
                    )
                    ?? Dword(
                        Registry.LocalMachine,
                        @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\" + p.Local,
                        "EnableFirewall"
                    )
                )
                    is { } v
                    ? v != 0
                    : (bool?)null
        );
    }

    /// <summary>
    /// When the newest installed cumulative update (a "RollupFix" servicing package) was installed. Windows Update's
    /// own last-success time also moves with every antivirus definition update, so it says little about patches.
    /// </summary>
    private static DateTimeOffset? LastCumulativeUpdate()
    {
        const int Installed = 0x70;
        using var packages = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages"
        );
        if (packages is null)
            return null;
        DateTimeOffset? newest = null;
        foreach (var name in packages.GetSubKeyNames())
        {
            if (!name.StartsWith("Package_for_RollupFix", StringComparison.OrdinalIgnoreCase))
                continue;
            using var package = packages.OpenSubKey(name);
            if (
                package?.GetValue("CurrentState") is not int state
                || state != Installed
                || package.GetValue("InstallTimeHigh") is not int high
                || package.GetValue("InstallTimeLow") is not int low
            )
                continue;
            var fileTime = ((long)(uint)high << 32) | (uint)low;
            if (fileTime <= 0)
                continue;
            var at = DateTimeOffset.FromFileTime(fileTime).ToUniversalTime();
            if (newest is null || at > newest)
                newest = at;
        }
        return newest;
    }

    private static IEnumerable<BaselineFinding> BitLockerState()
    {
        var drive = (Environment.GetEnvironmentVariable("SystemDrive") ?? "C:").TrimEnd('\\');
        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"root\CIMV2\Security\MicrosoftVolumeEncryption",
                "SELECT DriveLetter, ProtectionStatus, ConversionStatus FROM Win32_EncryptableVolume"
            );
            var volume = searcher
                .Get()
                .Cast<ManagementBaseObject>()
                .FirstOrDefault(v =>
                    string.Equals(v["DriveLetter"] as string, drive, StringComparison.OrdinalIgnoreCase)
                );
            if (volume is null)
                throw new NotCoveredException($"BitLocker 未列出系统盘 {drive}");
            static int? Number(object? value) => value is null ? null : Convert.ToInt32(value);
            return BaselineRules.BitLocker(
                drive,
                Number(volume["ProtectionStatus"]),
                Number(volume["ConversionStatus"])
            );
        }
        catch (ManagementException ex)
            when (ex.ErrorCode is ManagementStatus.InvalidNamespace or ManagementStatus.InvalidClass)
        {
            throw new NotCoveredException("此 Windows 版本不提供 BitLocker");
        }
    }

    /// <summary>A user's screen saver settings; values set by group policy win over the user's own.</summary>
    private static ScreenSaverSettings ScreenSaver(Profile profile)
    {
        using var policy = Registry.Users.OpenSubKey(
            profile.Sid + @"\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
        );
        using var own = Registry.Users.OpenSubKey(profile.Sid + @"\Control Panel\Desktop");
        string? Value(string name) => (policy?.GetValue(name) ?? own?.GetValue(name))?.ToString()?.Trim();
        return new(
            profile.Sid,
            Value("ScreenSaveActive") == "1",
            Value("ScreenSaverIsSecure") == "1",
            int.TryParse(Value("ScreenSaveTimeOut"), out var seconds) ? seconds : null,
            !string.IsNullOrEmpty(Value("SCRNSAVE.EXE"))
        );
    }

    private static IEnumerable<BaselineFinding> GuestState()
    {
        using var searcher = new ManagementObjectSearcher(
            "SELECT Name, SID, Disabled FROM Win32_UserAccount WHERE LocalAccount = TRUE"
        );
        var guest = searcher
            .Get()
            .Cast<ManagementBaseObject>()
            .FirstOrDefault(a => (a["SID"] as string)?.EndsWith("-501", StringComparison.Ordinal) == true);
        return BaselineRules.Guest(guest?["Name"] as string, guest?["Disabled"] as bool?);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LocalGroupMembersInfo2
    {
        public IntPtr Sid;
        public int SidUsage;
        public IntPtr DomainAndName;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupGetMembers(
        string? server,
        string group,
        int level,
        out IntPtr buffer,
        int preferredLength,
        out int read,
        out int total,
        IntPtr resume
    );

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);

    /// <summary>Members of the local Administrators group, found by its well-known SID since its name is localized.</summary>
    private static GroupMember[] Administrators()
    {
        const int SidTypeUser = 1;
        var group = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null)
            .Translate(typeof(NTAccount))
            .Value;
        group = group[(group.LastIndexOf('\\') + 1)..];
        var status = NetLocalGroupGetMembers(null, group, 2, out var buffer, -1, out var read, out _, IntPtr.Zero);
        try
        {
            if (status != 0)
                throw new IOException($"读取本地管理员组失败（错误 {status}）");
            var size = Marshal.SizeOf<LocalGroupMembersInfo2>();
            return Enumerable
                .Range(0, read)
                .Select(i => Marshal.PtrToStructure<LocalGroupMembersInfo2>(buffer + i * size))
                .Select(m =>
                {
                    var sid = new SecurityIdentifier(m.Sid).Value;
                    return new GroupMember(
                        sid,
                        Marshal.PtrToStringUni(m.DomainAndName) ?? sid,
                        m.SidUsage == SidTypeUser
                    );
                })
                .ToArray();
        }
        finally
        {
            if (buffer != IntPtr.Zero)
                NetApiBufferFree(buffer);
        }
    }
}
