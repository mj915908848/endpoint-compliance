using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace Compliance.Agent;

/// <summary>
/// Starts the tray in every signed-in session that has none. The installer closes the tray in all sessions before it
/// replaces the files, and a silent install (a remote upgrade) has no user to start it again, so without this the tray
/// stayed away until the next sign-in. The tray keeps one copy per session, so starting it where one runs is harmless.
/// Only for installs that start the tray at sign-in (the Run value the MSI writes); its command line is used as is.
/// </summary>
[SupportedOSPlatform("windows")]
public static class TrayLauncher
{
    const string RunKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    const string RunValue = "ComplianceTray";

    public static void StartInSignedInSessions()
    {
        if (Registry.LocalMachine.OpenSubKey(RunKey)?.GetValue(RunValue) is not string command)
            return;
        var exe = command.Trim().Trim('"');
        if (!File.Exists(exe))
            return;
        var running = Process
            .GetProcessesByName(Path.GetFileNameWithoutExtension(exe))
            .Select(p =>
            {
                using (p)
                    return p.SessionId;
            })
            .ToHashSet();
        foreach (var session in ActiveSessions())
        {
            if (running.Contains(session))
                continue;
            try
            {
                Start(session, exe);
                Console.WriteLine($"已在会话 {session} 中启动托盘");
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"无法在会话 {session} 中启动托盘：{e.Message}");
            }
        }
    }

    static List<int> ActiveSessions()
    {
        var sessions = new List<int>();
        if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var list, out var count))
            return sessions;
        try
        {
            var size = Marshal.SizeOf<WtsSessionInfo>();
            for (var i = 0; i < count; i++)
            {
                var info = Marshal.PtrToStructure<WtsSessionInfo>(list + i * size);
                if (info.State == WtsActive)
                    sessions.Add(info.SessionId);
            }
        }
        finally
        {
            WTSFreeMemory(list);
        }
        return sessions;
    }

    static void Start(int session, string exe)
    {
        if (!WTSQueryUserToken(session, out var token))
            throw new System.ComponentModel.Win32Exception();
        var environment = IntPtr.Zero;
        try
        {
            if (!CreateEnvironmentBlock(out environment, token, false))
                throw new System.ComponentModel.Win32Exception();
            var startup = new StartupInfo { cb = Marshal.SizeOf<StartupInfo>(), lpDesktop = @"winsta0\default" };
            if (
                !CreateProcessAsUser(
                    token,
                    null,
                    $"\"{exe}\"",
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    CreateUnicodeEnvironment,
                    environment,
                    Path.GetDirectoryName(exe),
                    ref startup,
                    out var process
                )
            )
                throw new System.ComponentModel.Win32Exception();
            CloseHandle(process.hProcess);
            CloseHandle(process.hThread);
        }
        finally
        {
            if (environment != IntPtr.Zero)
                DestroyEnvironmentBlock(environment);
            CloseHandle(token);
        }
    }

    const int WtsActive = 0;
    const uint CreateUnicodeEnvironment = 0x00000400;

    [StructLayout(LayoutKind.Sequential)]
    struct WtsSessionInfo
    {
        public int SessionId;
        public IntPtr WinStationName;
        public int State;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct StartupInfo
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX,
            dwY,
            dwXSize,
            dwYSize,
            dwXCountChars,
            dwYCountChars,
            dwFillAttribute,
            dwFlags;
        public short wShowWindow,
            cbReserved2;
        public IntPtr lpReserved2,
            hStdInput,
            hStdOutput,
            hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ProcessInformation
    {
        public IntPtr hProcess,
            hThread;
        public int dwProcessId,
            dwThreadId;
    }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    static extern bool WTSEnumerateSessions(
        IntPtr server,
        int reserved,
        int version,
        out IntPtr sessions,
        out int count
    );

    [DllImport("wtsapi32.dll")]
    static extern void WTSFreeMemory(IntPtr memory);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    static extern bool WTSQueryUserToken(int session, out IntPtr token);

    [DllImport("userenv.dll", SetLastError = true)]
    static extern bool CreateEnvironmentBlock(out IntPtr environment, IntPtr token, bool inherit);

    [DllImport("userenv.dll", SetLastError = true)]
    static extern bool DestroyEnvironmentBlock(IntPtr environment);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessAsUser(
        IntPtr token,
        string? application,
        string commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string? currentDirectory,
        ref StartupInfo startupInfo,
        out ProcessInformation processInformation
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);
}
