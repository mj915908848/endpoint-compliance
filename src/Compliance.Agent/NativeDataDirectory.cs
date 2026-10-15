using System.Security.AccessControl;
using System.Security.Principal;

namespace Compliance.Agent;

public static class NativeDataDirectory
{
    /// <summary>
    /// Creates the data directory readable only by SYSTEM and Administrators, or checks an existing one. Access
    /// granted to anyone else (Explorer's "permanently get access" prompt adds the signed-in user) is removed and
    /// reported by returning true; only an administrator can change these permissions in the first place.
    /// </summary>
    /// <remarks>
    /// The directory and its files are also given to Administrators: an owner can always rewrite permissions, and
    /// standard users may create folders under ProgramData. Files the enrolling administrator or an earlier version
    /// created belong to that account, so a new owner alone is not reported; access it granted would be.
    /// </remarks>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static bool EnsureSecure(string path)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException();
        var full = Path.GetFullPath(path);
        for (var parent = new DirectoryInfo(full); parent is not null; parent = parent.Parent)
            if (parent.Exists && parent.Attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new UnauthorizedAccessException("Agent data path cannot include a reparse point");
        var directory = new DirectoryInfo(full);
        if (!directory.Exists)
            directory.Create(Protected());
        foreach (var file in directory.EnumerateFiles())
            if (file.Attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new UnauthorizedAccessException("Agent data file cannot be a reparse point");
        if (!TrustedOwner(directory.GetAccessControl(AccessControlSections.Owner)))
            directory.SetAccessControl(OwnedByAdministrators(new DirectorySecurity()));
        foreach (var file in directory.EnumerateFiles())
            if (!TrustedOwner(file.GetAccessControl(AccessControlSections.Owner)))
                file.SetAccessControl(OwnedByAdministrators(new FileSecurity()));
        if (Secure(directory))
            return false;
        directory.SetAccessControl(Protected());
        foreach (var file in directory.EnumerateFiles())
        {
            // No rules of its own: the file inherits the directory's.
            var inherit = new FileSecurity();
            inherit.SetAccessRuleProtection(false, false);
            file.SetAccessControl(inherit);
        }
        if (!Secure(directory))
            throw new UnauthorizedAccessException(
                "Agent data ACL permits an untrusted principal and could not be repaired"
            );
        return true;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static DirectorySecurity Protected()
    {
        var security = OwnedByAdministrators(new DirectorySecurity());
        security.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            security.AddAccessRule(
                new FileSystemAccessRule(
                    new SecurityIdentifier(sid, null),
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow
                )
            );
        return security;
    }

    /// <summary>Only the owner is set, so applying it leaves the object's access rules as they are.</summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static T OwnedByAdministrators<T>(T security)
        where T : FileSystemSecurity
    {
        security.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        return security;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static bool Secure(DirectoryInfo directory)
    {
        var acl = directory.GetAccessControl();
        return acl.AreAccessRulesProtected
            && TrustedOwner(acl)
            && Trusted(acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            && directory
                .EnumerateFiles()
                .Select(f => f.GetAccessControl())
                .All(f => TrustedOwner(f) && Trusted(f.GetAccessRules(true, true, typeof(SecurityIdentifier))));
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static bool TrustedOwner(FileSystemSecurity security) =>
        security.GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier owner
        && (
            owner.IsWellKnown(WellKnownSidType.LocalSystemSid)
            || owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)
        );

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static bool Trusted(AuthorizationRuleCollection rules)
    {
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        foreach (AuthorizationRule entry in rules)
            if (
                entry is FileSystemAccessRule rule
                && rule.AccessControlType == AccessControlType.Allow
                && !Equals(rule.IdentityReference, system)
                && !Equals(rule.IdentityReference, administrators)
            )
                return false;
        return true;
    }

    /// <summary>The service log's folder next to the data directory: C:\ProgramData\ComplianceAgentLogs.</summary>
    public static string LogDirectory(string dataDirectory) =>
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(dataDirectory)) + "Logs";

    /// <summary>
    /// Creates the log folder, which everyone may read but only SYSTEM and Administrators may change, and moves the
    /// log of earlier versions out of the data directory, so nobody opens the data directory to read it. A folder that
    /// is not exactly so (a user may create it first under ProgramData, or plant a link the service would write
    /// through) is deleted and created again: it only holds logs.
    /// </summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static string EnsureLogs(string dataDirectory)
    {
        var logs = new DirectoryInfo(LogDirectory(dataDirectory));
        if (logs.Exists && !LogsSecure(logs))
        {
            // Removes a junction itself, without following it.
            logs.Delete(true);
            logs.Refresh();
        }
        if (!logs.Exists)
            logs.Create(LogSecurity());
        foreach (var name in new[] { "agent.log.1", "agent.log" })
        {
            var earlier = Path.Combine(dataDirectory, name);
            if (!File.Exists(earlier))
                continue;
            // Copied rather than moved, so the file takes the log folder's permissions.
            var target = Path.Combine(logs.FullName, name);
            if (!File.Exists(target))
                File.Copy(earlier, target);
            File.Delete(earlier);
        }
        return logs.FullName;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static DirectorySecurity LogSecurity()
    {
        var security = Protected();
        security.AddAccessRule(
            new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                FileSystemRights.ReadAndExecute,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow
            )
        );
        return security;
    }

    private const FileSystemRights Changes =
        FileSystemRights.Write
        | FileSystemRights.Delete
        | FileSystemRights.DeleteSubdirectoriesAndFiles
        | FileSystemRights.ChangePermissions
        | FileSystemRights.TakeOwnership;

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static bool LogsSecure(DirectoryInfo logs)
    {
        if (logs.Attributes.HasFlag(FileAttributes.ReparsePoint))
            return false;
        var acl = logs.GetAccessControl();
        if (!acl.AreAccessRulesProtected || !TrustedOwner(acl))
            return false;
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (
                rule.AccessControlType == AccessControlType.Allow
                && !Equals(rule.IdentityReference, system)
                && !Equals(rule.IdentityReference, administrators)
                && (rule.FileSystemRights & Changes) != 0
            )
                return false;
        return logs.EnumerateFileSystemInfos()
            .All(f => f is FileInfo && !f.Attributes.HasFlag(FileAttributes.ReparsePoint));
    }
}
