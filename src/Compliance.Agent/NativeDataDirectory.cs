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
        // Created with its permissions in one step: between a plain create and setting them, a standard user could
        // open the directory and keep writing to it.
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

    /// <summary>
    /// Deletes a data directory someone other than SYSTEM or Administrators created, before the MSI first starts the
    /// service. Standard users may create folders under ProgramData, and one with an agent.json and identity key of
    /// their own would otherwise point the service, which runs as SYSTEM, at a server they chose; <see
    /// cref="EnsureSecure"/> takes such a folder over rather than refusing it. What the service or an earlier install
    /// left belongs to SYSTEM or Administrators and stays, so an upgrade keeps the device's enrollment. Links are
    /// removed, never followed. Returns whether the directory was deleted.
    /// </summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static bool RemoveIfForeign(string path)
    {
        var directory = new DirectoryInfo(Path.GetFullPath(path));
        if (!directory.Exists)
            return false;
        var items = new FileSystemInfo[] { directory }.Concat(directory.EnumerateFileSystemInfos());
        if (
            items.All(item =>
                !item.Attributes.HasFlag(FileAttributes.ReparsePoint)
                && TrustedOwner(
                    item is DirectoryInfo d
                        ? d.GetAccessControl(AccessControlSections.Owner)
                        : ((FileInfo)item).GetAccessControl(AccessControlSections.Owner)
                )
            )
        )
            return false;
        // Deleting a link removes the link itself; a recursive delete does not descend into links inside.
        directory.Delete(!directory.Attributes.HasFlag(FileAttributes.ReparsePoint));
        return true;
    }

    /// <summary>
    /// Run by the MSI as SYSTEM before the service first starts. Removes a directory someone else created (see
    /// <see cref="RemoveIfForeign"/>) and creates the data directory with its permissions, so no standard user can
    /// create one in the time until the service starts and <see cref="EnsureSecure"/> would take it over. Should someone
    /// create it again between the two steps, it is removed again. Returns whether a directory was removed.
    /// </summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static bool PrepareInstall(string path)
    {
        var directory = new DirectoryInfo(Path.GetFullPath(path));
        var removed = false;
        for (var attempt = 0; attempt < 3; attempt++)
        {
            removed |= RemoveIfForeign(directory.FullName);
            directory.Refresh();
            if (!directory.Exists)
                directory.Create(Protected());
            if (!RemoveIfForeign(directory.FullName))
                return removed;
            removed = true;
        }
        throw new UnauthorizedAccessException(
            $"{directory.FullName} keeps being created by someone other than SYSTEM or Administrators"
        );
    }

    /// <summary>
    /// Creates the logs folder inside the data directory, which every local user may read but not change, so the tray
    /// shows the log without asking for administrator rights. Its permissions are set on every start and are not
    /// inherited, so the data directory's stay as they are. Logs an earlier version wrote next to the key move here.
    /// </summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static string EnsureLogs(string dataDirectory)
    {
        var logs = new DirectoryInfo(Path.Combine(Path.GetFullPath(dataDirectory), "logs"));
        if (logs.Exists && logs.Attributes.HasFlag(FileAttributes.ReparsePoint))
            throw new UnauthorizedAccessException("Agent log folder cannot be a reparse point");
        logs.Create();
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
        logs.SetAccessControl(security);
        foreach (var name in new[] { "agent.log.1", "agent.log" })
        {
            var old = Path.Combine(dataDirectory, name);
            if (File.Exists(old))
                File.Move(old, Path.Combine(logs.FullName, name), true);
        }
        foreach (var file in logs.EnumerateFiles())
        {
            // A moved file keeps the rules it had; with none of its own it takes the folder's.
            var inherit = OwnedByAdministrators(new FileSecurity());
            inherit.SetAccessRuleProtection(false, false);
            file.SetAccessControl(inherit);
        }
        return logs.FullName;
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
}
