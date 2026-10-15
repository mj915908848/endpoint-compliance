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
        {
            directory.Create();
            directory.SetAccessControl(Protected());
        }
        foreach (var file in directory.EnumerateFiles())
            if (file.Attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new UnauthorizedAccessException("Agent data file cannot be a reparse point");
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
        var security = new DirectorySecurity();
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

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static bool Secure(DirectoryInfo directory)
    {
        var acl = directory.GetAccessControl();
        return acl.AreAccessRulesProtected
            && Trusted(acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            && directory
                .EnumerateFiles()
                .All(f => Trusted(f.GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier))));
    }

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
