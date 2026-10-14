using System.Security.AccessControl;
using System.Security.Principal;

namespace Compliance.Agent;

public static class NativeDataDirectory
{
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static void EnsureSecure(string path)
    {
        if(!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var full=Path.GetFullPath(path);
        for(var parent=new DirectoryInfo(full);parent is not null;parent=parent.Parent)
            if(parent.Exists && parent.Attributes.HasFlag(FileAttributes.ReparsePoint)) throw new UnauthorizedAccessException("Agent data path cannot include a reparse point");
        var directory=new DirectoryInfo(full);
        if(!directory.Exists)
        {
            directory.Create();
            var security=new DirectorySecurity(); security.SetAccessRuleProtection(true,false);
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null),FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
            directory.SetAccessControl(security);
        }
        Verify(directory.GetAccessControl().GetAccessRules(true,true,typeof(SecurityIdentifier)),directory.GetAccessControl().AreAccessRulesProtected);
        foreach(var file in Directory.EnumerateFiles(full))
        {
            var info=new FileInfo(file);
            if(info.Attributes.HasFlag(FileAttributes.ReparsePoint)) throw new UnauthorizedAccessException("Agent data file cannot be a reparse point");
            Verify(info.GetAccessControl().GetAccessRules(true,true,typeof(SecurityIdentifier)),true);
        }
    }
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void Verify(AuthorizationRuleCollection rules,bool protectedDacl)
    {
        if(!protectedDacl) throw new UnauthorizedAccessException("Agent data directory inherits access rules");
        var system=new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null);
        var administrators=new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null);
        foreach(AuthorizationRule entry in rules)
            if(entry is FileSystemAccessRule rule && rule.AccessControlType==AccessControlType.Allow && !Equals(rule.IdentityReference,system) && !Equals(rule.IdentityReference,administrators))
                throw new UnauthorizedAccessException("Agent data ACL permits an untrusted principal");
    }
}
