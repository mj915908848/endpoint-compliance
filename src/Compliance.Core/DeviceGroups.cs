namespace Compliance.Core;

/// <summary>
/// Device groups, such as departments or sites: each device is in at most one, named by the administrator or by the
/// enrollment code it used. A policy can apply to groups instead of listing devices.
/// </summary>
public static class DeviceGroups
{
    public const int MaxLength = 64;
    public const int MaxPerPolicy = 100;

    /// <summary>The group name as stored, or why it cannot be one. Empty means no group.</summary>
    public static string Normalize(string? name)
    {
        var trimmed = (name ?? "").Trim();
        if (trimmed.Length > MaxLength || trimmed.Any(char.IsControl))
            throw new ArgumentException($"分组名称不能超过 {MaxLength} 个字符，也不能包含控制字符");
        return trimmed;
    }

    public static void ValidatePolicy(PolicyDocument doc)
    {
        if (doc.TargetGroups is null)
            throw new ArgumentException("策略不完整：缺少适用分组");
        if (
            doc.TargetGroups.Length > MaxPerPolicy
            || doc.TargetGroups.Any(g => g is null || g.Length == 0 || Normalize(g) != g)
            || doc.TargetGroups.Distinct(StringComparer.OrdinalIgnoreCase).Count() != doc.TargetGroups.Length
        )
            throw new ArgumentException($"适用分组无效：最多 {MaxPerPolicy} 个，名称不能为空或重复");
        if (doc.TargetGroups.Length > 0 && doc.TargetDeviceIds.Length > 0)
            throw new ArgumentException("一份策略只能按分组或按终端指定适用范围，不能同时使用");
        if (doc.TargetGroups.Length > 0 && doc.Mode == "Enforce")
            throw new ArgumentException("强制模式需要逐台指定试点终端，不能按分组");
    }

    public static bool Same(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
}
