namespace Compliance.Core;

/// <summary>The protection measures a policy can require. Ready means the device can apply it; Applied means it is in effect.</summary>
public static class Controls
{
    public const string Process = "process";
    public const string Browser = "browser";
    public const string Usb = "usb";
    public static readonly string[] All = [Process, Browser, Usb];

    /// <summary>Earlier policies named measures that were never implemented; they map onto the two real ones.</summary>
    public static string[] Normalize(IEnumerable<string>? ids) =>
        (ids ?? [])
            .Select(id =>
                id switch
                {
                    "application" => Process,
                    "edge" => Browser,
                    _ => id,
                }
            )
            .Where(All.Contains)
            .Distinct()
            .OrderBy(id => Array.IndexOf(All, id))
            .ToArray();

    public static bool Enforced(PolicyDocument policy, string id) =>
        policy.Mode == "Enforce" && Normalize(policy.RequiredControls).Contains(id);
}
