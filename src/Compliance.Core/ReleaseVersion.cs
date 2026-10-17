using System.Reflection;

namespace Compliance.Core;

public static class ReleaseVersion
{
    /// <summary>The release version an assembly was built as, without the commit hash the SDK appends.</summary>
    public static string Of(Assembly assembly) =>
        assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "";

    /// <summary>
    /// Whether a client reporting <paramref name="agent"/> is older than <paramref name="server"/>. Clients before
    /// 0.2.8 report no version (an empty string here) and are older; development builds are never compared.
    /// </summary>
    public static bool Older(string agent, string server) =>
        Version.TryParse(server, out var current)
        && current > new Version(0, 0, 0)
        && (agent == "" || Version.TryParse(agent, out var reported) && reported < current);

    /// <summary>
    /// The oldest client release this release of the server still serves fully: older clients are judged and kept,
    /// but administrators are told to upgrade them. Raised only together with docs/compatibility.md.
    /// </summary>
    public const string MinimumAgent = "0.2.0";

    /// <summary>
    /// Whether a client reporting <paramref name="agent"/> is older than <paramref name="minimum"/>. Clients that report
    /// no version are 0.2.0 to 0.2.7 and supported.
    /// </summary>
    public static bool Unsupported(string agent, string minimum = MinimumAgent) =>
        Version.TryParse(agent, out var reported)
        && reported > new Version(0, 0, 0)
        && Version.TryParse(minimum, out var oldest)
        && reported < oldest;
}
