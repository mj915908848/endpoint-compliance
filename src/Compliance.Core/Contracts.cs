using System.Text.Json;
using System.Text.Json.Serialization;

namespace Compliance.Core;

public static class Wire
{
    public const int SchemaVersion = 1;
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
    };

    public static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Json);

    public static T Read<T>(string json) =>
        JsonSerializer.Deserialize<T>(json, Json) ?? throw new JsonException("Empty document");
}

public enum Verdict
{
    PASS,
    FAIL,
    UNKNOWN,
}

public enum EvidenceKind
{
    Installation,
    Process,
    Extension,
    Proxy,
    Clue,
    BlockedAttempt,

    /// <summary>A file or folder whose name contains a configured keyword; ProductId is the rule id.</summary>
    SensitiveFile,
}

public record ProductRule(
    string Id,
    string Name,
    string Category,
    string[] PackageIds,
    string[] ExecutableNames,
    string[] ExtensionIds,
    string[] Domains
)
{
    public string[] DisplayNames { get; init; } = [];

    /// <summary>Substrings of tunnel adapter names or descriptions this product creates; a match is a clue only.</summary>
    public string[] AdapterNames { get; init; } = [];

    /// <summary>npm package names installed globally, e.g. "@openai/codex".</summary>
    public string[] NpmPackages { get; init; } = [];

    /// <summary>Python package names installed with pip, pipx or uv, e.g. "aider-chat".</summary>
    public string[] PipPackages { get; init; } = [];
}

public record PolicyDocument
{
    public int SchemaVersion { get; init; } = Wire.SchemaVersion;
    public string PolicyId { get; init; } = "Default";

    /// <summary>This policy's own release number, counting 1, 2, 3 ... per policy; shown to administrators.</summary>
    public long Version { get; init; } = 1;

    /// <summary>
    /// The release's number among the releases of every policy, which only grows. Agents refuse a lower one than
    /// they hold, so moving a device to another policy can never roll it back. 0 in releases from before 0.2.17,
    /// whose <see cref="Version"/> was that number.
    /// </summary>
    public long Sequence { get; init; }

    /// <summary>
    /// What identifies a release: agents report it as their policy version and the server stores releases under it.
    /// </summary>
    [JsonIgnore]
    public long Serial => Sequence > 0 ? Sequence : Version;
    public string Mode { get; init; } = "Audit";
    public string[] TargetDeviceIds { get; init; } = [];
    public DateTimeOffset IssuedAt { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset ExpiresAt { get; init; } = DateTimeOffset.UtcNow.AddDays(365);
    public bool DenyInstalled { get; init; } = true;
    public bool DenyProxy { get; init; } = true;

    /// <summary>Every module the agent can run, in the order the management UI lists them.</summary>
    public static readonly string[] AllModules =
    [
        "installed",
        "installed-paths",
        "services",
        "processes",
        "proxy",
        "proxy-env",
        "proxy-advanced",
        "extensions",
        "appx",
        "ports",
        "users",
        "cli",
        "programs",
    ];

    /// <summary>
    /// Modules the agent runs; each must complete for a pass. Modules left out are not run at all. User accounts are
    /// always read, since per-user modules need them, but only count toward the verdict when listed.
    /// </summary>
    public string[] RequiredModules { get; init; } = [.. AllModules];
    public string[] RequiredControls { get; init; } = [];

    /// <summary>How often the agent checks processes, ports and proxy settings.</summary>
    public int QuickCheckMinutes { get; init; } = 5;

    /// <summary>How often the agent also checks installed software, extensions and services.</summary>
    public int FullCheckMinutes { get; init; } = 60;

    /// <summary>Results older than this count as missing; the server sets it to twice <see cref="FullCheckMinutes"/>.</summary>
    public int InventoryFreshMinutes { get; init; } = 120;

    /// <summary>Results older than this count as missing; the server sets it to twice <see cref="QuickCheckMinutes"/>.</summary>
    public int LightweightFreshMinutes { get; init; } = 10;

    /// <summary>
    /// Modules the agent runs on full checks only; quick checks carry their last results forward, so they are judged
    /// against <see cref="InventoryFreshMinutes"/>.
    /// </summary>
    public static readonly string[] InventoryModules =
    [
        "installed",
        "installed-paths",
        "services",
        "programs",
        "extensions",
        "cli",
        "appx",
    ];

    /// <summary>How old a module's results may be before they count as missing.</summary>
    public int FreshMinutes(string module) =>
        InventoryModules.Contains(module) ? InventoryFreshMinutes : LightweightFreshMinutes;

    public ProductRule[] Products { get; init; } = [];
    public string[] BlockDomains { get; init; } = [];
    public ApplicationDenyRule[] ApplicationRules { get; init; } = [];

    /// <summary>
    /// Network adapters the customer has approved (e.g. its own VPN), matched case-insensitively as substrings
    /// of the adapter name or description. Approved adapters are not reported as clues.
    /// </summary>
    public string[] ApprovedNetworkAdapters { get; init; } = [];

    /// <summary>File name keyword scanning; off unless an administrator enables it.</summary>
    public SensitiveFilePolicy SensitiveFiles { get; init; } = new();
}

/// <summary>
/// Scans file and folder names (never contents) in user profiles and on fixed drives other than the system drive.
/// </summary>
public record SensitiveFilePolicy
{
    public bool Enabled { get; init; }
    public SensitiveFileRule[] Rules { get; init; } = [];
    public bool ScanUserProfiles { get; init; } = true;
    public bool ScanOtherFixedDrives { get; init; } = true;

    /// <summary>
    /// A bare name (e.g. "node_modules") skips every folder with that name; a path (e.g. "D:\Backup") skips that
    /// folder and everything under it.
    /// </summary>
    public string[] ExcludePaths { get; init; } =
    ["AppData", "$Recycle.Bin", "System Volume Information", "node_modules", ".git"];

    /// <summary>A completed scan is repeated after this many hours; a changed rule set starts a new scan at once.</summary>
    public int RescanHours { get; init; } = 24;

    /// <summary>Hits reported per user profile or drive; further hits are counted but not listed.</summary>
    public int MaxHitsPerScope { get; init; } = 200;
}

/// <summary>
/// A name matches when it contains any keyword, ignoring case and full-width/half-width differences. Action "Alert"
/// only notifies administrators; "Violation" also makes the device fail.
/// </summary>
public record SensitiveFileRule(string Id, string Name, string[] Keywords)
{
    /// <summary>File extensions such as ".xlsx"; empty matches every file. Rules with extensions never match folders.</summary>
    public string[] Extensions { get; init; } = [];

    /// <summary>A matching folder is reported once instead of each file inside it.</summary>
    public bool MatchFolders { get; init; } = true;

    public string Action { get; init; } = "Alert";
}

public record ApplicationDenyRule(string ProductId, string Name, string Sha256, string Type = "Exe");

public record SignedPolicy(string Payload, string Signature, string KeyId);

public record Evidence(
    string ProductId,
    string ProductName,
    EvidenceKind Kind,
    string ObjectKey,
    string Source,
    string Summary,
    string? UserSid = null,
    bool Confirmed = true
)
{
    public DateTimeOffset? CollectedAt { get; init; }
}

public record ModuleResult(
    string Module,
    string Scope,
    string Status,
    DateTimeOffset CollectedAt,
    string? Error = null
);

/// <param name="Version">The <see cref="PolicyDocument.Serial"/> of the policy the state was reached under.</param>
public record ControlState(
    string Id,
    long Version,
    string State,
    string Detail,
    bool Verified = false,
    bool RebootRequired = false
);

public record ScanSnapshot
{
    public int SchemaVersion { get; init; } = Wire.SchemaVersion;
    public string DeviceId { get; init; } = "";
    public string HostName { get; init; } = "";
    public string Platform { get; init; } = "Windows";
    public bool Simulated { get; init; }
    public DateTimeOffset CollectedAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>The <see cref="PolicyDocument.Serial"/> of the policy the scan used.</summary>
    public long PolicyVersion { get; init; }
    public Evidence[] Evidence { get; init; } = [];
    public ModuleResult[] Modules { get; init; } = [];
    public ControlState[] Controls { get; init; } = [];

    /// <summary>Account names for the user SIDs in this snapshot, so reports can say "kaiyu" instead of a SID.</summary>
    public UserAccount[] Users { get; init; } = [];
}

public record UserAccount(string Sid, string Name);

public record ComplianceReport(
    Verdict Verdict,
    string Summary,
    string[] Reasons,
    string[] CoverageGaps,
    int ViolationCount,
    int EvidenceCount,
    string ProtectionStatus,
    ScanSnapshot Snapshot
)
{
    /// <summary>Incomplete sensitive file scans when every rule only alerts; they do not affect the verdict.</summary>
    public string[] SensitiveFileNotes { get; init; } = [];

    /// <summary>The name of the policy the report judged against.</summary>
    public string PolicyName { get; init; } = "";

    /// <summary>That policy's own <see cref="PolicyDocument.Version"/>.</summary>
    public long PolicyVersion { get; init; }

    /// <summary>
    /// The first moment the same policy and snapshot could give a different report as time passes (data going stale,
    /// the policy expiring); null when nothing in it depends on time. Not part of the report itself.
    /// </summary>
    [JsonIgnore]
    public DateTimeOffset? ValidUntil { get; init; }

    /// <summary>
    /// Positions in the judged snapshot's evidence of the evidence that makes it fail, so callers need not judge each
    /// piece again. Not part of the report itself.
    /// </summary>
    [JsonIgnore]
    public int[] ConfirmedEvidence { get; init; } = [];
}

public record AgentEvent(
    string EventId,
    long Sequence,
    DateTimeOffset SourceTime,
    string Type,
    string ObjectKey,
    ScanSnapshot? Snapshot = null,
    string? Detail = null
);

public record EnrollmentRequest(string Code, string HostName, string PublicKeyPem);

public record EnrollmentResponse(string DeviceId, string PolicyPublicKeyPem, string PolicyKeyId);

/// <param name="PolicyVersion">The <see cref="PolicyDocument.Serial"/> of the policy the agent holds.</param>
/// <param name="PolicyKeyIds">The policy signing keys the agent trusts: its own, and during a rotation the next.</param>
public record HeartbeatRequest(
    string HostName,
    string AgentVersion,
    DateTimeOffset SourceTime,
    long PolicyVersion,
    ControlState[] Controls,
    NetworkAdapter[]? Network = null,
    string[]? PolicyKeyIds = null
);

/// <summary>A device's physical network adapter: its hardware address as AA-BB-CC-DD-EE-FF and its IP addresses.</summary>
/// <param name="Primary">The adapter has a default gateway, so it is the one the device reaches the network by.</param>
public record NetworkAdapter(string Name, string Mac, string[] Addresses, bool Primary = false);

public record EventBatch(AgentEvent[] Events);

public record EventReceipt(string[] AcceptedEventIds);

/// <param name="Version">For <c>Upgrade</c>: the <see cref="ClientPackage.Version"/> to install.</param>
public record DeviceCommand(string Id, string Type, DateTimeOffset ExpiresAt, string? Version = null);

public record CommandReply(bool Success, string Detail);

/// <param name="TargetPolicyVersion">The device's policy's own version, as administrators see it.</param>
/// <param name="PolicyApplied">The agent reported holding that release.</param>
/// <param name="AgentOutdated">The client is older than the server.</param>
/// <param name="AgentUnsupported">The client is older than <see cref="ReleaseVersion.MinimumAgent"/>.</param>
public record DeviceSummary(
    string Id,
    string HostName,
    DateTimeOffset? LastHeartbeat,
    string OnlineState,
    Verdict CurrentVerdict,
    Verdict? LastVerdict,
    DateTimeOffset? LastScan,
    long TargetPolicyVersion,
    bool PolicyApplied,
    string ProtectionStatus,
    int ViolationCount,
    bool Simulated,
    string Note = "",
    string PolicyName = "",
    string AgentVersion = "",
    bool AgentOutdated = false,
    NetworkAdapter[]? Network = null,
    string SourceAddress = "",
    bool AgentUnsupported = false
);

public record AlertSummary(
    string Id,
    string DeviceId,
    string HostName,
    string Type,
    string ObjectKey,
    string Summary,
    string State,
    long LastSequence,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen,
    bool Acknowledged
);

// Canonical authenticated request: method + path (without query) + timestamp + nonce + SHA256(body), separated by LF.
// The body is hashed as sent: gzip-compressed (Content-Encoding: gzip) when the heartbeat reply had gzipUploads.
// Header names: X-Device-Id, X-Timestamp (Unix seconds), X-Nonce (UUID), X-Signature (Base64 ECDSA SHA256).
// Enrollment HTTPS POST /api/agent/enroll; then authenticated heartbeat, policy, events, commands endpoints.
