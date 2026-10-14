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
}

public record PolicyDocument
{
    public int SchemaVersion { get; init; } = 1;
    public string PolicyId { get; init; } = "customer-no-foreign-ai";
    public long Version { get; init; } = 1;
    public string Mode { get; init; } = "Audit";
    public string[] TargetDeviceIds { get; init; } = [];
    public DateTimeOffset IssuedAt { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset ExpiresAt { get; init; } = DateTimeOffset.UtcNow.AddDays(30);
    public bool DenyInstalled { get; init; } = true;
    public bool DenyProxy { get; init; } = true;
    public string[] RequiredModules { get; init; } =
    ["installed", "processes", "proxy", "extensions", "appx", "ports", "users"];
    public string[] RequiredControls { get; init; } = ["application", "edge", "network"];
    public int InventoryFreshMinutes { get; init; } = 120;
    public int LightweightFreshMinutes { get; init; } = 10;
    public ProductRule[] Products { get; init; } = [];
    public string[] BlockDomains { get; init; } = [];
    public ApplicationDenyRule[] ApplicationRules { get; init; } = [];

    /// <summary>
    /// Network adapters the customer has approved (e.g. its own VPN), matched case-insensitively as substrings
    /// of the adapter name or description. Approved adapters are not reported as clues.
    /// </summary>
    public string[] ApprovedNetworkAdapters { get; init; } = [];
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
    public int SchemaVersion { get; init; } = 1;
    public string DeviceId { get; init; } = "";
    public string HostName { get; init; } = "";
    public string Platform { get; init; } = "Windows";
    public bool Simulated { get; init; }
    public DateTimeOffset CollectedAt { get; init; } = DateTimeOffset.UtcNow;
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
);

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

public record HeartbeatRequest(
    string HostName,
    string AgentVersion,
    DateTimeOffset SourceTime,
    long PolicyVersion,
    ControlState[] Controls
);

public record EventBatch(AgentEvent[] Events);

public record EventReceipt(string[] AcceptedEventIds);

public record DeviceCommand(string Id, string Type, DateTimeOffset ExpiresAt);

public record CommandReply(bool Success, string Detail);

public record DeviceSummary(
    string Id,
    string HostName,
    DateTimeOffset? LastHeartbeat,
    string OnlineState,
    Verdict CurrentVerdict,
    Verdict? LastVerdict,
    DateTimeOffset? LastScan,
    long TargetPolicyVersion,
    long AppliedPolicyVersion,
    string ProtectionStatus,
    int ViolationCount,
    bool Simulated
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
// Header names: X-Device-Id, X-Timestamp (Unix seconds), X-Nonce (UUID), X-Signature (Base64 ECDSA SHA256).
// Enrollment HTTPS POST /api/agent/enroll; then authenticated heartbeat, policy, events, commands endpoints.
