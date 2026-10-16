using System.Security.Cryptography;
using System.Text;
using Compliance.Core;

namespace Compliance.Server;

public sealed class Settings
{
    public bool DemoMode { get; set; }
    public bool DemoHttpLan { get; set; }
    public string Storage { get; set; } = "Postgres";
    public string Database { get; set; } = "";
    public string SigningKeyPath { get; set; } = "";
    public string BootstrapUsers { get; set; } = "[]";
    public string[] TrustedProxies { get; set; } = [];

    /// <summary>Days events other than snapshots are kept for; snapshot events are kept one day.</summary>
    public int EventRetentionDays { get; set; } = 90;

    /// <summary>Days resolved alerts are kept for; alerts not resolved are always kept.</summary>
    public int AlertRetentionDays { get; set; } = 180;

    /// <summary>Minutes without keyboard or mouse use after which a management session ends; 0 turns this off.</summary>
    public int SessionIdleMinutes { get; set; } = 30;
}

public sealed record UserRecord(string Username, string PasswordHash, string[] Roles);

public sealed record BootstrapUser(string Username, string Password, string[] Roles);

/// <summary>A management sign-in. LastActive is the last time the administrator used the page, not the last request.</summary>
public sealed record SessionRecord(
    string Username,
    string CsrfToken,
    DateTimeOffset ExpiresAt,
    DateTimeOffset LastActive = default
);

public sealed record CodeRecord(DateTimeOffset ExpiresAt, bool Used);

/// <summary>An enrollment code; only its hash is stored, so the code itself is shown once when created.</summary>
public sealed record EnrollmentCode(
    string Id,
    string Label,
    DateTimeOffset ExpiresAt,
    int MaxUses,
    int Uses,
    DateTimeOffset CreatedAt,
    string CreatedBy,
    bool Revoked
);

public sealed record DeviceRecord(
    string Id,
    string HostName,
    string PublicKeyPem,
    DateTimeOffset? LastHeartbeat = null,
    long AppliedPolicyVersion = 0,
    ControlState[]? Controls = null,
    ScanSnapshot? Snapshot = null,
    long SnapshotSequence = 0,
    long TargetPolicyVersion = 1,
    string Note = "",
    string AgentVersion = "",
    NetworkAdapter[]? Network = null,
    string SourceAddress = "",
    StoredVerdict? Verdict = null
);

/// <summary>
/// A device's verdicts as last evaluated, kept on the device so lists read them instead of judging every snapshot.
/// It holds while the device's snapshot and policy are still the ones it was computed from and time has not reached
/// <see cref="ValidUntil"/> (when data goes stale or the policy expires).
/// </summary>
/// <param name="Current">The verdict of the current snapshot under the device's policy; null without a snapshot.</param>
/// <param name="Last">The verdict at collection time, under the policy the scan used.</param>
/// <param name="PolicyVersion">The device's policy's own version, as administrators see it.</param>
public sealed record StoredVerdict(
    Verdict? Current,
    Verdict? Last,
    DateTimeOffset? CollectedAt,
    long PolicyVersion,
    string PolicyName,
    string ProtectionStatus,
    int ViolationCount,
    bool Simulated,
    long SnapshotSequence,
    long TargetPolicyVersion,
    DateTimeOffset ComputedAt,
    DateTimeOffset? ValidUntil
)
{
    public bool HoldsFor(DeviceRecord d, DateTimeOffset now) =>
        SnapshotSequence == d.SnapshotSequence
        && TargetPolicyVersion == d.TargetPolicyVersion
        && ComputedAt <= now
        && (ValidUntil is null || now < ValidUntil);
}

public sealed record SnapshotIncident(string Id, string DeviceId, string Scope, string[] Modules);

public sealed record StoredEvent(string Fingerprint, AgentEvent Event, DateTimeOffset ReceivedAt);

public sealed record DraftRecord(
    string Id,
    PolicyDocument Document,
    string CreatedBy,
    string? ApprovedBy,
    bool Published,
    bool ImpactReviewed
);

public sealed record CommandRecord(string DeviceId, DeviceCommand Command, CommandReply? Reply = null);

public sealed record AuditRecord(string Id, string Actor, string Action, string Target, DateTimeOffset At);

public sealed class ApiError(int status, string message) : Exception(message)
{
    public int Status => status;
}

public static class Secrets
{
    const int Iterations = 210000;

    public static string Token() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));

    public static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    public static string Password(string value)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(value, salt, Iterations, HashAlgorithmName.SHA256, 32);
        return Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(hash);
    }

    public static bool Check(string value, string stored)
    {
        var parts = stored.Split(':');
        var expected = Convert.FromBase64String(parts[1]);
        var actual = Rfc2898DeriveBytes.Pbkdf2(
            value,
            Convert.FromBase64String(parts[0]),
            Iterations,
            HashAlgorithmName.SHA256,
            32
        );
        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }
}
