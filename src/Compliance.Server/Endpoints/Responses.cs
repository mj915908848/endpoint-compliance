using Compliance.Core;

namespace Compliance.Server;

// Named response bodies, so the OpenAPI document (and the UI types generated from it) can refer to them.

/// <summary>A request that succeeded with nothing more to say.</summary>
public record Done(bool Ok = true);

public record ServerStatus(
    string Version,
    string Mode,
    string Storage,
    NetworkCapability[] NetworkCapabilities,
    string PolicyPublicKeyPem,
    string PolicyKeyId
);

public record NetworkCapability(string Id, bool Implemented, bool Verified, string Detail);

/// <param name="IdleMinutes">Minutes without use before the session ends; 0 if it does not.</param>
public record SessionInfo(string Username, string[] Roles, string CsrfToken, double IdleMinutes);

/// <param name="SignedOut">Other sessions of the account that were ended.</param>
public record PasswordChanged(int SignedOut, bool Ok = true);

/// <param name="Health">What the client last said about itself; null for clients that do not report it.</param>
/// <param name="HealthProblems">The problems that health shows, as the client health alert names them.</param>
public record DeviceDetail(
    DeviceSummary Device,
    ScanSnapshot? Snapshot,
    ControlState[] Controls,
    int PendingCommands,
    ClientHealth? Health = null,
    string[]? HealthProblems = null
);

public record DeviceDeleted(string Deleted);

/// <param name="Done">The devices the action changed; devices already in that state or no longer enrolled are left out.</param>
public record DevicesChanged(int Done);

/// <summary>Where each device sent an upgrade to one version stands.</summary>
/// <param name="Remaining">Devices in use still older than the version that have not been sent it.</param>
public record UpgradeProgress(string Version, UpgradeProgressItem[] Devices, int Remaining);

/// <param name="State">Waiting, Installing, Succeeded, Failed, NotApplied or Expired.</param>
/// <param name="SentAt">When the upgrade was sent.</param>
public record UpgradeProgressItem(
    string DeviceId,
    string HostName,
    string Note,
    string OnlineState,
    string AgentVersion,
    string State,
    string Detail,
    DateTimeOffset SentAt
);

/// <summary>A new enrollment code; the code itself is shown only this once.</summary>
public record NewEnrollmentCode(string Code, string Id, string Label, DateTimeOffset ExpiresAt, int MaxUses);

public record CodeRevoked(string Revoked);

/// <param name="LastNotification">The last push attempt since the server started.</param>
/// <param name="AuditRetentionDays">0 keeps audit records forever.</param>
/// <param name="ArchiveDays">Devices silent this many days are archived; 0 never archives them.</param>
public record AppSettings(
    NotificationView Notifications,
    NotificationResult? LastNotification,
    int AuditRetentionDays,
    int ArchiveDays
);

/// <summary><see cref="NotificationSettings"/> with the secret left out.</summary>
/// <param name="Version">Changes with every save; sent back so a save over someone else's is refused.</param>
public record NotificationView(
    bool Enabled,
    string Channel,
    string WebhookUrl,
    bool HasSecret,
    string[] Types,
    string ConsoleUrl,
    string Version
);

/// <param name="Version">The saved settings' new <see cref="NotificationView.Version"/>.</param>
public record NotificationsSaved(string Version);

public record NotificationTested(bool Ok, string? Error);

/// <param name="GzipUploads">The server accepts gzip-compressed uploads (clients from 0.2.9 use them).</param>
/// <param name="LastSequence">The highest event sequence the server holds for the device.</param>
/// <param name="ServerVersion">The server's release.</param>
/// <param name="MinimumAgentVersion">Clients older than this should be upgraded (<see cref="ReleaseVersion.MinimumAgent"/>).</param>
/// <param name="KeyRotation">While the signing key is being replaced: the next key, signed with the current one.</param>
/// <param name="PolicySerial">The serial of the policy release assigned to the device; releases never change.</param>
/// <param name="PolicyKeyId">
/// The key policies are signed with now. Completing a key rotation re-signs every release without changing its serial,
/// so a client holding the release signed with the old key fetches it again.
/// </param>
public record HeartbeatReply(
    bool Ok,
    bool GzipUploads,
    long LastSequence,
    string ServerVersion,
    string MinimumAgentVersion,
    SignedKeyRotation? KeyRotation = null,
    long? PolicySerial = null,
    string? PolicyKeyId = null
);
