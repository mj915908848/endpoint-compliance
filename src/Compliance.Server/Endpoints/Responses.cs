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

public record DeviceDetail(DeviceSummary Device, ScanSnapshot? Snapshot, ControlState[] Controls, int PendingCommands);

public record DeviceDeleted(string Deleted);

/// <summary>A new enrollment code; the code itself is shown only this once.</summary>
public record NewEnrollmentCode(string Code, string Id, string Label, DateTimeOffset ExpiresAt, int MaxUses);

public record CodeRevoked(string Revoked);

/// <param name="LastNotification">The last push attempt since the server started.</param>
/// <param name="AuditRetentionDays">0 keeps audit records forever.</param>
public record AppSettings(NotificationView Notifications, NotificationResult? LastNotification, int AuditRetentionDays);

/// <summary><see cref="NotificationSettings"/> with the secret left out.</summary>
public record NotificationView(
    bool Enabled,
    string Channel,
    string WebhookUrl,
    bool HasSecret,
    string[] Types,
    string ConsoleUrl
);

public record NotificationTested(bool Ok, string? Error);

/// <param name="GzipUploads">The server accepts gzip-compressed uploads (clients from 0.2.9 use them).</param>
/// <param name="LastSequence">The highest event sequence the server holds for the device.</param>
/// <param name="ServerVersion">The server's release.</param>
/// <param name="MinimumAgentVersion">Clients older than this should be upgraded (<see cref="ReleaseVersion.MinimumAgent"/>).</param>
public record HeartbeatReply(
    bool Ok,
    bool GzipUploads,
    long LastSequence,
    string ServerVersion,
    string MinimumAgentVersion
);
