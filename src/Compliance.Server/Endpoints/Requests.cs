using Compliance.Core;

namespace Compliance.Server;

/// <param name="Code">The authenticator app's code, for an account with two-step sign-in.</param>
public record LoginRequest(string Username, string Password, string? Code = null);

public record NewUserRequest(string? Username, string? Password, string[]? Roles);

public record RolesRequest(string[]? Roles);

public record ResetPasswordRequest(string? Password);

public record RequireTwoFactorRequest(bool Required);

public record TwoFactorCodeRequest(string? Code);

public record DisableTwoFactorRequest(string? Password, string? Code);

/// <param name="Group">The device group the code puts the devices it enrolls in.</param>
public record CodeRequest(int? ExpiresMinutes = null, int? MaxUses = null, string? Label = null, string? Group = null);

/// <param name="Version">For <c>Upgrade</c>: the client package to install; the newest uploaded one if left out.</param>
public record CommandRequest(string Type, string? Version = null);

public record NoteRequest(string? Note);

/// <summary>Devices an action applies to, chosen in the device list.</summary>
public record DeviceIdsRequest(string[]? Ids);

/// <param name="Group">The group to put the devices in; empty takes them out of their group.</param>
public record DeviceGroupRequest(string[]? Ids, string? Group);

public record ArchiveDaysRequest(int Days);

public record LogForwardingRequest(
    bool Enabled,
    string? Host,
    int Port = 514,
    string Protocol = "Udp",
    string Format = "Json",
    int Facility = 16,
    bool Alerts = true,
    bool Audit = true,
    string? CaCertificate = null
);
