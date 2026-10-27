using Compliance.Core;

namespace Compliance.Server;

public record LoginRequest(string Username, string Password);

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
