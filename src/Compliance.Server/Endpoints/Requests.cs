using Compliance.Core;

namespace Compliance.Server;

public record LoginRequest(string Username, string Password);

public record CodeRequest(int? ExpiresMinutes = null, int? MaxUses = null, string? Label = null);

/// <param name="Version">For <c>Upgrade</c>: the client package to install; the newest uploaded one if left out.</param>
public record CommandRequest(string Type, string? Version = null);

public record NoteRequest(string? Note);
