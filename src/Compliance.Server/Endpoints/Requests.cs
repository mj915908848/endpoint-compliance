using Compliance.Core;

namespace Compliance.Server;

public record LoginRequest(string Username, string Password);

public record CodeRequest(int? ExpiresMinutes = null, int? MaxUses = null, string? Label = null);

public record CommandRequest(string Type);

public record NoteRequest(string? Note);
