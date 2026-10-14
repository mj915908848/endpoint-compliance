using Compliance.Core;

namespace Compliance.Server;

public record LoginRequest(string Username, string Password);

public record CodeRequest(int? ExpiresMinutes = null);

public record CommandRequest(string Type);
