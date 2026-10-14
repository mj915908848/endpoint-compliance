using Compliance.Core;

namespace Compliance.Server;

public record LoginRequest(string Username, string Password);

public record CodeRequest(int? ExpiresMinutes = null);

public record DraftRequest(PolicyDocument? Document, bool ImpactReviewed = false);

public record CommandRequest(string Type);
