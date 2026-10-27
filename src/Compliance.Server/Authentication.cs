using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Compliance.Core;

namespace Compliance.Server;

/// <summary>Request authentication: session cookie + CSRF for admins, ECDSA request signatures for agents.</summary>
static class Authentication
{
    static readonly string[] SetUpPaths =
    [
        "/api/me",
        "/api/auth/logout",
        "/api/auth/password",
        "/api/auth/two-factor/setup",
        "/api/auth/two-factor/enable",
    ];

    public static async Task Admin(HttpContext c, ComplianceService s)
    {
        var token = c.Request.Cookies["compliance-session"];
        if (string.IsNullOrWhiteSpace(token))
            throw new ApiError(401, "Login required");

        var hash = Secrets.Hash(token);
        var user = await s.Tx(async tx =>
        {
            var session = await tx.GetSession(hash);
            if (session == null || session.ExpiresAt <= s.Now)
                throw new ApiError(401, "Session expired");
            if (s.SessionIdle is { } idle && s.Now - session.LastActive >= idle)
                throw new ApiError(401, "Session idle");
            // The page polls on its own, so a request alone does not count as use: it says how long ago the
            // administrator last typed or clicked. Requests that do not say (downloads, scripts) count as use.
            var active = s.Now;
            if (
                long.TryParse(c.Request.Headers["X-Idle-Seconds"].ToString(), out var seconds)
                && seconds is >= 0 and < 366L * 24 * 3600
            )
                active -= TimeSpan.FromSeconds(seconds);
            // Written at most once a minute, so polling does not rewrite the row on every request.
            if (active - session.LastActive >= TimeSpan.FromMinutes(1))
                await tx.TouchSession(hash, active);
            if (
                !HttpMethods.IsGet(c.Request.Method)
                && !CryptographicOperations.FixedTimeEquals(
                    Encoding.UTF8.GetBytes(session.CsrfToken),
                    Encoding.UTF8.GetBytes(c.Request.Headers["X-CSRF-Token"].ToString())
                )
            )
                throw new ApiError(403, "CSRF token required");
            c.Items["session"] = session;
            var user = await tx.GetUser(session.Username);
            if (user is not { Disabled: false })
                throw new ApiError(401, "Account unavailable");
            var required = await Endpoints.TwoFactorRequired(tx);
            c.Items["twoFactorRequired"] = required;
            // An account the organisation requires two-step sign-in of may only set it up until it has.
            if (required && !user.TwoFactor && !SetUpPaths.Contains((c.Request.Path.Value ?? "").ToLowerInvariant()))
                throw new ApiError(403, "单位要求启用两步验证，请先在账号菜单中启用");
            return user;
        });
        c.Items["user"] = user;
    }

    public static async Task Agent(HttpContext c, ComplianceService s)
    {
        string device = c.Request.Headers["X-Device-Id"].ToString();
        string timestamp = c.Request.Headers["X-Timestamp"].ToString();
        string nonce = c.Request.Headers["X-Nonce"].ToString();
        string signature = c.Request.Headers["X-Signature"].ToString();
        if (
            device.Length > 100
            || !long.TryParse(timestamp, out var seconds)
            || Math.Abs((double)s.Now.ToUnixTimeSeconds() - seconds) > 300
            || !Guid.TryParse(nonce, out _)
        )
            throw new ApiError(401, "Invalid device authentication");

        c.Request.EnableBuffering();
        using var bytes = new MemoryStream();
        await c.Request.Body.CopyToAsync(bytes);
        c.Request.Body.Position = 0;
        if (bytes.Length > 2 * 1024 * 1024)
            throw new ApiError(413, "Body too large");

        var raw = bytes.ToArray();
        await s.Tx(async tx =>
        {
            var publicKey =
                await tx.GetDevicePublicKey(device) ?? throw new ApiError(401, RequestAuthentication.UnknownDevice);
            if (
                !RequestAuthentication.Verify(
                    publicKey,
                    c.Request.Method,
                    c.Request.Path,
                    timestamp,
                    nonce,
                    raw,
                    signature
                )
            )
                throw new ApiError(401, "Invalid device signature");
            if (!await tx.AcceptNonce(device, nonce, s.Now))
                throw new ApiError(401, "Nonce already used");
            return true;
        });
        c.Items["device"] = device;
        // The signature covers the bytes as sent; a compressed body is expanded only once it is verified.
        var encoding = c.Request.Headers.ContentEncoding.ToString();
        if (encoding.Length > 0)
        {
            if (!encoding.Equals("gzip", StringComparison.OrdinalIgnoreCase))
                throw new ApiError(415, "Unsupported content encoding");
            c.Request.Body = Expand(raw);
            c.Request.ContentLength = c.Request.Body.Length;
            c.Request.Headers.ContentEncoding = default;
        }
    }

    /// <summary>Largest body a compressed agent request may expand to.</summary>
    public const int MaxExpandedBody = 8 * 1024 * 1024;

    static MemoryStream Expand(byte[] compressed)
    {
        var expanded = new MemoryStream();
        try
        {
            using var gzip = new GZipStream(new MemoryStream(compressed), CompressionMode.Decompress);
            var buffer = new byte[81920];
            int read;
            while ((read = gzip.Read(buffer)) > 0)
            {
                if (expanded.Length + read > MaxExpandedBody)
                    throw new ApiError(413, "Body too large");
                expanded.Write(buffer, 0, read);
            }
        }
        catch (InvalidDataException)
        {
            throw new ApiError(400, "Invalid compressed body");
        }
        expanded.Position = 0;
        return expanded;
    }
}

/// <summary>
/// Stops password guessing against one account, which the per-address rate limit cannot see. Wrong passwords are
/// counted per account and source address: after <see cref="MaxFailures"/> within <see cref="Window"/> that address
/// may not sign in to that account until the oldest of them is that old. Someone who knows an account's name therefore
/// cannot lock its owner out from one machine. Guessing spread over many addresses is stopped by a higher limit per
/// account, <see cref="MaxAccountFailures"/>. Kept in memory, so a restart clears it.
/// </summary>
public sealed class LoginThrottle
{
    public const int MaxFailures = 10;
    public const int MaxAccountFailures = 50;
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(15);
    const int MaxEntries = 10_000;

    readonly Dictionary<string, Queue<DateTimeOffset>> failures = new(StringComparer.OrdinalIgnoreCase);

    static string Pair(string username, string address) => username + "\n" + address;

    static string Account(string username) => username + "\n*";

    public TimeSpan? LockedFor(string username, string address, DateTimeOffset now)
    {
        lock (failures)
        {
            TimeSpan? Wait(string key, int limit)
            {
                if (!failures.TryGetValue(key, out var times))
                    return null;
                Expire(key, times, now);
                return times.Count >= limit ? times.Peek() + Window - now : null;
            }
            var pair = Wait(Pair(username, address), MaxFailures);
            var account = Wait(Account(username), MaxAccountFailures);
            return pair > account || account is null ? pair : account;
        }
    }

    /// <summary>Counts a wrong password; whether this one locked the account for the address.</summary>
    public bool Failed(string username, string address, DateTimeOffset now)
    {
        lock (failures)
        {
            var keys = new[] { (Pair(username, address), MaxFailures), (Account(username), MaxAccountFailures) };
            // Names that do not exist count too, so an attacker cannot tell them apart; old entries make room. When
            // the table is still full, the entries with the fewest failures go, oldest first: many names tried once
            // must not stop the count of an account someone keeps guessing.
            var added = keys.Count(k => !failures.ContainsKey(k.Item1));
            if (failures.Count + added > MaxEntries)
                foreach (var (key, times) in failures.ToList())
                    Expire(key, times, now);
            // A tenth goes at once, so a flood of names does not sort the table on every attempt.
            var excess = failures.Count + added - MaxEntries;
            if (excess > 0)
                excess = Math.Max(excess, MaxEntries / 10);
            if (excess > 0)
                foreach (
                    var key in failures
                        .Where(f => !keys.Any(k => k.Item1 == f.Key))
                        .OrderBy(f => f.Value.Count)
                        .ThenBy(f => f.Value.Last())
                        .Take(excess)
                        .Select(f => f.Key)
                        .ToList()
                )
                    failures.Remove(key);
            var locked = false;
            foreach (var (key, limit) in keys)
            {
                if (!failures.TryGetValue(key, out var list))
                    failures[key] = list = new();
                list.Enqueue(now);
                // A queue never holds more than its limit needs.
                while (list.Count > limit)
                    list.Dequeue();
                locked |= list.Count == limit;
            }
            return locked;
        }
    }

    /// <summary>Clears the address's count; failures from elsewhere still count towards the account's limit.</summary>
    public void Succeeded(string username, string address)
    {
        lock (failures)
            failures.Remove(Pair(username, address));
    }

    void Expire(string key, Queue<DateTimeOffset> times, DateTimeOffset now)
    {
        while (times.Count > 0 && times.Peek() + Window <= now)
            times.Dequeue();
        if (times.Count == 0)
            failures.Remove(key);
    }
}
