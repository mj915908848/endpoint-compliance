using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Compliance.Core;

namespace Compliance.Server;

/// <summary>Request authentication: session cookie + CSRF for admins, ECDSA request signatures for agents.</summary>
static class Authentication
{
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
            return await tx.GetUser(session.Username) ?? throw new ApiError(401, "Account unavailable");
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
            var publicKey = await tx.GetDevicePublicKey(device);
            if (
                publicKey == null
                || !RequestAuthentication.Verify(
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
/// Stops password guessing against one account from many addresses, which the per-address rate limit cannot see:
/// after <see cref="MaxFailures"/> wrong passwords within <see cref="Window"/>, the account refuses sign-in until the
/// oldest of them is that old. Kept in memory, so a restart clears it.
/// </summary>
public sealed class LoginThrottle
{
    public const int MaxFailures = 10;
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(15);
    const int MaxAccounts = 10_000;

    readonly Dictionary<string, Queue<DateTimeOffset>> failures = new(StringComparer.OrdinalIgnoreCase);

    public TimeSpan? LockedFor(string username, DateTimeOffset now)
    {
        lock (failures)
        {
            if (!failures.TryGetValue(username, out var times))
                return null;
            Expire(username, times, now);
            return times.Count >= MaxFailures ? times.Peek() + Window - now : null;
        }
    }

    public void Failed(string username, DateTimeOffset now)
    {
        lock (failures)
        {
            // Names that do not exist count too, so an attacker cannot tell them apart; old entries make room.
            if (failures.Count >= MaxAccounts)
                foreach (var (name, times) in failures.ToList())
                    Expire(name, times, now);
            if (failures.Count >= MaxAccounts)
                return;
            if (!failures.TryGetValue(username, out var list))
                failures[username] = list = new();
            list.Enqueue(now);
        }
    }

    public void Succeeded(string username)
    {
        lock (failures)
            failures.Remove(username);
    }

    void Expire(string username, Queue<DateTimeOffset> times, DateTimeOffset now)
    {
        while (times.Count > 0 && times.Peek() + Window <= now)
            times.Dequeue();
        if (times.Count == 0)
            failures.Remove(username);
    }
}
