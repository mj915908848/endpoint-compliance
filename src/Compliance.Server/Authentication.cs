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

        var user = await s.Tx(async tx =>
        {
            var session = await tx.GetSession(Secrets.Hash(token));
            if (session == null || session.ExpiresAt <= s.Now)
                throw new ApiError(401, "Session expired");
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
    }
}
