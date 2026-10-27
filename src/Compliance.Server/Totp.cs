using System.Security.Cryptography;
using System.Text;

namespace Compliance.Server;

/// <summary>
/// Time-based one-time passwords (RFC 6238: HMAC-SHA1, 30-second steps, 6 digits), the codes authenticator apps such
/// as Microsoft Authenticator, Google Authenticator or 腾讯身份验证器 show. A code is accepted one step early or
/// late, for clocks that drift, and each step only once.
/// </summary>
public static class Totp
{
    public const int Digits = 6;
    public static readonly TimeSpan Step = TimeSpan.FromSeconds(30);
    const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /// <summary>A new 160-bit secret in Base32, as authenticator apps take it.</summary>
    public static string NewSecret() => Base32(RandomNumberGenerator.GetBytes(20));

    /// <summary>The otpauth:// address a QR code carries for authenticator apps to add the account.</summary>
    public static string Uri(string issuer, string account, string secret) =>
        $"otpauth://totp/{System.Uri.EscapeDataString(issuer)}:{System.Uri.EscapeDataString(account)}"
        + $"?secret={secret}&issuer={System.Uri.EscapeDataString(issuer)}&digits={Digits}&period={(int)Step.TotalSeconds}";

    public static long StepAt(DateTimeOffset time) => time.ToUnixTimeSeconds() / (long)Step.TotalSeconds;

    public static string Code(string secret, long step)
    {
        Span<byte> counter = stackalloc byte[8];
        for (var i = 7; i >= 0; i--, step >>= 8)
            counter[i] = (byte)step;
        var hash = HMACSHA1.HashData(FromBase32(secret), counter);
        var offset = hash[^1] & 0x0f;
        var value =
            ((hash[offset] & 0x7f) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        return (value % 1_000_000).ToString("D6");
    }

    /// <summary>
    /// The step <paramref name="code"/> belongs to, or null when it is wrong, outside the steps accepted or not
    /// after <paramref name="lastUsed"/>, the step of the code used last (so a code works once).
    /// </summary>
    public static long? Verify(string secret, string? code, DateTimeOffset now, long lastUsed)
    {
        code = code?.Replace(" ", "");
        if (string.IsNullOrEmpty(secret) || code is not { Length: Digits } || !code.All(char.IsAsciiDigit))
            return null;
        var current = StepAt(now);
        for (var step = current - 1; step <= current + 1; step++)
            if (
                step > lastUsed
                && CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(Code(secret, step)),
                    Encoding.ASCII.GetBytes(code)
                )
            )
                return step;
        return null;
    }

    static string Base32(byte[] bytes)
    {
        var text = new StringBuilder();
        int buffer = 0,
            bits = 0;
        foreach (var b in bytes)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                text.Append(Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0)
            text.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        return text.ToString();
    }

    static byte[] FromBase32(string text)
    {
        var bytes = new List<byte>();
        int buffer = 0,
            bits = 0;
        foreach (var c in text.TrimEnd('=').ToUpperInvariant())
        {
            var value = Alphabet.IndexOf(c);
            if (value < 0)
                throw new FormatException("Invalid Base32 secret");
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8)
            {
                bytes.Add((byte)(buffer >> (bits - 8)));
                bits -= 8;
            }
        }
        return [.. bytes];
    }
}
