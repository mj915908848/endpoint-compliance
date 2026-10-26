using System.Security.Cryptography;
using System.Text;

namespace Compliance.Core;

/// <summary>
/// The uninstall password: policies carry only its PBKDF2 hash, <c>pbkdf2-sha256$iterations$salt$hash</c> with salt
/// and hash in base64, which the management UI computes in the browser so the password itself is never sent or stored.
/// </summary>
public static class UninstallPassword
{
    public const string Scheme = "pbkdf2-sha256";
    public const int MinIterations = 100_000;
    public const int MaxIterations = 10_000_000;

    public static string Hash(string password, byte[]? salt = null, int iterations = MinIterations)
    {
        salt ??= RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            32
        );
        return $"{Scheme}${iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public static bool Verify(string stored, string? password)
    {
        if (password is null || Parse(stored) is not var (iterations, salt, hash))
            return false;
        var actual = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            hash.Length
        );
        return CryptographicOperations.FixedTimeEquals(actual, hash);
    }

    static (int Iterations, byte[] Salt, byte[] Hash)? Parse(string stored)
    {
        var parts = stored.Split('$');
        if (
            parts.Length != 4
            || parts[0] != Scheme
            || !int.TryParse(parts[1], System.Globalization.NumberStyles.None, null, out var iterations)
            || iterations is < MinIterations or > MaxIterations
        )
            return null;
        try
        {
            var salt = Convert.FromBase64String(parts[2]);
            var hash = Convert.FromBase64String(parts[3]);
            return salt.Length is >= 16 and <= 64 && hash.Length == 32 ? (iterations, salt, hash) : null;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    public static void Validate(TamperPolicy? policy)
    {
        if (policy is null || policy.UninstallPassword is null)
            throw new ArgumentException("防篡改配置不完整");
        if (policy.UninstallPassword.Length > 0 && Parse(policy.UninstallPassword) is null)
            throw new ArgumentException("卸载密码格式无效，请在管理界面重新设置");
    }
}
