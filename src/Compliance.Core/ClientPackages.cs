using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Compliance.Core;

/// <summary>A client installer (MSI) the server hosts for remote upgrades.</summary>
/// <param name="Sha256">Lower-case hex SHA-256 of the file.</param>
public record ClientPackage(string Version, string Sha256, long Size, DateTimeOffset UploadedAt);

/// <summary>
/// A <see cref="ClientPackage"/> signed with the policy signing key, so a client installs only packages its server
/// published, whoever serves the file.
/// </summary>
public record SignedClientPackage(string Payload, string Signature, string KeyId);

public static partial class PackageCrypto
{
    public const long MaxSize = 512L * 1024 * 1024;

    // Signed bytes start with this, so a package signature can never pass as a policy signature or the other way round.
    const string Purpose = "compliance-client-package\n";

    public static SignedClientPackage Sign(ClientPackage package, ECDsa key, string keyId)
    {
        Validate(package);
        var payload = Wire.Serialize(package);
        return new(
            payload,
            Convert.ToBase64String(key.SignData(Encoding.UTF8.GetBytes(Purpose + payload), HashAlgorithmName.SHA256)),
            keyId
        );
    }

    public static ClientPackage Verify(SignedClientPackage signed, string publicKeyPem)
    {
        if (signed.Payload.Length > 4096)
            throw new ArgumentException("Package description too large");
        using var key = ECDsa.Create();
        key.ImportFromPem(publicKeyPem);
        try
        {
            if (
                !key.VerifyData(
                    Encoding.UTF8.GetBytes(Purpose + signed.Payload),
                    Convert.FromBase64String(signed.Signature),
                    HashAlgorithmName.SHA256
                )
            )
                throw new CryptographicException("Invalid package signature");
        }
        catch (FormatException)
        {
            throw new CryptographicException("Invalid package signature encoding");
        }
        var package = Wire.Read<ClientPackage>(signed.Payload);
        Validate(package);
        return package;
    }

    public static void Validate(ClientPackage package)
    {
        if (!IsVersion(package.Version))
            throw new ArgumentException("客户端版本号应为 主.次.序号，如 0.2.23");
        if (!Sha256Pattern().IsMatch(package.Sha256 ?? ""))
            throw new ArgumentException("Invalid package hash");
        if (package.Size <= 0 || package.Size > MaxSize)
            throw new ArgumentException("Invalid package size");
    }

    /// <summary>A release version as packages carry it: three numbers, such as 0.2.23.</summary>
    public static bool IsVersion(string? version) =>
        version is { Length: <= 32 } && VersionPattern().IsMatch(version) && Version.TryParse(version, out _);

    /// <summary>The first bytes of every MSI file (an OLE compound document).</summary>
    public static ReadOnlySpan<byte> MsiSignature => [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    [GeneratedRegex("^[0-9a-f]{64}$")]
    private static partial Regex Sha256Pattern();

    [GeneratedRegex(@"^\d{1,5}\.\d{1,5}\.\d{1,5}$")]
    private static partial Regex VersionPattern();
}
