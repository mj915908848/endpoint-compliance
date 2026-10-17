using System.Security.Cryptography;
using System.Text;

namespace Compliance.Core;

/// <summary>
/// Announces the policy signing key that is about to replace the current one. Signed with the current key, so a
/// client that pinned it at enrollment can trust the new key without enrolling again.
/// </summary>
public record KeyRotation(string NewPublicKeyPem, string NewKeyId, DateTimeOffset IssuedAt);

public record SignedKeyRotation(string Payload, string Signature, string KeyId);

/// <summary>
/// Signatures over statements other than policies (client packages, key rotations). Each kind of statement signs
/// its purpose before the payload, so a signature made for one never verifies as another, nor as a policy.
/// </summary>
public static class Statement
{
    public const string ClientPackage = "compliance-client-package";
    public const string KeyRotation = "compliance-key-rotation";

    public static string Sign(string purpose, string payload, ECDsa key) =>
        Convert.ToBase64String(key.SignData(Bytes(purpose, payload), HashAlgorithmName.SHA256));

    public static void Verify(string purpose, string payload, string signature, string publicKeyPem)
    {
        if (payload.Length > 16 * 1024)
            throw new ArgumentException("Statement too large");
        using var key = ECDsa.Create();
        key.ImportFromPem(publicKeyPem);
        try
        {
            if (!key.VerifyData(Bytes(purpose, payload), Convert.FromBase64String(signature), HashAlgorithmName.SHA256))
                throw new CryptographicException("Invalid signature");
        }
        catch (FormatException)
        {
            throw new CryptographicException("Invalid signature encoding");
        }
    }

    static byte[] Bytes(string purpose, string payload) => Encoding.UTF8.GetBytes(purpose + "\n" + payload);
}

public static class KeyRotationCrypto
{
    public static SignedKeyRotation Sign(KeyRotation rotation, ECDsa currentKey, string currentKeyId)
    {
        var payload = Wire.Serialize(rotation);
        return new(payload, Statement.Sign(Statement.KeyRotation, payload, currentKey), currentKeyId);
    }

    /// <summary>The announced key, once the announcement is shown to come from <paramref name="currentPublicKeyPem"/>.</summary>
    public static KeyRotation Verify(SignedKeyRotation signed, string currentPublicKeyPem)
    {
        Statement.Verify(Statement.KeyRotation, signed.Payload, signed.Signature, currentPublicKeyPem);
        var rotation = Wire.Read<KeyRotation>(signed.Payload);
        using var key = ECDsa.Create();
        key.ImportFromPem(rotation.NewPublicKeyPem);
        if (string.IsNullOrWhiteSpace(rotation.NewKeyId) || rotation.NewKeyId.Length > 64)
            throw new ArgumentException("Invalid key id");
        return rotation;
    }
}
