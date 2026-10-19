using System.Security.Cryptography;
using Compliance.Core;

namespace Compliance.Server;

/// <summary>
/// Replacing the signing key without enrolling devices again. Starting a rotation creates the next key next to the
/// current one; heartbeats then announce it, signed with the current key, and clients trust both until policies
/// arrive signed with the new one. Completing re-signs every stored release and package with the new key, keeps the
/// old one as a retired file and signs with the new one from then on.
/// </summary>
public sealed partial class PolicyService
{
    ECDsa? next;

    string KeyPath => Path.GetFullPath(settings.SigningKeyPath);
    string NextKeyPath => KeyPath + ".next";

    /// <summary>The announcement of the next key, while a rotation is under way.</summary>
    public SignedKeyRotation? Rotation { get; private set; }

    public string? NextKeyId => next is null ? null : IdOf(next);

    async Task LoadNextKey()
    {
        next?.Dispose();
        next = null;
        Rotation = null;
        if (!File.Exists(NextKeyPath))
            return;
        next = ECDsa.Create();
        next.ImportFromPem(await File.ReadAllTextAsync(NextKeyPath));
        var rotation = new KeyRotation(
            next.ExportSubjectPublicKeyInfoPem(),
            IdOf(next),
            new DateTimeOffset(File.GetCreationTimeUtc(NextKeyPath), TimeSpan.Zero)
        );
        lock (signing)
            Rotation = KeyRotationCrypto.Sign(rotation, signer, IdOf(signer));
    }

    public async Task StartRotation()
    {
        if (next != null)
            throw new ApiError(409, "已有正在进行的密钥轮换");
        CreateKeyFile(NextKeyPath);
        await LoadNextKey();
    }

    public void CancelRotation()
    {
        if (next == null)
            throw new ApiError(409, "没有正在进行的密钥轮换");
        File.Delete(NextKeyPath);
        next.Dispose();
        next = null;
        Rotation = null;
    }

    /// <summary>
    /// Under <see cref="PolicyLock"/> and <see cref="PackageService.PackageLock"/>: re-signs every release and package
    /// with the next key and makes it the signing key. If the transaction then fails, <see cref="UndoCompletion"/>
    /// puts the old key back; a restart in between is repaired by <see cref="RecoverRotation"/>.
    /// </summary>
    public async Task<string> CompleteRotation(Transaction tx)
    {
        if (next == null)
            throw new ApiError(409, "没有正在进行的密钥轮换");
        var nextId = IdOf(next);
        foreach (var (serial, release) in await tx.AllReleases())
            await tx.SetReleaseSignature(serial, PolicyCrypto.Resign(release, next, nextId));
        foreach (var package in await tx.ClientPackages())
            await tx.SetClientPackageSignature(
                package.Package.Version,
                PackageCrypto.Sign(package.Package, next, nextId)
            );
        var retired = KeyPath + ".retired-" + Now.ToString("yyyyMMddHHmmss");
        File.Move(KeyPath, retired);
        File.Move(NextKeyPath, KeyPath);
        Replace(await File.ReadAllTextAsync(KeyPath));
        await LoadNextKey();
        return retired;
    }

    /// <summary>Puts the key a failed completion retired back in place, with the new one pending again.</summary>
    public async Task UndoCompletion(string retired)
    {
        File.Move(KeyPath, NextKeyPath);
        File.Move(retired, KeyPath);
        Replace(await File.ReadAllTextAsync(KeyPath));
        await LoadNextKey();
    }

    string? NewestRetired() =>
        Directory
            .GetFiles(Path.GetDirectoryName(KeyPath)!, Path.GetFileName(KeyPath) + ".retired-*")
            .OrderDescending(StringComparer.Ordinal)
            .FirstOrDefault();

    /// <summary>
    /// At startup, when the stored releases were signed with another key: a completion that did not commit left the
    /// old key retired. If the newest retired key is the one the releases need, it is put back.
    /// </summary>
    async Task<bool> RecoverRotation(string storedKeyId)
    {
        var retired = NewestRetired();
        if (retired == null || File.Exists(NextKeyPath))
            return false;
        using var key = ECDsa.Create();
        key.ImportFromPem(await File.ReadAllTextAsync(retired));
        if (IdOf(key) != storedKeyId)
            return false;
        await UndoCompletion(retired);
        return true;
    }
}
