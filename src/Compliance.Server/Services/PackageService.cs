using System.Security.Cryptography;
using Compliance.Core;

namespace Compliance.Server;

/// <summary>
/// Client installers uploaded for remote upgrades. Files are kept on disk under their hash; the database holds what
/// each version is and its signed description, which clients check before installing.
/// </summary>
public sealed class PackageService(Settings settings, TimeProvider clock)
{
    public const string Upgrade = "Upgrade";

    /// <summary>How long an upgrade waits for a device that is switched off or offline.</summary>
    public static readonly TimeSpan UpgradeExpiry = TimeSpan.FromDays(1);

    /// <summary>Serializes adding and removing packages.</summary>
    public const string PackageLock = "client-packages";

    string Directory =>
        settings.PackageDirectory is { Length: > 0 } configured
            ? configured
            : Path.Combine(Path.GetDirectoryName(Path.GetFullPath(settings.SigningKeyPath))!, "client-packages");

    public string FilePath(ClientPackage package) => Path.Combine(Directory, package.Sha256 + ".msi");

    /// <summary>
    /// Writes an uploaded installer to disk and returns its description, for the caller to sign and store. Only
    /// files that look like an MSI and fit <see cref="PackageCrypto.MaxSize"/> are kept.
    /// </summary>
    public async Task<ClientPackage> Receive(Stream body, string version, CancellationToken ct)
    {
        System.IO.Directory.CreateDirectory(Directory);
        // Uploads a restart cut off leave their temporary file; none takes a day.
        foreach (var stale in System.IO.Directory.GetFiles(Directory, "upload-*.tmp"))
            if (File.GetLastWriteTimeUtc(stale) < clock.GetUtcNow().UtcDateTime.AddDays(-1))
                File.Delete(stale);
        var temporary = Path.Combine(Directory, "upload-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            long size = 0;
            var header = new byte[PackageCrypto.MsiSignature.Length];
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            await using (var file = File.Create(temporary))
            {
                var buffer = new byte[81920];
                int read;
                while ((read = await body.ReadAsync(buffer, ct)) > 0)
                {
                    if (size < header.Length)
                        buffer.AsSpan(0, Math.Min(read, header.Length - (int)size)).CopyTo(header.AsSpan((int)size));
                    size += read;
                    if (size > PackageCrypto.MaxSize)
                        throw new ApiError(413, "安装包过大");
                    hash.AppendData(buffer, 0, read);
                    await file.WriteAsync(buffer.AsMemory(0, read), ct);
                }
            }
            if (size < header.Length || !header.AsSpan().SequenceEqual(PackageCrypto.MsiSignature))
                throw new ApiError(400, "请上传客户端的 MSI 安装包");
            var package = new ClientPackage(
                version,
                Convert.ToHexStringLower(hash.GetHashAndReset()),
                size,
                clock.GetUtcNow()
            );
            var target = FilePath(package);
            if (File.Exists(target))
                File.Delete(temporary);
            else
                File.Move(temporary, target);
            return package;
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }

    /// <summary>Deletes the file of a removed package, once its removal is committed.</summary>
    public void DeleteFile(ClientPackage package)
    {
        if (File.Exists(FilePath(package)))
            File.Delete(FilePath(package));
    }

    /// <summary>The upgrade command for one device, after checking there is something newer for it to install.</summary>
    public DeviceCommand UpgradeCommand(DeviceRecord device, ClientPackage package)
    {
        if (device.AgentVersion is { Length: > 0 } current && !ReleaseVersion.Older(current, package.Version))
            throw new ApiError(400, $"该终端的客户端已是 {current}，不需要升级到 {package.Version}");
        return new(Guid.NewGuid().ToString("D"), Upgrade, clock.GetUtcNow().Add(UpgradeExpiry), package.Version);
    }
}
