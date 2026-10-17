using System.Diagnostics;
using System.Security.Cryptography;
using Compliance.Core;

namespace Compliance.Agent;

/// <summary>
/// Remote upgrades: the server sends an <c>Upgrade</c> command naming a client package. The client installs it only
/// when the server's policy key signed its description, the downloaded file matches it, and it is newer than itself.
/// </summary>
public static class ClientUpgrade
{
    public const string Command = "Upgrade";

    /// <summary>
    /// Checks and downloads the package an upgrade command names. Returns the reply for the server and, when the
    /// package is fit to install, the installer to hand to <see cref="Install"/> once the reply is sent: installing
    /// stops this service.
    /// </summary>
    public static async Task<(CommandReply Reply, string? Installer)> PrepareAsync(
        AgentApi api,
        DeviceCommand command,
        string policyPublicKeyPem,
        string dataDirectory,
        CancellationToken ct
    )
    {
        var own = ReleaseVersion.Of(typeof(ClientUpgrade).Assembly);
        if (!PackageCrypto.IsVersion(command.Version))
            return (new(false, "升级命令没有指明有效的版本"), null);
        // Local builds are versioned like 0.2.30-dev, and count as that release.
        var current = Version.TryParse(own.Split('-')[0], out var parsed) ? parsed : new Version(0, 0, 0);
        if (Version.Parse(command.Version!) <= current)
            return (new(true, $"客户端已是 {own}，无需升级到 {command.Version}"), null);
        var path = $"/api/agent/client-packages/{Uri.EscapeDataString(command.Version!)}";
        ClientPackage package;
        try
        {
            package = PackageCrypto.Verify(
                await api.SendAsync<SignedClientPackage>(HttpMethod.Get, path, null, ct),
                policyPublicKeyPem
            );
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException)
        {
            return (new(false, "安装包签名无效，未安装：" + e.Message), null);
        }
        if (package.Version != command.Version)
            return (new(false, $"安装包版本 {package.Version} 与命令要求的 {command.Version} 不符，未安装"), null);

        var directory = Path.Combine(dataDirectory, "updates");
        Directory.CreateDirectory(directory);
        foreach (var old in Directory.GetFiles(directory, "*.msi"))
            File.Delete(old);
        var installer = Path.Combine(directory, package.Sha256 + ".msi");
        await api.DownloadAsync(path + "/file", installer, package.Size, ct);
        await using (var file = File.OpenRead(installer))
        {
            var header = new byte[PackageCrypto.MsiSignature.Length];
            var fits =
                file.Length == package.Size
                && await file.ReadAtLeastAsync(header, header.Length, false, ct) == header.Length
                && header.AsSpan().SequenceEqual(PackageCrypto.MsiSignature);
            file.Position = 0;
            if (!fits || Convert.ToHexStringLower(await SHA256.HashDataAsync(file, ct)) != package.Sha256)
            {
                file.Close();
                File.Delete(installer);
                return (new(false, "下载的安装包与签名不符，未安装"), null);
            }
        }
        return (new(true, $"已下载并核对 {package.Version} 安装包，开始安装"), installer);
    }

    /// <summary>
    /// Starts Windows Installer on a checked package. The MSI upgrades in place, keeping the enrollment, and stops and
    /// restarts this service; its log is kept next to the package.
    /// </summary>
    public static void Install(string installer)
    {
        var log = Path.ChangeExtension(installer, ".log");
        using var process = Process.Start(
            new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "msiexec.exe"))
            {
                ArgumentList = { "/i", installer, "/qn", "/norestart", "/l*v", log },
                UseShellExecute = false,
                CreateNoWindow = true,
            }
        );
    }
}
