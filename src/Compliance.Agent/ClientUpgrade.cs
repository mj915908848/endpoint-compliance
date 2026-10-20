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
        Func<string, string> publicKeyFor,
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
            var signed = await api.SendAsync<SignedClientPackage>(HttpMethod.Get, path, null, ct);
            package = PackageCrypto.Verify(signed, publicKeyFor(signed.KeyId));
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
    public static string Install(string installer)
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
        return log;
    }
}

/// <summary>
/// An upgrade this client started, kept in the data directory until the server has heard how it ended. The installer
/// stops this service, so the version that runs after it (the new one, or this one again when the installation
/// failed and rolled back) reads the installer's log and reports the outcome with its next heartbeat.
/// </summary>
public sealed record PendingUpgrade(string CommandId, string Version, string Log, DateTimeOffset StartedAt)
{
    public const string FileName = "upgrade-pending.json";

    /// <summary>An installer that has not finished by then is reported as not completed.</summary>
    public static readonly TimeSpan Timeout = TimeSpan.FromHours(1);

    public static PendingUpgrade? Read(string dataDirectory)
    {
        var path = Path.Combine(dataDirectory, FileName);
        try
        {
            return File.Exists(path) ? Wire.Read<PendingUpgrade>(File.ReadAllText(path)) : null;
        }
        catch (Exception e) when (e is IOException or System.Text.Json.JsonException or UnauthorizedAccessException)
        {
            // A record the power cut damaged cannot be reported; the server then goes by the version.
            Clear(dataDirectory);
            return null;
        }
    }

    public void Save(string dataDirectory) =>
        File.WriteAllText(Path.Combine(dataDirectory, FileName), Wire.Serialize(this));

    public static void Clear(string dataDirectory)
    {
        try
        {
            File.Delete(Path.Combine(dataDirectory, FileName));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>
    /// How the upgrade ended, or null while the installer may still be running: done when this client is now that
    /// version, failed when the installer's log reports an error or it has not finished within <see cref="Timeout"/>.
    /// </summary>
    public UpgradeOutcome? Outcome(string ownVersion, DateTimeOffset now)
    {
        var current = System.Version.TryParse(ownVersion.Split('-')[0], out var parsed) ? parsed : null;
        if (current != null && System.Version.TryParse(Version, out var target) && current >= target)
            return new(CommandId, Version, true, $"已升级到 {ownVersion}");
        var status = ExitStatus(Log);
        if (status is { } code)
            return new(CommandId, Version, false, $"安装程序返回 {code}：{Meaning(code)}，客户端仍是 {ownVersion}");
        if (now - StartedAt >= Timeout)
            return new(CommandId, Version, false, $"安装程序一小时内没有完成，客户端仍是 {ownVersion}");
        return null;
    }

    /// <summary>The status Windows Installer ended with, from the last such line of its verbose log.</summary>
    public static int? ExitStatus(string log)
    {
        string text;
        try
        {
            if (!File.Exists(log))
                return null;
            // Verbose logs are UTF-16 with a byte order mark; the reader detects it.
            using var stream = new FileStream(
                log,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete
            );
            using var reader = new StreamReader(
                stream,
                System.Text.Encoding.UTF8,
                detectEncodingFromByteOrderMarks: true
            );
            text = reader.ReadToEnd();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
        int? status = null;
        foreach (
            System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(
                text,
                @"(?:Installation success or error status|MainEngineThread is returning):?\s*(\d+)"
            )
        )
            status = int.Parse(m.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
        return status is 0 ? null : status;
    }

    static string Meaning(int code) =>
        code switch
        {
            1602 => "安装被取消",
            1603 => "安装过程中出现致命错误，详见终端上的安装日志",
            1618 => "另一个安装程序正在运行",
            1625 => "系统策略禁止安装",
            1638 => "已安装了该产品的另一个版本",
            3010 => "需要重启电脑后才能完成",
            _ => "安装未成功，详见终端上的安装日志",
        };
}
