using Compliance.Core;
using Microsoft.AspNetCore.Http.Features;

namespace Compliance.Server;

/// <param name="Outdated">Devices in use whose client is older than this version.</param>
public sealed record ClientPackageItem(
    string Version,
    string Sha256,
    long Size,
    DateTimeOffset UploadedAt,
    string UploadedBy,
    int Outdated
);

/// <param name="Queued">Devices that were sent the upgrade; devices already upgrading or up to date are left out.</param>
public sealed record UpgradeRollout(int Queued);

static partial class Endpoints
{
    static void MapPackages(IEndpointRouteBuilder routes, ComplianceService s)
    {
        var group = routes.MapGroup("/api/client-packages");

        group.MapGet(
            "",
            async (HttpContext c) =>
            {
                Require(c, "Reader");
                return await s.Tx(async tx =>
                {
                    // Devices by client version: a few distinct versions to compare with each package, not every device.
                    var versions = (await tx.DeviceHeads())
                        .GroupBy(d => d.AgentVersion)
                        .Select(g => (Version: g.Key, Count: g.Count()))
                        .ToArray();
                    return (await tx.ClientPackages())
                        .OrderByDescending(p => Version.Parse(p.Package.Version))
                        .Select(p => new ClientPackageItem(
                            p.Package.Version,
                            p.Package.Sha256,
                            p.Package.Size,
                            p.Package.UploadedAt,
                            p.UploadedBy,
                            versions.Where(v => ReleaseVersion.Older(v.Version, p.Package.Version)).Sum(v => v.Count)
                        ))
                        .ToArray();
                });
            }
        );

        // The body is the MSI itself, sent as application/octet-stream.
        group
            .MapPost(
                "",
                async (HttpContext c, string version) =>
                {
                    var u = Require(c, "Publisher");
                    if (!PackageCrypto.IsVersion(version))
                        throw new ApiError(400, "客户端版本号应为 主.次.序号，如 0.2.23");
                    if (c.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } limit)
                        limit.MaxRequestBodySize = PackageCrypto.MaxSize;
                    if (await s.Tx(async tx => await tx.GetClientPackage(version)) != null)
                        throw new ApiError(409, $"已有 {version} 的安装包，如需替换请先删除");
                    var package = await s.Packages.Receive(c.Request.Body, version, c.RequestAborted);
                    var record = await s.Tx(async tx =>
                    {
                        // Signed under the lock a key rotation takes, so it cannot be signed with the key being retired.
                        await tx.Lock(PackageService.PackageLock);
                        if (await tx.GetClientPackage(version) != null)
                            throw new ApiError(409, $"已有 {version} 的安装包，如需替换请先删除");
                        // A package with the same contents may have been deleted, with its file, since it was received.
                        if (!File.Exists(s.Packages.FilePath(package)))
                            throw new ApiError(409, "安装包文件刚被删除，请重新上传");
                        var record = new ClientPackageRecord(package, u.Username, s.Policies.Sign(package));
                        await tx.InsertClientPackage(record);
                        await tx.Audit(
                            u.Username,
                            "UploadClientPackage",
                            $"{version}（SHA-256 {record.Package.Sha256}）",
                            s.Now
                        );
                        return record;
                    });
                    return new ClientPackageItem(
                        version,
                        record.Package.Sha256,
                        record.Package.Size,
                        record.Package.UploadedAt,
                        u.Username,
                        0
                    );
                }
            )
            .Accepts<byte[]>("application/octet-stream");

        group.MapDelete(
            "/{version}",
            async (HttpContext c, string version) =>
            {
                var u = Require(c, "Publisher");
                await s.Tx(async tx =>
                {
                    await tx.Lock(PackageService.PackageLock);
                    var p = await tx.GetClientPackage(version) ?? throw new ApiError(404, "安装包不存在");
                    await tx.DeleteClientPackage(version);
                    await tx.Audit(u.Username, "DeleteClientPackage", version, s.Now);
                    // Under the lock, so an upload of the same file cannot start using it in between.
                    if (!await tx.ClientPackageFileUsed(p.Package.Sha256))
                        s.Packages.DeleteFile(p.Package);
                    return true;
                });
                return new Done();
            }
        );

        // Sends the upgrade to every outdated device in use, or with ?count= to that many first, online and most
        // recently seen ones before others, so a bad package reaches a few devices before all of them.
        group.MapPost(
            "/{version}/rollout",
            async (HttpContext c, string version, int? count) =>
            {
                var u = Require(c, "Operator");
                if (count is < 1)
                    throw new ApiError(400, "台数至少为 1");
                return await s.Tx(async tx =>
                {
                    // Two operators starting it at once would queue two upgrades per device.
                    await tx.Lock("rollout");
                    var package = await NewestPackage(tx, version);
                    var upgrading = (await tx.DevicesUpgrading(s.Now)).ToHashSet();
                    // Devices installing it now would be sent it again; failed and expired ones are sent it again.
                    upgrading.UnionWith(
                        (await tx.UpgradeCommands(version))
                            .Where(x =>
                                x.Reply is { Success: true }
                                && x.Outcome is null
                                && x.RepliedAt is { } at
                                && s.Now - at < ClientStatus.InstallTimeout
                            )
                            .Select(x => x.DeviceId)
                    );
                    var targets = (await tx.DeviceHeads())
                        .Where(d => !upgrading.Contains(d.Id) && ReleaseVersion.Older(d.AgentVersion, version))
                        .OrderByDescending(d => DeviceStatus.Online(d, s.Now) == "Online")
                        .ThenByDescending(d => d.LastHeartbeat)
                        .ThenBy(d => d.Id, StringComparer.Ordinal)
                        .Take(count ?? int.MaxValue)
                        .ToList();
                    foreach (var d in targets)
                        await tx.InsertCommand(new CommandRecord(d.Id, s.Packages.UpgradeCommand(d, package.Package)));
                    await tx.Audit(
                        u.Username,
                        "RolloutUpgrade",
                        $"{version}，{targets.Count} 台" + (count is null ? "" : "（分批）"),
                        s.Now
                    );
                    return new UpgradeRollout(targets.Count);
                });
            }
        );

        // Where each device sent this version stands: the latest upgrade to it per device.
        group.MapGet(
            "/{version}/rollout",
            async (HttpContext c, string version) =>
            {
                Require(c, "Reader");
                return await s.Tx(async tx =>
                {
                    await NewestPackage(tx, version);
                    var devices = (await tx.AllDeviceHeads()).ToDictionary(d => d.Id);
                    var sent = (await tx.UpgradeCommands(version))
                        .Where(x => devices.ContainsKey(x.DeviceId))
                        .GroupBy(x => x.DeviceId)
                        .Select(g => g.Last())
                        .ToList();
                    var items = sent.Select(x =>
                        {
                            var d = devices[x.DeviceId];
                            var (state, detail) = ClientStatus.Upgrade(x, d, version, s.Now);
                            return new UpgradeProgressItem(
                                d.Id,
                                d.HostName,
                                d.Note,
                                DeviceStatus.Online(d, s.Now),
                                d.AgentVersion,
                                state,
                                detail,
                                x.Command.ExpiresAt - PackageService.UpgradeExpiry
                            );
                        })
                        .OrderByDescending(i => i.SentAt)
                        .ThenBy(i => i.HostName, StringComparer.CurrentCultureIgnoreCase)
                        .ToArray();
                    var reached = sent.Select(x => x.DeviceId).ToHashSet();
                    var remaining = devices.Values.Count(d =>
                        d.ArchivedAt == null && !reached.Contains(d.Id) && ReleaseVersion.Older(d.AgentVersion, version)
                    );
                    return new UpgradeProgress(version, items, remaining);
                });
            }
        );
    }

    /// <summary>The package of <paramref name="version"/>, or the newest uploaded one when it is null.</summary>
    static async Task<ClientPackageRecord> NewestPackage(Transaction tx, string? version)
    {
        if (version != null)
            return await tx.GetClientPackage(version) ?? throw new ApiError(404, "安装包不存在");
        return (await tx.ClientPackages()).MaxBy(p => Version.Parse(p.Package.Version))
            ?? throw new ApiError(400, "还没有上传客户端安装包");
    }
}
