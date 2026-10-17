using Compliance.Core;
using Microsoft.AspNetCore.Http.Features;

namespace Compliance.Server;

/// <param name="Outdated">Enrolled devices whose client is older than this version.</param>
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
                    var devices = await tx.AllDeviceHeads();
                    return (await tx.ClientPackages())
                        .OrderByDescending(p => Version.Parse(p.Package.Version))
                        .Select(p => new ClientPackageItem(
                            p.Package.Version,
                            p.Package.Sha256,
                            p.Package.Size,
                            p.Package.UploadedAt,
                            p.UploadedBy,
                            devices.Count(d => ReleaseVersion.Older(d.AgentVersion, p.Package.Version))
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
                    var record = await s.Packages.Receive(c.Request.Body, version, u.Username, c.RequestAborted);
                    await s.Tx(async tx =>
                    {
                        await tx.Lock(PackageService.PackageLock);
                        if (await tx.GetClientPackage(version) != null)
                            throw new ApiError(409, $"已有 {version} 的安装包，如需替换请先删除");
                        await tx.InsertClientPackage(record);
                        await tx.Audit(
                            u.Username,
                            "UploadClientPackage",
                            $"{version}（SHA-256 {record.Package.Sha256}）",
                            s.Now
                        );
                        return true;
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
                var (package, fileUsed) = await s.Tx(async tx =>
                {
                    await tx.Lock(PackageService.PackageLock);
                    var p = await tx.GetClientPackage(version) ?? throw new ApiError(404, "安装包不存在");
                    await tx.DeleteClientPackage(version);
                    await tx.Audit(u.Username, "DeleteClientPackage", version, s.Now);
                    return (p.Package, await tx.ClientPackageFileUsed(p.Package.Sha256));
                });
                if (!fileUsed)
                    s.Packages.DeleteFile(package);
                return new Done();
            }
        );

        group.MapPost(
            "/{version}/rollout",
            async (HttpContext c, string version) =>
            {
                var u = Require(c, "Operator");
                return await s.Tx(async tx =>
                {
                    var package = await NewestPackage(tx, version);
                    var upgrading = (await tx.DevicesUpgrading(s.Now)).ToHashSet();
                    var queued = 0;
                    foreach (var d in await tx.AllDeviceHeads())
                    {
                        if (upgrading.Contains(d.Id) || !ReleaseVersion.Older(d.AgentVersion, version))
                            continue;
                        await tx.InsertCommand(new CommandRecord(d.Id, s.Packages.UpgradeCommand(d, package.Package)));
                        queued++;
                    }
                    await tx.Audit(u.Username, "RolloutUpgrade", $"{version}，{queued} 台", s.Now);
                    return new UpgradeRollout(queued);
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
