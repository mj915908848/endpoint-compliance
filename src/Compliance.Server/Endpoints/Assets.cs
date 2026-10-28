using Compliance.Core;

namespace Compliance.Server;

static partial class Endpoints
{
    const int MaxInventoryChanges = 1000;
    public static readonly TimeSpan InventoryChangeRetention = TimeSpan.FromDays(365);

    static void CheckInventory(AssetInventory? r, DateTimeOffset now)
    {
        if (
            r is null
            || r.Hardware is null
            || r.OperatingSystem is null
            || r.Disks is null
            || r.Volumes is null
            || r.Software is null
            || r.Disks.Length > Inventory.MaxDisks
            || r.Volumes.Length > Inventory.MaxDisks
            || r.Software.Length > Inventory.MaxSoftware
            || r.Disks.Any(d => d is null)
            || r.Volumes.Any(v => v is null)
            || r.Software.Any(p => p is null)
            || r.CollectedAt > now.AddMinutes(5)
        )
            throw new ApiError(400, "Invalid inventory");
    }

    static void MapAssets(IEndpointRouteBuilder routes, ComplianceService s)
    {
        // Sent by clients after a full check when their inventory changed, and daily.
        routes
            .MapPost(
                "/api/agent/inventory",
                async (HttpContext c) =>
                {
                    var r = await Body<AssetInventory>(c);
                    CheckInventory(r, s.Now);
                    var inventory = Inventory.Normalize(r);
                    return await s.Tx(async tx =>
                    {
                        var deviceId = Agent(c);
                        await tx.Lock(ComplianceService.DeviceLock(deviceId));
                        await s.DeviceHead(tx, deviceId);
                        var previous = await tx.GetInventory(deviceId);
                        // One collected earlier than the one held arrived late and is already out of date.
                        if (previous is { } held && inventory.CollectedAt < held.Inventory.CollectedAt)
                            return new Done();
                        // The first inventory is where the record starts, not a list of programs just installed.
                        if (previous is { } before)
                            await tx.InsertInventoryChanges(
                                deviceId,
                                Inventory.Changes(before.Inventory, inventory, s.Now)
                            );
                        await tx.PutInventory(deviceId, inventory, s.Now);
                        return new Done();
                    });
                }
            )
            .Accepts<AssetInventory>(JsonBody);

        routes.MapGet(
            "/api/devices/{id}/inventory",
            async (HttpContext c, string id) =>
            {
                Require(c, "Reader");
                return await s.Tx(async tx =>
                {
                    await s.DeviceHead(tx, id);
                    var held = await tx.GetInventory(id);
                    return new DeviceInventory(
                        held?.Inventory,
                        held?.ReceivedAt,
                        [.. await tx.DeviceInventoryChanges(id, 200)]
                    );
                });
            }
        );

        var group = routes.MapGroup("/api/assets");

        group.MapGet(
            "",
            async (HttpContext c) =>
            {
                Require(c, "Reader");
                return await s.Tx(async tx => (await tx.Assets()).ToArray());
            }
        );

        group.MapGet(
            "/export.csv",
            async (HttpContext c) =>
            {
                var u = Require(c, "Reader");
                var rows = await s.Tx(async tx =>
                {
                    var list = await tx.Assets();
                    await tx.Audit(u.Username, "ExportAssets", $"{list.Count} 台", s.Now);
                    return list;
                });
                return Results.Text(AssetCsv(rows), "text/csv; charset=utf-8");
            }
        );

        group.MapGet(
            "/software",
            async (HttpContext c) =>
            {
                Require(c, "Reader");
                return await s.Tx(async tx => SortedSoftware(await tx.Software()));
            }
        );

        group.MapGet(
            "/software/devices",
            async (HttpContext c, string? name) =>
            {
                Require(c, "Reader");
                if (name is not { Length: > 0 and <= 256 })
                    throw new ApiError(400, "请指定软件名称");
                return await s.Tx(async tx => (await tx.SoftwareDevices(name)).ToArray());
            }
        );

        group.MapGet(
            "/software/export.csv",
            async (HttpContext c) =>
            {
                var u = Require(c, "Reader");
                var rows = await s.Tx(async tx =>
                {
                    var list = SortedSoftware(await tx.Software());
                    await tx.Audit(u.Username, "ExportSoftware", $"{list.Length} 个软件", s.Now);
                    return list;
                });
                return Results.Text(
                    Csv([
                        ["软件名称", "发布者", "安装终端数", "版本（终端数）"],
                        .. rows.Select(x =>
                            (IEnumerable<string>)
                                [
                                    x.Name,
                                    x.Publisher,
                                    x.Devices.ToString(),
                                    string.Join(
                                        "；",
                                        x.Versions.Select(v =>
                                            $"{(v.Version.Length > 0 ? v.Version : "未知版本")}（{v.Devices}）"
                                        )
                                    ),
                                ]
                        ),
                    ]),
                    "text/csv; charset=utf-8"
                );
            }
        );

        // What changed on devices in use in the last days (30 by default), newest first.
        group.MapGet(
            "/changes",
            async (HttpContext c, int? days) =>
            {
                Require(c, "Reader");
                var since = s.Now - TimeSpan.FromDays(Math.Clamp(days ?? 30, 1, 365));
                return await s.Tx(async tx => (await tx.InventoryChangesSince(since, MaxInventoryChanges)).ToArray());
            }
        );
    }

    static SoftwareSummary[] SortedSoftware(List<SoftwareSummary> software) =>
        [.. software.OrderByDescending(x => x.Devices).ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase)];

    /// <summary>The hardware list for Excel (see <see cref="Csv"/>).</summary>
    static string AssetCsv(List<AssetRow> rows) =>
        Csv([
            [
                "计算机名",
                "备注",
                "分组",
                "厂商",
                "型号",
                "序列号",
                "BIOS 版本",
                "处理器",
                "核心 / 线程",
                "内存",
                "硬盘",
                "分区（剩余 / 总量）",
                "操作系统",
                "系统版本",
                "系统安装时间",
                "软件数",
                "资产采集时间",
                "设备 ID",
            ],
            .. rows.OrderBy(r => r.HostName, StringComparer.CurrentCultureIgnoreCase)
                .Select(r =>
                    (IEnumerable<string>)
                        [
                            r.HostName,
                            r.Note,
                            r.Group,
                            r.Hardware.Manufacturer,
                            r.Hardware.Model,
                            r.Hardware.SerialNumber,
                            r.Hardware.BiosVersion,
                            r.Hardware.Processor,
                            r.Hardware.Cores > 0 ? $"{r.Hardware.Cores} / {r.Hardware.LogicalProcessors}" : "",
                            Inventory.Bytes(r.Hardware.MemoryBytes),
                            string.Join(
                                "；",
                                r.Disks.Select(d =>
                                    string.Join(
                                        " ",
                                        new[] { d.Model, d.MediaType, Inventory.Bytes(d.SizeBytes) }.Where(x =>
                                            x.Length > 0
                                        )
                                    )
                                )
                            ),
                            string.Join(
                                "；",
                                r.Volumes.Select(v =>
                                    $"{v.Name} {Inventory.Bytes(v.FreeBytes)} / {Inventory.Bytes(v.SizeBytes)}"
                                )
                            ),
                            r.OperatingSystem.Name,
                            string.Join(
                                " ",
                                new[] { r.OperatingSystem.DisplayVersion, r.OperatingSystem.Version }.Where(x =>
                                    x.Length > 0
                                )
                            ),
                            CsvTime(r.OperatingSystem.InstalledAt),
                            r.SoftwareCount.ToString(),
                            CsvTime(r.CollectedAt),
                            r.DeviceId,
                        ]
                ),
        ]);
}
