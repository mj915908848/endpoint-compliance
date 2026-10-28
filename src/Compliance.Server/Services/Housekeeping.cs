using Compliance.Core;

namespace Compliance.Server;

/// <summary>Offline alerts and the removal of data nothing reads any more.</summary>
public sealed class Housekeeping(Store store, Settings settings, TimeProvider clock)
{
    DateTimeOffset Now => clock.GetUtcNow();

    /// <summary>When this server started; devices could not report while it was down.</summary>
    readonly DateTimeOffset started = clock.GetUtcNow();

    Task<T> Tx<T>(Func<Transaction, Task<T>> action) => store.Transaction(action);

    public static readonly TimeSpan SnapshotEventRetention = TimeSpan.FromDays(1);
    public static readonly TimeSpan ExpiredCommandRetention = TimeSpan.FromDays(30);

    /// <summary>Resolved alerts the alert list returns without paging back.</summary>
    public static readonly TimeSpan RecentlyResolved = TimeSpan.FromDays(30);
    const int PruneBatch = 2000;

    /// <summary>
    /// Removes what nothing reads any more, in short batches: snapshot events after a day (their rows only answer
    /// retries, which come within minutes), other events after <see cref="Settings.EventRetentionDays"/>, alerts
    /// resolved for <see cref="Settings.AlertRetentionDays"/>, expired sessions (and replay nonces), commands expired for 30 days, asset inventory changes and USB storage records after a year, and audit records older than the period chosen in the settings
    /// page (kept forever by default; the removal itself is audited). Returns how many rows went.
    /// </summary>
    public async Task<int> Maintain(CancellationToken ct = default)
    {
        var total = 0;
        async Task Repeat(Func<Transaction, Task<int>> batch)
        {
            int removed;
            do
            {
                ct.ThrowIfCancellationRequested();
                removed = await Tx(batch);
                total += removed;
            } while (removed >= PruneBatch);
        }
        await Repeat(tx => tx.PruneEvents(Now - SnapshotEventRetention, true, PruneBatch));
        await Repeat(tx =>
            tx.PruneEvents(Now - TimeSpan.FromDays(Math.Max(1, settings.EventRetentionDays)), false, PruneBatch)
        );
        var resolvedCutoff = Now - TimeSpan.FromDays(Math.Max(1, settings.AlertRetentionDays));
        await Repeat(tx => tx.PruneResolvedAlerts(resolvedCutoff, PruneBatch));
        total += await Tx(tx => tx.PruneSessions(Now));
        // Replay-protection bookkeeping, not data anyone kept: not counted.
        await Tx(tx => tx.PruneNonces(Now));
        total += await Tx(tx => tx.PruneCommands(Now - ExpiredCommandRetention));
        await Repeat(tx => tx.PruneVerdictHistory(Now - VerdictService.VerdictHistoryRetention, PruneBatch));
        await Repeat(tx => tx.PruneInventoryChanges(Now - Endpoints.InventoryChangeRetention, PruneBatch));
        await Repeat(tx => tx.PruneUsbEvents(Now - Endpoints.UsbEventRetention, PruneBatch));
        await ArchiveSilent(ct);
        var days = await Tx(AuditRetentionDays);
        if (days > 0)
        {
            var before = total;
            var cutoff = Now - TimeSpan.FromDays(days);
            await Repeat(tx => tx.PruneAudit(cutoff, PruneBatch));
            if (total > before)
                await Tx(async tx =>
                {
                    await tx.Audit(
                        "system",
                        "PruneAudit",
                        $"{total - before} 条，{cutoff.ToLocalTime():yyyy-MM-dd HH:mm} 之前",
                        Now
                    );
                    return true;
                });
        }
        return total;
    }

    public const string ArchiveDaysKey = "device-archive-days";

    /// <summary>Days without a heartbeat before a device is archived; 0 never archives devices by itself.</summary>
    public static readonly int[] ArchiveChoices = [0, 30, 60, 90, 180];

    public const int DefaultArchiveDays = 30;

    public static async Task<int> ArchiveDays(Transaction tx) =>
        int.TryParse(await tx.GetSetting(ArchiveDaysKey), out var days) ? days : DefaultArchiveDays;

    /// <summary>
    /// Archives devices: they leave the device list, the counts, upgrades and key rotation, and their alerts are
    /// resolved. A device that reports again is taken out of the archive. Returns the devices archived.
    /// </summary>
    public static async Task<int> Archive(
        Transaction tx,
        IEnumerable<string> ids,
        string actor,
        string why,
        DateTimeOffset now
    )
    {
        var archived = 0;
        foreach (var id in ids.Distinct().Order(StringComparer.Ordinal))
        {
            await tx.Lock(ComplianceService.DeviceLock(id));
            foreach (var (_, host) in await tx.ArchiveDevices([id], now))
            {
                await tx.ResolveDeviceAlerts(id, now);
                await tx.Audit(actor, "ArchiveDevice", $"{host}（{id}）{why}", now);
                archived++;
            }
        }
        return archived;
    }

    /// <summary>Archives devices silent for the chosen number of days, a batch per transaction.</summary>
    async Task ArchiveSilent(CancellationToken ct)
    {
        var days = await Tx(ArchiveDays);
        if (days <= 0)
            return;
        int found;
        do
        {
            ct.ThrowIfCancellationRequested();
            found = await Tx(async tx =>
            {
                // Offline alerts are opened under this lock; taken first, as UpdateOffline does.
                await tx.Lock("offline");
                var ids = await tx.DevicesSilentSince(Now - TimeSpan.FromDays(days), 200);
                await Archive(tx, ids, "system", $"{days} 天未上线", Now);
                return ids.Count;
            });
        } while (found == 200);
    }

    public const string AuditRetentionKey = "audit-retention-days";

    /// <summary>Kept forever (0) unless an administrator chose a period; at least 180 days, as logs must be kept.</summary>
    public static readonly int[] AuditRetentionChoices = [0, 180, 365, 730, 1095];

    public static async Task<int> AuditRetentionDays(Transaction tx) =>
        int.TryParse(await tx.GetSetting(AuditRetentionKey), out var days) ? days : 0;

    /// <summary>
    /// Opens an offline alert for devices silent for 5 minutes and resolves it once they are Online again.
    /// Only devices whose state actually changes are loaded. Silence is counted from this server's start at the
    /// earliest, so restarting it after an outage does not report every device offline at once.
    /// </summary>
    public async Task UpdateOffline(Transaction tx)
    {
        await tx.Lock("offline");
        // Not audited: the alert records each outage, and two audit rows per device per day (shut down at night,
        // started in the morning) buried what people did.
        var silentSince = Now - TimeSpan.FromMinutes(5);
        var goingOffline = started < silentSince ? await tx.DevicesGoingOffline(silentSince) : [];
        foreach (var (id, hostName) in goingOffline)
        {
            await tx.UpsertAlert(
                new AlertSummary(
                    "offline:" + id,
                    id,
                    hostName,
                    "Offline",
                    "heartbeat",
                    "终端长时间未上报心跳，原因待确认",
                    "Active",
                    0,
                    Now,
                    Now,
                    false
                )
            );
        }
        foreach (var id in await tx.DevicesBackOnline(Now - TimeSpan.FromMinutes(3)))
        {
            await tx.ResolveAlert("offline:" + id, Now);
        }
    }
}

public sealed class MaintenanceService(ComplianceService service, ILogger<MaintenanceService> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
            using var timer = new PeriodicTimer(TimeSpan.FromHours(1));
            do
            {
                try
                {
                    var removed = await service.Housekeeping.Maintain(stoppingToken);
                    // Expired exceptions leave the policies, so devices stop carrying them.
                    await service.Tx(async tx =>
                    {
                        await tx.Lock(PolicyService.PolicyLock);
                        return await service.Policies.RefreshExceptions(tx);
                    });
                    if (removed > 0)
                        logger.LogInformation("Removed {Count} expired events, sessions and commands", removed);
                }
                catch (Exception e) when (!stoppingToken.IsCancellationRequested)
                {
                    logger.LogError(e, "Maintenance failed");
                }
            } while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }
}

/// <summary>
/// Every 15 seconds opens and resolves offline alerts and stores verdicts that no longer hold. Only this writes them;
/// the pages that show them only read.
/// </summary>
public sealed class StatusMonitor(ComplianceService service, ILogger<StatusMonitor> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(15));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await service.Tx(async tx =>
                {
                    await service.Housekeeping.UpdateOffline(tx);
                    return true;
                });
            }
            catch (Exception e) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogError(e, "Offline status refresh failed");
            }
            try
            {
                await service.Verdicts.RefreshVerdicts(stoppingToken);
            }
            catch (Exception e) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogError(e, "Verdict refresh failed");
            }
        }
    }
}
