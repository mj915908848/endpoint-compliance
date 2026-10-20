using System.Collections.Concurrent;
using Compliance.Core;

namespace Compliance.Server;

/// <summary>Judges devices against their policies, stores the verdicts and serves them to the management pages.</summary>
public sealed class VerdictService(Store store, PolicyService policies, TimeProvider clock)
{
    DateTimeOffset Now => clock.GetUtcNow();

    Task<T> Tx<T>(Func<Transaction, Task<T>> action) => store.Transaction(action);

    string Online(DeviceRecord d) => DeviceStatus.Online(d, Now);

    public async Task<ComplianceReport> Report(Transaction tx, DeviceRecord device)
    {
        if (device.Snapshot == null)
            throw new ApiError(404, "No scan available");
        var report = ReportEngine.Evaluate(
            Wire.Read<PolicyDocument>((await policies.AssignedPolicy(tx, device)).Payload),
            device.Snapshot,
            Now
        );
        if (Online(device) == "Online")
            return report;
        return report with
        {
            Verdict = Verdict.UNKNOWN,
            Summary = "终端失联或疑似失联，当前无法判断；以下为上次检查结果，仅供参考",
            CoverageGaps = report.CoverageGaps.Append("终端最近没有上报心跳").ToArray(),
        };
    }

    // Releases never change once committed; only read-only summaries fill this, never a publishing transaction.
    readonly ConcurrentDictionary<long, PolicyDocument> releases = new();

    async Task<PolicyDocument?> Release(Transaction tx, long version)
    {
        if (releases.TryGetValue(version, out var cached))
            return cached;
        var release = await tx.GetRelease(version);
        return release == null ? null : releases[version] = Wire.Read<PolicyDocument>(release.Payload);
    }

    /// <summary>Judges <paramref name="d"/> (which must include its snapshot) now; stores nothing.</summary>
    internal async Task<(StoredVerdict Verdict, ComplianceReport? Report)> Evaluate(Transaction tx, DeviceRecord d)
    {
        var policy = await Release(tx, d.TargetPolicyVersion) ?? throw new ApiError(409, "Assigned policy unavailable");
        var report = d.Snapshot == null ? null : ReportEngine.Evaluate(policy, d.Snapshot, Now);
        var historical = d.Snapshot == null ? null : await Release(tx, d.Snapshot.PolicyVersion);
        var last =
            d.Snapshot == null || historical == null
                ? null
                : ReportEngine.Evaluate(historical, d.Snapshot, d.Snapshot.CollectedAt);
        return (
            new StoredVerdict(
                report?.Verdict,
                last?.Verdict,
                d.Snapshot?.CollectedAt,
                policy.Version,
                policy.PolicyId,
                report?.ProtectionStatus ?? "未取得检查结果",
                report?.ViolationCount ?? 0,
                d.Snapshot?.Simulated ?? false,
                d.SnapshotSequence,
                d.TargetPolicyVersion,
                Now,
                report?.ValidUntil
            ),
            report
        );
    }

    /// <summary>The stored verdict while it holds, otherwise a new evaluation (read-only: nothing is stored).</summary>
    async Task<StoredVerdict> CurrentVerdict(Transaction tx, DeviceRecord d)
    {
        if (d.Verdict is { } v && v.HoldsFor(d, Now))
            return v;
        // A device head leaves out the snapshot the evaluation needs.
        var full = d.Snapshot == null && d.SnapshotSequence > 0 ? await tx.RequireDevice(d.Id) : d;
        return (await Evaluate(tx, full)).Verdict;
    }

    /// <summary>The verdict combined with the device's online state, which comes from the record now.</summary>
    DeviceSummary Summary(DeviceRecord d, StoredVerdict v)
    {
        var online = Online(d);
        return new(
            d.Id,
            d.HostName,
            d.LastHeartbeat,
            online,
            online == "Online" ? v.Current ?? Verdict.UNKNOWN : Verdict.UNKNOWN,
            v.Last,
            v.CollectedAt,
            v.PolicyVersion,
            d.AppliedPolicyVersion == v.TargetPolicyVersion,
            v.ProtectionStatus,
            v.ViolationCount,
            v.Simulated,
            d.Note,
            v.PolicyName,
            d.AgentVersion,
            ReleaseVersion.Older(d.AgentVersion, ComplianceService.Version),
            d.Network,
            d.SourceAddress,
            ReleaseVersion.Unsupported(d.AgentVersion),
            d.ArchivedAt
        );
    }

    public async Task<DeviceSummary> Summary(Transaction tx, DeviceRecord d) => Summary(d, await CurrentVerdict(tx, d));

    /// <summary>
    /// Every device in use (or every archived one) from its stored verdict. The few whose stored verdict no longer holds (a new snapshot or policy the
    /// background refresh has not reached yet, or data that just went stale) are evaluated here, a few hundred
    /// snapshots per query, without storing anything: administrators' pages poll this and must not write.
    /// </summary>
    public async Task<List<DeviceSummary>> Summaries(Transaction tx, bool archived = false)
    {
        var heads = await tx.DeviceHeads(archived);
        var now = Now;
        var evaluated = new Dictionary<string, DeviceSummary>();
        foreach (
            var chunk in heads.Where(h => h.Verdict is not { } v || !v.HoldsFor(h, now)).Select(h => h.Id).Chunk(200)
        )
        foreach (var full in await tx.GetDevices(chunk))
            evaluated[full.Id] = Summary(full, (await Evaluate(tx, full)).Verdict);
        return heads
            .Select(h => evaluated.GetValueOrDefault(h.Id) ?? (h.Verdict is { } v ? Summary(h, v) : null))
            .OfType<DeviceSummary>()
            .ToList();
    }

    /// <summary>
    /// Stores <paramref name="v"/> for <paramref name="d"/> (as read in this transaction, with its stored verdict) and
    /// records a history entry when the verdict differs from the stored one. Returns 1 if stored.
    /// </summary>
    internal async Task<int> StoreVerdict(Transaction tx, DeviceRecord d, StoredVerdict v)
    {
        if (await tx.SaveVerdict(d.Id, v) == 0)
            return 0;
        var verdict = v.Current ?? Verdict.UNKNOWN;
        if (d.Verdict is null || (d.Verdict.Current ?? Verdict.UNKNOWN) != verdict)
            await tx.InsertVerdictChange(new VerdictChange(d.Id, Now, verdict, v.ViolationCount, v.PolicyVersion));
        return 1;
    }

    /// <summary>Changes kept for history and trends; each device's latest change is kept regardless.</summary>
    public static readonly TimeSpan VerdictHistoryRetention = TimeSpan.FromDays(400);

    /// <summary>
    /// Stores a new verdict for every device whose stored one no longer holds, a few hundred per transaction. Run in
    /// the background, so that lists find stored verdicts; returns how many were stored.
    /// </summary>
    public async Task<int> RefreshVerdicts(CancellationToken ct = default)
    {
        var total = 0;
        int found;
        do
        {
            ct.ThrowIfCancellationRequested();
            found = await Tx(async tx =>
            {
                var ids = await tx.DevicesWithStaleVerdicts(Now, 200);
                // Locked in id order, like every refresh, so that two servers refreshing at once neither deadlock nor
                // record the same change twice; a snapshot arriving meanwhile waits and stores its own.
                foreach (var id in ids)
                {
                    await tx.Lock(ComplianceService.DeviceLock(id));
                    if (await tx.GetDevice(id) is { } d)
                        total += await StoreVerdict(tx, d, (await Evaluate(tx, d)).Verdict);
                }
                return ids.Count;
            });
        } while (found == 200);
        return total;
    }

    /// <summary>Every device in use evaluated now, with the reasons behind its verdict, for the exported device list.</summary>
    public async Task<List<(DeviceSummary Device, string[] Reasons)>> Export(Transaction tx)
    {
        var rows = new List<(DeviceSummary, string[])>();
        // A few hundred snapshots at a time keeps memory bounded without a query per device.
        foreach (var chunk in (await tx.DeviceHeads()).Select(h => h.Id).Chunk(200))
        foreach (var d in await tx.GetDevices(chunk))
        {
            var (v, report) = await Evaluate(tx, d);
            rows.Add((Summary(d, v), report?.Reasons ?? []));
        }
        return rows;
    }
}
