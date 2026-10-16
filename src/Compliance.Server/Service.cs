using System.Collections.Concurrent;
using System.Security.Cryptography;
using Compliance.Core;

namespace Compliance.Server;

public sealed class ComplianceService(Store store, Settings settings, TimeProvider clock) : IDisposable
{
    readonly ECDsa signer = ECDsa.Create();

    public string PublicKey => signer.ExportSubjectPublicKeyInfoPem();
    public string KeyId => Secrets.Hash(PublicKey)[..16];
    public DateTimeOffset Now => clock.GetUtcNow();

    /// <summary>How long a management session may go without the administrator using the page; null if unlimited.</summary>
    public TimeSpan? SessionIdle =>
        settings.SessionIdleMinutes > 0 ? TimeSpan.FromMinutes(settings.SessionIdleMinutes) : null;

    /// <summary>This server's release version; clients of the same release report the same one.</summary>
    public static readonly string Version = ReleaseVersion.Of(typeof(ComplianceService).Assembly);

    public static string DeviceLock(string deviceId) => "device:" + deviceId;

    /// <summary>
    /// Held by everything that publishes or reassigns policies, and by enrollment. Taken after "bootstrap" and
    /// <see cref="EnrollmentLock"/>, never before them.
    /// </summary>
    public const string PolicyLock = "policy";
    public const string DefaultPolicy = "default";

    /// <summary>Names the default policy had in earlier versions; renamed to "Default" at startup.</summary>
    static readonly string[] LegacyDefaultNames = ["customer-no-foreign-ai", "endpoint-compliance"];
    public const string EnrollmentLock = "enrollment";

    public async Task Initialize()
    {
        await store.Initialize();
        if (string.IsNullOrWhiteSpace(settings.SigningKeyPath))
            throw new InvalidOperationException("Configure a durable Compliance:SigningKeyPath");

        var keyPath = Path.GetFullPath(settings.SigningKeyPath);
        Directory.CreateDirectory(Path.GetDirectoryName(keyPath)!);
        if (!File.Exists(keyPath))
        {
            using var created = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
            if (!OperatingSystem.IsWindows())
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using var stream = new FileStream(keyPath, options);
            using var writer = new StreamWriter(stream);
            writer.Write(created.ExportECPrivateKeyPem());
        }
        signer.ImportFromPem(await File.ReadAllTextAsync(keyPath));

        await store.Transaction(async tx =>
        {
            await tx.Lock("bootstrap");
            // Renaming the legacy default reassigns devices, like a publish.
            await tx.Lock(PolicyLock);
            foreach (var user in Wire.Read<BootstrapUser[]>(settings.BootstrapUsers))
            {
                if (
                    string.IsNullOrWhiteSpace(user.Username)
                    || user.Username.Length > 100
                    || user.Password.Length < 16
                    || user.Roles.Length == 0
                    || user.Roles.Any(r => r is not ("Reader" or "Operator" or "Publisher" or "Reviewer"))
                )
                    throw new InvalidOperationException(
                        "Bootstrap users need names, >=16 character passwords and defined roles"
                    );
                if (await tx.GetUser(user.Username) == null)
                {
                    await tx.InsertUser(new UserRecord(user.Username, Secrets.Password(user.Password), user.Roles));
                    await tx.Audit("bootstrap", "CreateUser", user.Username, Now);
                }
            }

            var current = await tx.CurrentRelease();
            if (current != null && current.KeyId != KeyId)
                throw new InvalidOperationException(
                    "Configured signing key does not match persisted policy; restore original key"
                );
            if (current == null)
            {
                var doc = PolicySeed.Create() with
                {
                    Mode = "Audit",
                    Version = 1,
                    Sequence = 1,
                    IssuedAt = Now,
                    ExpiresAt = Now + PolicyValidity,
                };
                await tx.InsertRelease(1, PolicyCrypto.Sign(doc, signer, KeyId), Now);
                await tx.Audit("bootstrap", "SeedAuditPolicy", "1", Now);
            }
            else
                await RenameLegacyDefault(tx);
            return true;
        });
    }

    public Task<T> Tx<T>(Func<Transaction, Task<T>> action) => store.Transaction(action);

    public async Task<DeviceRecord> Device(Transaction tx, string id) =>
        await tx.GetDevice(id) ?? throw new ApiError(404, "Device not found");

    /// <summary>A device without its controls and snapshot, for requests that need neither.</summary>
    public async Task<DeviceRecord> DeviceHead(Transaction tx, string id) =>
        await tx.GetDeviceHead(id) ?? throw new ApiError(404, "Device not found");

    public string Online(DeviceRecord device)
    {
        if (device.LastHeartbeat is null || Now - device.LastHeartbeat >= TimeSpan.FromMinutes(5))
            return "Offline";
        return Now - device.LastHeartbeat >= TimeSpan.FromMinutes(3) ? "SuspectedOffline" : "Online";
    }

    public sealed record PolicyState(string Key, SignedPolicy Release, PolicyDocument Document)
    {
        public bool IsDefault => Key == DefaultPolicy;
    }

    public async Task<List<PolicyState>> Policies(Transaction tx) =>
        (await tx.LatestReleases())
            .Select(r => new PolicyState(r.Key, r.Release, Wire.Read<PolicyDocument>(r.Release.Payload)))
            .OrderBy(p => p.IsDefault ? 0 : 1)
            .ThenBy(p => p.Document.PolicyId, StringComparer.CurrentCultureIgnoreCase)
            .ToList();

    /// <summary>The default policy's newest release: it applies to every device no other policy names.</summary>
    public async Task<SignedPolicy> CurrentRelease(Transaction tx) =>
        (await Policies(tx)).FirstOrDefault(p => p.IsDefault)?.Release
        ?? throw new InvalidOperationException("No policy release; database was not initialized");

    /// <summary>A device follows the named policy that lists it, otherwise the default policy.</summary>
    public static PolicyState PolicyFor(string deviceId, List<PolicyState> policies) =>
        policies.FirstOrDefault(p => !p.IsDefault && p.Document.TargetDeviceIds.Contains(deviceId))
        ?? policies.First(p => p.IsDefault);

    /// <summary>
    /// Points every device at the newest release of its policy. Agents refuse a lower serial than they hold, so a
    /// policy that devices move to from a newer release is first re-issued under a new serial; its own version, which
    /// administrators see, stays the same since its content does.
    /// </summary>
    async Task Reassign(Transaction tx)
    {
        var policies = await Policies(tx);
        var devices = await tx.AllDeviceHeads();
        foreach (
            var stale in policies
                .Where(p =>
                    devices.Any(d => d.TargetPolicyVersion > p.Document.Serial && PolicyFor(d.Id, policies) == p)
                )
                .ToList()
        )
        {
            var doc = stale.Document with
            {
                Sequence = await NextSerial(tx),
                IssuedAt = Now,
                ExpiresAt = Now + PolicyValidity,
            };
            await tx.InsertRelease(doc.Serial, Sign(doc), Now, stale.Key);
            await tx.Audit("system", "ReissuePolicy", $"{doc.PolicyId} v{doc.Version}", Now);
        }
        policies = await Policies(tx);
        foreach (var d in devices)
        {
            var serial = PolicyFor(d.Id, policies).Document.Serial;
            if (d.TargetPolicyVersion != serial)
                await tx.SetTargetPolicy(d.Id, serial);
        }
    }

    /// <summary>Releases are stored under their serial, so the newest release overall holds the highest.</summary>
    async Task<long> NextSerial(Transaction tx) =>
        Wire.Read<PolicyDocument>((await tx.CurrentRelease())!.Payload).Serial + 1;

    async Task RenameLegacyDefault(Transaction tx)
    {
        var current = (await Policies(tx)).FirstOrDefault(p => p.IsDefault)?.Document;
        // A legacy release limited to pilot devices keeps its name until an administrator republishes it.
        if (
            current == null
            || !LegacyDefaultNames.Contains(current.PolicyId)
            || current.TargetDeviceIds.Length > 0
            || current.Mode != "Audit"
        )
            return;
        var doc = current with
        {
            PolicyId = "Default",
            Version = current.Version + 1,
            Sequence = await NextSerial(tx),
            IssuedAt = Now,
            ExpiresAt = Now + PolicyValidity,
        };
        await tx.InsertRelease(doc.Serial, Sign(doc), Now);
        await tx.Audit("bootstrap", "RenameDefaultPolicy", "v" + doc.Version, Now);
        await Reassign(tx);
    }

    public async Task<SignedPolicy> AssignedPolicy(Transaction tx, DeviceRecord device) =>
        await tx.GetRelease(device.TargetPolicyVersion) ?? throw new ApiError(409, "Assigned policy unavailable");

    public async Task<ComplianceReport> Report(Transaction tx, DeviceRecord device)
    {
        if (device.Snapshot == null)
            throw new ApiError(404, "No scan available");
        var report = ReportEngine.Evaluate(
            Wire.Read<PolicyDocument>((await AssignedPolicy(tx, device)).Payload),
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
    async Task<(StoredVerdict Verdict, ComplianceReport? Report)> Evaluate(Transaction tx, DeviceRecord d)
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
        var full = d.Snapshot == null && d.SnapshotSequence > 0 ? await Device(tx, d.Id) : d;
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
            ReleaseVersion.Older(d.AgentVersion, Version),
            d.Network,
            d.SourceAddress
        );
    }

    public async Task<DeviceSummary> Summary(Transaction tx, DeviceRecord d) => Summary(d, await CurrentVerdict(tx, d));

    /// <summary>
    /// Every device from its stored verdict. The few whose stored verdict no longer holds (a new snapshot or policy the
    /// background refresh has not reached yet, or data that just went stale) are evaluated here, a few hundred
    /// snapshots per query, without storing anything: administrators' pages poll this and must not write.
    /// </summary>
    public async Task<List<DeviceSummary>> Summaries(Transaction tx)
    {
        var heads = await tx.AllDeviceHeads();
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
                foreach (var d in await tx.GetDevices(ids))
                    total += await tx.SaveVerdict(d.Id, (await Evaluate(tx, d)).Verdict);
                return ids.Count;
            });
        } while (found == 200);
        return total;
    }

    /// <summary>Every device evaluated now, with the reasons behind its verdict, for the exported device list.</summary>
    public async Task<List<(DeviceSummary Device, string[] Reasons)>> Export(Transaction tx)
    {
        var rows = new List<(DeviceSummary, string[])>();
        // A few hundred snapshots at a time keeps memory bounded without a query per device.
        foreach (var chunk in (await tx.AllDeviceHeads()).Select(h => h.Id).Chunk(200))
        foreach (var d in await tx.GetDevices(chunk))
        {
            var (v, report) = await Evaluate(tx, d);
            rows.Add((Summary(d, v), report?.Reasons ?? []));
        }
        return rows;
    }

    public static readonly TimeSpan SnapshotEventRetention = TimeSpan.FromDays(1);
    public static readonly TimeSpan ExpiredCommandRetention = TimeSpan.FromDays(30);

    /// <summary>Resolved alerts the alert list returns without paging back.</summary>
    public static readonly TimeSpan RecentlyResolved = TimeSpan.FromDays(30);
    const int PruneBatch = 2000;

    /// <summary>
    /// Removes what nothing reads any more, in short batches: snapshot events after a day (their rows only answer
    /// retries, which come within minutes), other events after <see cref="Settings.EventRetentionDays"/>, alerts
    /// resolved for <see cref="Settings.AlertRetentionDays"/>, expired sessions, commands expired for 30 days, and audit records older than the period chosen in the settings
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
        total += await Tx(tx => tx.PruneCommands(Now - ExpiredCommandRetention));
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

    public const string AuditRetentionKey = "audit-retention-days";

    /// <summary>Kept forever (0) unless an administrator chose a period; at least 180 days, as logs must be kept.</summary>
    public static readonly int[] AuditRetentionChoices = [0, 180, 365, 730, 1095];

    public static async Task<int> AuditRetentionDays(Transaction tx) =>
        int.TryParse(await tx.GetSetting(AuditRetentionKey), out var days) ? days : 0;

    /// <summary>
    /// Opens an offline alert for devices silent for 5 minutes and resolves it once they are Online again.
    /// Only devices whose state actually changes are loaded.
    /// </summary>
    public async Task UpdateOffline(Transaction tx)
    {
        await tx.Lock("offline");
        foreach (var (id, hostName) in await tx.DevicesGoingOffline(Now - TimeSpan.FromMinutes(5)))
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
            await tx.Audit("system", "Offline", id, Now);
        }
        foreach (var id in await tx.DevicesBackOnline(Now - TimeSpan.FromMinutes(3)))
        {
            await tx.ResolveAlert("offline:" + id, Now);
            await tx.Audit("system", "OnlineRecovered", id, Now);
        }
    }

    public async Task<EventReceipt> Events(Transaction tx, string deviceId, EventBatch batch)
    {
        if (batch.Events is null || batch.Events.Length is 0 or > 500 || batch.Events.Any(e => e is null))
            throw new ApiError(400, "Batch requires 1..500 events");

        foreach (var e in batch.Events)
            Validate(deviceId, e);

        await tx.Lock(DeviceLock(deviceId));
        var d = await Device(tx, deviceId);
        var accepted = new HashSet<string>();
        var snapshotChanged = false;

        // Retries and sequence clashes are looked up for the whole batch at once; events stored below join them.
        var fingerprints = await tx.EventFingerprints(deviceId, batch.Events.Select(e => e.EventId).Distinct());
        var sequences = await tx.UsedSequences(deviceId, batch.Events.Select(e => e.Sequence).Distinct());
        Dictionary<string, AlertSummary>? alerts = null;

        foreach (var e in batch.Events)
        {
            var fingerprint = Secrets.Hash(Wire.Serialize(e));
            if (fingerprints.TryGetValue(e.EventId, out var existing))
            {
                if (existing != fingerprint)
                    throw new ApiError(409, "Event id already has different content");
                accepted.Add(e.EventId);
                continue;
            }
            if (!sequences.Add(e.Sequence))
                throw new ApiError(409, "Sequence already belongs to a different event");
            fingerprints[e.EventId] = fingerprint;

            var safe = e with
            {
                ObjectKey = EvidenceSanitizer.Clean(e.ObjectKey),
                Detail = e.Detail is null ? null : EvidenceSanitizer.Clean(e.Detail),
                Snapshot = e.Snapshot is null ? null : EvidenceSanitizer.Sanitize(e.Snapshot),
            };
            // The event row only answers retries; the snapshot itself is kept on the device below.
            await tx.InsertEvent(
                deviceId,
                new StoredEvent(fingerprint, e.Type == "Snapshot" ? safe with { Snapshot = null } : safe, Now)
            );
            accepted.Add(e.EventId);

            // Current snapshot follows original collection time (sequence breaks ties), never arrival time.
            if (
                e.Snapshot is { } snapshot
                && (
                    d.Snapshot == null
                    || snapshot.CollectedAt >= d.Snapshot.CollectedAt && e.Sequence > d.SnapshotSequence
                )
            )
            {
                // Already sanitized above for the event row.
                d = d with
                {
                    Snapshot = safe.Snapshot,
                    SnapshotSequence = e.Sequence,
                };
                snapshotChanged = true;
                await SnapshotAlerts(tx, d, e.Sequence);
            }

            if (e.Type != "Snapshot")
            {
                var incidentId = deviceId + ":" + Secrets.Hash(e.ObjectKey);
                // Snapshot alerts use other ids, so this map stays current while snapshots are handled in between.
                alerts ??= await tx.DeviceAlerts(deviceId);
                var alert = alerts.GetValueOrDefault(incidentId);
                if (alert == null || e.Sequence > alert.LastSequence)
                {
                    var type = e.Type == "Recovered" ? alert?.Type ?? "Violation" : e.Type;
                    await tx.UpsertAlert(
                        alerts[incidentId] = new AlertSummary(
                            incidentId,
                            deviceId,
                            d.HostName,
                            type,
                            safe.ObjectKey,
                            safe.Detail ?? e.Type,
                            e.Type == "Recovered" ? "Resolved" : "Active",
                            e.Sequence,
                            alert?.FirstSeen ?? e.SourceTime,
                            e.SourceTime,
                            false
                        )
                    );
                }
            }
        }

        if (snapshotChanged)
        {
            await tx.UpdateSnapshot(deviceId, d.Snapshot!, d.SnapshotSequence);
            await tx.SaveVerdict(deviceId, (await Evaluate(tx, d)).Verdict);
        }
        return new(accepted.ToArray());
    }

    void Validate(string deviceId, AgentEvent e)
    {
        if (
            string.IsNullOrWhiteSpace(e.EventId)
            || e.EventId.Length > 128
            || string.IsNullOrWhiteSpace(e.ObjectKey)
            || e.ObjectKey.Length > 256
            || e.Sequence <= 0
            || e.SourceTime > Now.AddMinutes(5)
            || (e.Detail?.Length ?? 0) > 2048
            || e.Type is not ("Snapshot" or "Violation" or "Recovered" or "Health" or "BlockedAttempt")
        )
            throw new ApiError(400, "Invalid event");
        if (e.Type == "Snapshot" && e.Snapshot == null)
            throw new ApiError(400, "Snapshot event needs snapshot");
        if (
            e.Snapshot is { } s
            && (
                s.SchemaVersion != 1
                || s.DeviceId != deviceId
                || s.CollectedAt > Now.AddMinutes(5)
                || s.Evidence == null
                || s.Modules == null
                || s.Controls == null
                || s.Evidence.Length > 5000
                || s.Modules.Length > 1000
                || s.Controls.Length > 100
                || s.Evidence.Any(x => x is null)
                || s.Modules.Any(m => m is null)
                || s.Controls.Any(c => c is null)
            )
        )
            throw new ApiError(400, "Invalid snapshot");
    }

    async Task SnapshotAlerts(Transaction tx, DeviceRecord device, long sequence)
    {
        var snapshot = device.Snapshot!;
        var policy = Wire.Read<PolicyDocument>((await AssignedPolicy(tx, device)).Payload);
        var report = ReportEngine.Evaluate(policy, snapshot, Now);
        await SensitiveFileAlerts(tx, device, policy, sequence);
        // Sensitive files get one alert per file from SensitiveFileAlerts, also when their rule makes the device fail.
        var confirmed =
            report.Verdict == Verdict.FAIL
                ? snapshot
                    .Evidence.Where(e =>
                        e.Kind != EvidenceKind.SensitiveFile
                        && ReportEngine.Evaluate(policy, snapshot with { Evidence = [e] }, Now).Verdict == Verdict.FAIL
                    )
                    .ToArray()
                : [];

        string ObjectId(Evidence e) =>
            e.ProductId + "|" + (e.UserSid ?? "machine") + (e.Kind == EvidenceKind.Proxy ? "|" + e.ObjectKey : "");
        string Module(Evidence e) =>
            e.Kind switch
            {
                EvidenceKind.Installation => e.Source == "Appx" ? "appx" : "installed",
                EvidenceKind.Extension => "extensions",
                EvidenceKind.Proxy => "proxy",
                _ => "processes",
            };

        // Each alert below is read and written at most once, so one read of the device's alerts serves them all.
        var alerts = await tx.DeviceAlerts(device.Id);
        var incidents = (await tx.SnapshotIncidents(device.Id)).ToDictionary(x => x.Id);
        var present = new HashSet<string>();
        foreach (var group in confirmed.GroupBy(ObjectId))
        {
            var id = "snapshot:" + device.Id + ":" + Secrets.Hash(group.Key);
            present.Add(id);
            var previous = alerts.GetValueOrDefault(id);
            if (previous != null && previous.LastSequence >= sequence)
                continue;

            var oldMetadata = incidents.GetValueOrDefault(id);
            var modules = group.Select(Module).Concat(oldMetadata?.Modules ?? []).Distinct().ToArray();
            await tx.PutSnapshotIncident(
                new SnapshotIncident(id, device.Id, group.First().UserSid ?? "machine", modules)
            );
            await tx.UpsertAlert(
                new AlertSummary(
                    id,
                    device.Id,
                    device.HostName,
                    "Violation",
                    group.Key,
                    string.Join("；", group.Select(e => e.ProductName + ": " + e.Summary).Distinct()),
                    "Active",
                    sequence,
                    previous?.FirstSeen ?? snapshot.CollectedAt,
                    snapshot.CollectedAt,
                    previous?.State == "Active" && previous.Acknowledged
                )
            );
        }

        // Recovery needs full, fresh coverage of the incident's original scope; acknowledgment never resolves.
        if (report.CoverageGaps.Length != 0)
            return;
        foreach (
            var metadata in incidents.Values.Where(x =>
                !present.Contains(x.Id) && !x.Modules.Contains(SensitiveFiles.Module)
            )
        )
        {
            var previous = alerts.GetValueOrDefault(metadata.Id);
            if (previous == null || previous.LastSequence >= sequence)
                continue;
            var complete = metadata.Modules.All(module =>
                snapshot.Modules.Any(m =>
                    m.Module == module
                    && m.Scope == metadata.Scope
                    && m.Status == "Complete"
                    && m.CollectedAt >= Now.AddMinutes(-policy.FreshMinutes(module))
                    && m.CollectedAt <= Now.AddMinutes(2)
                )
            );
            if (complete)
            {
                await tx.UpsertAlert(
                    previous with
                    {
                        State = "Resolved",
                        LastSeen = snapshot.CollectedAt,
                        LastSequence = sequence,
                    }
                );
                if (previous.State == "Active")
                    await tx.Audit(device.Id, "SnapshotRecovered", metadata.Id, Now);
            }
        }
    }

    /// <summary>
    /// One alert per reported file or folder, for administrators only. "Alert" rules raise a SensitiveFile alert and
    /// "Violation" rules a Violation alert. An alert resolves when a complete, fresh scan of its scope no longer
    /// lists the path, or when scanning is turned off; a scan that listed only part of its hits proves nothing.
    /// </summary>
    async Task SensitiveFileAlerts(Transaction tx, DeviceRecord device, PolicyDocument policy, long sequence)
    {
        var snapshot = device.Snapshot!;
        var sensitive = policy.SensitiveFiles;
        var rules = sensitive.Enabled
            ? sensitive.Rules.ToDictionary(r => r.Id, StringComparer.Ordinal)
            : new Dictionary<string, SensitiveFileRule>();
        var fresh = Now.AddMinutes(-SensitiveFiles.FreshMinutes(policy));
        // Each alert below is read and written at most once, so one read of the device's alerts serves them all.
        var alerts = await tx.DeviceAlerts(device.Id);
        var incidents = await tx.SnapshotIncidents(device.Id);
        var present = new HashSet<string>();
        foreach (
            var e in snapshot.Evidence.Where(e =>
                e.Kind == EvidenceKind.SensitiveFile
                && rules.ContainsKey(e.ProductId)
                && (e.CollectedAt ?? snapshot.CollectedAt) >= fresh
            )
        )
        {
            var id = "sensitive:" + device.Id + ":" + Secrets.Hash(e.Source + "|" + e.ObjectKey);
            if (!present.Add(id))
                continue;
            var previous = alerts.GetValueOrDefault(id);
            if (previous != null && previous.LastSequence >= sequence)
                continue;
            await tx.PutSnapshotIncident(new SnapshotIncident(id, device.Id, e.Source, [SensitiveFiles.Module]));
            var seen = e.CollectedAt ?? snapshot.CollectedAt;
            await tx.UpsertAlert(
                new AlertSummary(
                    id,
                    device.Id,
                    device.HostName,
                    rules[e.ProductId].Action == "Violation" ? "Violation" : "SensitiveFile",
                    e.ObjectKey,
                    e.Summary + "：" + e.ObjectKey,
                    "Active",
                    sequence,
                    previous?.State == "Active" ? previous.FirstSeen : seen,
                    seen,
                    previous?.State == "Active" && previous.Acknowledged
                )
            );
        }

        foreach (
            var metadata in incidents.Where(x => !present.Contains(x.Id) && x.Modules.Contains(SensitiveFiles.Module))
        )
        {
            var previous = alerts.GetValueOrDefault(metadata.Id);
            if (previous == null || previous.State != "Active" || previous.LastSequence >= sequence)
                continue;
            var rescanned = snapshot.Modules.Any(m =>
                m.Module == SensitiveFiles.Module
                && m.Scope == metadata.Scope
                && m.Status == "Complete"
                && m.CollectedAt >= fresh
                && m.CollectedAt > previous.LastSeen
                && m.CollectedAt <= Now.AddMinutes(2)
            );
            if (!sensitive.Enabled || rescanned)
            {
                await tx.UpsertAlert(previous with { State = "Resolved", LastSeen = Now, LastSequence = sequence });
                await tx.Audit(device.Id, "SnapshotRecovered", metadata.Id, Now);
            }
        }
    }

    /// <summary>Policies stay valid this long after publishing; agents treat an expired policy as unknown.</summary>
    public static readonly TimeSpan PolicyValidity = TimeSpan.FromDays(365);

    /// <summary>
    /// Publishes a new release of the policy <paramref name="key"/>, or creates a policy when the key is null.
    /// The server owns the version and validity; the default policy always covers every other device. With
    /// <paramref name="baseVersion"/>, publishing fails with 409 when the policy has had another release since.
    /// </summary>
    public async Task<(string Key, SignedPolicy Release)> Publish(
        Transaction tx,
        string? key,
        PolicyDocument? submitted,
        long? baseVersion = null
    )
    {
        if (submitted == null)
            throw new ApiError(400, "策略内容为空");
        var policies = await Policies(tx);
        var existing =
            key == null
                ? null
                : policies.FirstOrDefault(p => p.Key == key) ?? throw new ApiError(404, "策略不存在或已删除");
        if (existing != null && baseVersion is { } based && based != existing.Document.Version)
            throw new ApiError(
                409,
                $"“{existing.Document.PolicyId}”已被他人更新为 v{existing.Document.Version}，请载入最新版本后再修改"
            );
        var isDefault = existing?.IsDefault ?? false;
        var doc = submitted with
        {
            SchemaVersion = 1,
            PolicyId = submitted.PolicyId?.Trim() ?? "",
            // Each policy counts its own releases; the serial orders releases of every policy.
            Version = (existing?.Document.Version ?? 0) + 1,
            Sequence = await NextSerial(tx),
            IssuedAt = Now,
            ExpiresAt = Now + PolicyValidity,
            DenyInstalled = true,
            DenyProxy = true,
            RequiredControls = Controls.Normalize(submitted.RequiredControls),
            // A result counts as current until two check intervals have passed.
            LightweightFreshMinutes = submitted.QuickCheckMinutes * 2,
            InventoryFreshMinutes = submitted.FullCheckMinutes * 2,
            TargetDeviceIds = isDefault ? [] : (submitted.TargetDeviceIds ?? []).Distinct().ToArray(),
        };
        if (
            doc.RequiredModules == null
            || doc.RequiredModules.Length == 0
            || doc.Products == null
            || doc.Products.Length > 5000
            || doc.BlockDomains == null
            || doc.BlockDomains.Length > 1000
            || doc.ApplicationRules == null
            || doc.ApplicationRules.Length > 1000
        )
            throw new ApiError(400, "策略不完整：至少需要一个必需检查项");
        try
        {
            PolicyCrypto.Validate(doc);
        }
        catch (ArgumentException e)
        {
            throw new ApiError(400, "策略内容无效：" + e.Message);
        }
        var others = policies.Where(p => p.Key != key).ToList();
        if (others.Any(p => string.Equals(p.Document.PolicyId, doc.PolicyId, StringComparison.OrdinalIgnoreCase)))
            throw new ApiError(409, $"已有名为“{doc.PolicyId}”的策略，请换一个名称");
        if (isDefault && doc.Mode == "Enforce")
            throw new ApiError(409, "默认策略适用于所有终端，只能使用审计模式；强制模式请新建策略并指定试点终端");
        if (!isDefault)
        {
            if (doc.TargetDeviceIds.Length == 0)
                throw new ApiError(400, "请选择这份策略适用的终端；未指定的终端使用默认策略");
            foreach (var id in doc.TargetDeviceIds)
                if (others.FirstOrDefault(p => !p.IsDefault && p.Document.TargetDeviceIds.Contains(id)) is { } taken)
                    throw new ApiError(
                        409,
                        $"终端 {(await tx.GetDevice(id))?.HostName ?? id} 已在策略“{taken.Document.PolicyId}”中，一台终端只能使用一份策略"
                    );
        }
        await ValidateEnforcement(tx, doc);
        key ??= "p-" + Guid.NewGuid().ToString("N")[..12];
        await tx.InsertPolicy(key, Now);
        var signed = Sign(doc);
        await tx.InsertRelease(doc.Serial, signed, Now, key);
        await Reassign(tx);
        return (key, signed);
    }

    /// <summary>Deletes a named policy; its devices fall back to the default policy.</summary>
    public async Task<string> DeletePolicy(Transaction tx, string key)
    {
        var policy =
            (await Policies(tx)).FirstOrDefault(p => p.Key == key) ?? throw new ApiError(404, "策略不存在或已删除");
        if (policy.IsDefault)
            throw new ApiError(409, "默认策略不能删除");
        await tx.DeletePolicy(key, Now);
        await Reassign(tx);
        return policy.Document.PolicyId;
    }

    /// <summary>
    /// Enforcement starts only on pilot devices that are online with a fresh real scan and report every required
    /// measure as ready (or already in effect) under the policy they hold now.
    /// </summary>
    async Task ValidateEnforcement(Transaction tx, PolicyDocument doc)
    {
        if (doc.Mode != "Enforce")
            return;

        if (doc.TargetDeviceIds.Length == 0 || doc.RequiredControls.Length == 0)
            throw new ApiError(409, "强制模式需要指定试点终端，并选择至少一项防护措施");
        if (doc.RequiredControls.Contains(Controls.Process) && !doc.Products.Any(p => p.ExecutableNames.Length > 0))
            throw new ApiError(409, "“发现即结束进程”需要至少一个填写了程序文件名的禁用产品");
        if (doc.RequiredControls.Contains(Controls.Browser) && doc.BlockDomains.Length == 0)
            throw new ApiError(409, "“浏览器网址拦截”需要至少一个禁止访问的域名");
        foreach (var id in doc.TargetDeviceIds)
        {
            var d = await Device(tx, id);
            if (
                Online(d) != "Online"
                || d.Snapshot == null
                || d.Snapshot.Simulated
                || d.Snapshot.CollectedAt < Now.AddMinutes(-10)
            )
                throw new ApiError(409, $"试点终端 {d.HostName} 需要在线，且 10 分钟内有真实（非模拟）的检查结果");
            foreach (var control in doc.RequiredControls)
            {
                var c = d.Controls?.FirstOrDefault(x => x.Id == control);
                if (
                    c == null
                    || !c.Verified
                    || c.RebootRequired
                    || c.Version != d.TargetPolicyVersion
                    || c.State is not ("Ready" or "Applied" or "Verified")
                )
                    throw new ApiError(
                        409,
                        $"试点终端 {d.HostName} 的“{Labels.Control(control)}”尚不可用：{c?.Detail ?? "终端未上报，请更新客户端"}"
                    );
            }
        }
    }

    public SignedPolicy Sign(PolicyDocument doc) => PolicyCrypto.Sign(doc, signer, KeyId);

    public void Dispose() => signer.Dispose();
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
                    var removed = await service.Maintain(stoppingToken);
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
                    await service.UpdateOffline(tx);
                    return true;
                });
            }
            catch (Exception e) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogError(e, "Offline status refresh failed");
            }
            try
            {
                await service.RefreshVerdicts(stoppingToken);
            }
            catch (Exception e) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogError(e, "Verdict refresh failed");
            }
        }
    }
}
