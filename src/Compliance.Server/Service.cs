using System.Security.Cryptography;
using Compliance.Core;

namespace Compliance.Server;

public sealed class ComplianceService(Store store, Settings settings, TimeProvider clock) : IDisposable
{
    readonly ECDsa signer = ECDsa.Create();

    public string PublicKey => signer.ExportSubjectPublicKeyInfoPem();
    public string KeyId => Secrets.Hash(PublicKey)[..16];
    public DateTimeOffset Now => clock.GetUtcNow();

    public static string DeviceLock(string deviceId) => "device:" + deviceId;

    public const string PolicyLock = "policy";
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
                    IssuedAt = Now,
                    ExpiresAt = Now + PolicyValidity,
                };
                await tx.InsertRelease(1, PolicyCrypto.Sign(doc, signer, KeyId), Now);
                await tx.Audit("bootstrap", "SeedAuditPolicy", "1", Now);
            }
            return true;
        });
    }

    public Task<T> Tx<T>(Func<Transaction, Task<T>> action) => store.Transaction(action);

    public async Task<DeviceRecord> Device(Transaction tx, string id) =>
        await tx.GetDevice(id) ?? throw new ApiError(404, "Device not found");

    public string Online(DeviceRecord device)
    {
        if (device.LastHeartbeat is null || Now - device.LastHeartbeat >= TimeSpan.FromMinutes(5))
            return "Offline";
        return Now - device.LastHeartbeat >= TimeSpan.FromMinutes(3) ? "SuspectedOffline" : "Online";
    }

    public async Task<SignedPolicy> CurrentRelease(Transaction tx) =>
        await tx.CurrentRelease()
        ?? throw new InvalidOperationException("No policy release; database was not initialized");

    public async Task<PolicyDocument> Current(Transaction tx) =>
        Wire.Read<PolicyDocument>((await CurrentRelease(tx)).Payload);

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

    public async Task<DeviceSummary> Summary(Transaction tx, DeviceRecord d)
    {
        var policy = Wire.Read<PolicyDocument>((await AssignedPolicy(tx, d)).Payload);
        var report = d.Snapshot == null ? null : ReportEngine.Evaluate(policy, d.Snapshot, Now);
        var historicalPolicy = d.Snapshot == null ? null : await tx.GetRelease(d.Snapshot.PolicyVersion);
        var last =
            d.Snapshot == null || historicalPolicy == null
                ? null
                : ReportEngine.Evaluate(
                    Wire.Read<PolicyDocument>(historicalPolicy.Payload),
                    d.Snapshot,
                    d.Snapshot.CollectedAt
                );
        var online = Online(d);
        return new(
            d.Id,
            d.HostName,
            d.LastHeartbeat,
            online,
            online == "Online" ? report?.Verdict ?? Verdict.UNKNOWN : Verdict.UNKNOWN,
            last?.Verdict,
            d.Snapshot?.CollectedAt,
            policy.Version,
            d.AppliedPolicyVersion,
            report?.ProtectionStatus ?? "未取得检查结果",
            report?.ViolationCount ?? 0,
            d.Snapshot?.Simulated ?? false
        );
    }

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

        await tx.Lock(DeviceLock(deviceId));
        var d = await Device(tx, deviceId);
        var accepted = new HashSet<string>();
        var snapshotChanged = false;

        foreach (var e in batch.Events)
        {
            Validate(deviceId, e);

            var fingerprint = Secrets.Hash(Wire.Serialize(e));
            var existing = await tx.GetEventFingerprint(deviceId, e.EventId);
            if (existing != null)
            {
                if (existing != fingerprint)
                    throw new ApiError(409, "Event id already has different content");
                accepted.Add(e.EventId);
                continue;
            }
            if (await tx.SequenceUsed(deviceId, e.Sequence))
                throw new ApiError(409, "Sequence already belongs to a different event");

            var safe = e with
            {
                ObjectKey = EvidenceSanitizer.Clean(e.ObjectKey),
                Detail = e.Detail is null ? null : EvidenceSanitizer.Clean(e.Detail),
                Snapshot = e.Snapshot is null ? null : EvidenceSanitizer.Sanitize(e.Snapshot),
            };
            await tx.InsertEvent(deviceId, new StoredEvent(fingerprint, safe, Now));
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
                d = d with { Snapshot = EvidenceSanitizer.Sanitize(snapshot), SnapshotSequence = e.Sequence };
                snapshotChanged = true;
                await SnapshotAlerts(tx, d, e.Sequence);
            }

            if (e.Type != "Snapshot")
            {
                var incidentId = deviceId + ":" + Secrets.Hash(e.ObjectKey);
                var alert = await tx.GetAlert(incidentId);
                if (alert == null || e.Sequence > alert.LastSequence)
                {
                    var type = e.Type == "Recovered" ? alert?.Type ?? "Violation" : e.Type;
                    await tx.UpsertAlert(
                        new AlertSummary(
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
            await tx.UpdateSnapshot(deviceId, d.Snapshot!, d.SnapshotSequence);
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

        var present = new HashSet<string>();
        foreach (var group in confirmed.GroupBy(ObjectId))
        {
            var id = "snapshot:" + device.Id + ":" + Secrets.Hash(group.Key);
            present.Add(id);
            var previous = await tx.GetAlert(id);
            if (previous != null && previous.LastSequence >= sequence)
                continue;

            var oldMetadata = await tx.GetSnapshotIncident(id);
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
            var metadata in (await tx.SnapshotIncidents(device.Id)).Where(x =>
                !present.Contains(x.Id) && !x.Modules.Contains(SensitiveFiles.Module)
            )
        )
        {
            var previous = await tx.GetAlert(metadata.Id);
            if (previous == null || previous.LastSequence >= sequence)
                continue;
            var complete = metadata.Modules.All(module =>
                snapshot.Modules.Any(m =>
                    m.Module == module
                    && m.Scope == metadata.Scope
                    && m.Status == "Complete"
                    && m.CollectedAt
                        >= Now.AddMinutes(
                            -(
                                module is "installed" or "appx" or "extensions"
                                    ? policy.InventoryFreshMinutes
                                    : policy.LightweightFreshMinutes
                            )
                        )
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
            var previous = await tx.GetAlert(id);
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
            var metadata in (await tx.SnapshotIncidents(device.Id)).Where(x =>
                !present.Contains(x.Id) && x.Modules.Contains(SensitiveFiles.Module)
            )
        )
        {
            var previous = await tx.GetAlert(metadata.Id);
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

    public async Task<SignedPolicy> Publish(Transaction tx, PolicyDocument? submitted)
    {
        if (submitted == null)
            throw new ApiError(400, "策略内容为空");
        var current = await Current(tx);
        var doc = submitted with
        {
            SchemaVersion = 1,
            Version = current.Version + 1,
            IssuedAt = Now,
            ExpiresAt = Now + PolicyValidity,
            DenyInstalled = true,
            DenyProxy = true,
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
        await ValidateEnforcement(tx, doc, current);
        var signed = Sign(doc);
        await tx.InsertRelease(doc.Version, signed, Now);
        await tx.AssignPolicy(doc.Version, doc.TargetDeviceIds);
        return signed;
    }

    async Task ValidateEnforcement(Transaction tx, PolicyDocument doc, PolicyDocument current)
    {
        if (doc.Mode != "Enforce")
            return;

        if (doc.TargetDeviceIds.Length == 0 || doc.RequiredControls.Length == 0)
            throw new ApiError(409, "强制模式需要指定试点终端，并选择至少一项防护措施");
        foreach (var id in doc.TargetDeviceIds)
        {
            var d = await Device(tx, id);
            if (
                Online(d) != "Online"
                || d.Snapshot == null
                || d.Snapshot.Simulated
                || d.Snapshot.CollectedAt < Now.AddMinutes(-10)
            )
                throw new ApiError(409, "试点终端需要在线，且 10 分钟内有真实（非模拟）的检查结果");
            foreach (var control in doc.RequiredControls)
            {
                var c = d.Controls?.FirstOrDefault(x => x.Id == control);
                if (
                    c == null
                    || !c.Verified
                    || c.RebootRequired
                    || c.Version != current.Version
                    || c.State is not ("Applied" or "Verified")
                )
                    throw new ApiError(409, "试点终端尚未验证所需的防护措施，请先在审计模式下确认防护措施已生效");
            }
        }
        if (doc.RequiredControls.Contains("network"))
            throw new ApiError(409, "暂不支持强制启用“网络访问拦截”");
        if (doc.ApplicationRules.Length == 0 || doc.BlockDomains.Length > 1000)
            throw new ApiError(409, "强制模式需要至少一条应用程序拦截规则，禁止访问的域名不能超过 1000 项");
    }

    public SignedPolicy Sign(PolicyDocument doc) => PolicyCrypto.Sign(doc, signer, KeyId);

    public void Dispose() => signer.Dispose();
}

public sealed class OfflineMonitor(ComplianceService service, ILogger<OfflineMonitor> logger) : BackgroundService
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
        }
    }
}
