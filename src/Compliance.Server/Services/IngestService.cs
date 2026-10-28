using Compliance.Core;

namespace Compliance.Server;

/// <summary>Accepts agents' event batches: stores events and snapshots, and opens or resolves the alerts they imply.</summary>
public sealed class IngestService(VerdictService verdicts, PolicyService policies, TimeProvider clock)
{
    DateTimeOffset Now => clock.GetUtcNow();

    public async Task<EventReceipt> Events(Transaction tx, string deviceId, EventBatch batch)
    {
        if (batch.Events is null || batch.Events.Length is 0 or > 500 || batch.Events.Any(e => e is null))
            throw new ApiError(400, "Batch requires 1..500 events");

        foreach (var e in batch.Events)
            Validate(deviceId, e);

        await tx.Lock(ComplianceService.DeviceLock(deviceId));
        var d = await tx.RequireDevice(deviceId);
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

            if (UsbStorage.EventTypes.Contains(e.Type))
            {
                var key = safe.ObjectKey;
                await tx.InsertUsbEvent(
                    deviceId + ":" + e.EventId,
                    deviceId,
                    e.SourceTime,
                    e.Type,
                    key.StartsWith(UsbStorage.KeyPrefix, StringComparison.Ordinal)
                        ? key[UsbStorage.KeyPrefix.Length..]
                        : key,
                    safe.Detail ?? ""
                );
            }

            // Disks plugged in and removed are records, not alerts; a blocked one is both.
            if (e.Type is UsbStorage.Connected or UsbStorage.Removed) { }
            else if (e.Type == "Shutdown")
            {
                // Not an alert: the device says it is off, so going silent is expected. Server time, as heartbeats.
                await tx.SetShutdown(deviceId, Now);
                d = d with { ShutdownAt = Now };
            }
            else if (e.Type != "Snapshot")
            {
                // A request for an exception is kept for approval, and its alert says what was asked in words.
                var detail =
                    e.Type == PolicyExceptions.RequestEvent ? await ExceptionRequest(tx, d, e) : safe.Detail ?? e.Type;
                if (detail is null)
                    continue;
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
                            detail,
                            e.Type == "Recovered" ? "Resolved" : "Active",
                            e.Sequence,
                            alert?.FirstSeen ?? e.SourceTime,
                            e.SourceTime,
                            // Like snapshot alerts: an acknowledgment holds while the alert stays active, and a
                            // recurrence after recovery has to be acknowledged again.
                            alert is { State: "Active", Acknowledged: true }
                        )
                    );
                }
            }
        }

        if (snapshotChanged)
        {
            await tx.UpdateSnapshot(deviceId, d.Snapshot!, d.SnapshotSequence);
            await verdicts.StoreVerdict(tx, d, (await verdicts.Evaluate(tx, d)).Verdict);
        }
        return new(accepted.ToArray());
    }

    /// <summary>
    /// Keeps a request for an exception: a new pending one, or the pending one for the same thing updated. Returns
    /// the alert's text, or null when the request is not one (an old or broken client), which raises no alert.
    /// </summary>
    async Task<string?> ExceptionRequest(Transaction tx, DeviceRecord d, AgentEvent e)
    {
        ExceptionRequest? asked;
        try
        {
            asked = PolicyExceptions.Check(Wire.Read<ExceptionRequest>(e.Detail ?? ""));
        }
        catch (System.Text.Json.JsonException)
        {
            asked = null;
        }
        if (asked is null)
            return null;
        var r = asked with
        {
            Label = EvidenceSanitizer.Clean(asked.Label),
            Reason = EvidenceSanitizer.Clean(asked.Reason),
            User = EvidenceSanitizer.Clean(asked.User),
        };
        var label = r.Label.Length > 0 ? r.Label : r.Target;
        if (await tx.PendingException(d.Id, r.Kind, r.Target) is { } pending)
            await tx.RenewPendingException(pending.Id, r.Reason, r.Days, r.User, e.SourceTime);
        else
            await tx.InsertException(
                new StoredException(
                    "r-" + Secrets.Hash(d.Id + ":" + e.EventId)[..24],
                    d.Id,
                    d.HostName,
                    "",
                    "",
                    r.Kind,
                    r.Target,
                    label,
                    r.Reason,
                    r.Days,
                    r.User,
                    e.SourceTime,
                    PolicyExceptions.Pending,
                    "",
                    null,
                    null,
                    "",
                    e.ObjectKey
                )
            );
        return $"{r.User} 申请{PolicyExceptions.KindLabel(r.Kind)}：{label}，{r.Days} 天。理由：{r.Reason}";
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
            || e.Type
                is not (
                    "Snapshot"
                    or "Violation"
                    or "Recovered"
                    or "Health"
                    or "BlockedAttempt"
                    or "Tamper"
                    or "Shutdown"
                    or UsbStorage.Connected
                    or UsbStorage.Removed
                    or UsbStorage.Blocked
                    or PolicyExceptions.RequestEvent
                )
        )
            throw new ApiError(400, "Invalid event");
        if (e.Type == "Snapshot" && e.Snapshot == null)
            throw new ApiError(400, "Snapshot event needs snapshot");
        if (
            e.Snapshot is { } s
            && (
                s.SchemaVersion != Wire.SchemaVersion
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
        var policy = Wire.Read<PolicyDocument>((await policies.AssignedPolicy(tx, device)).Payload);
        var report = ReportEngine.Evaluate(policy, snapshot, Now);
        await SensitiveFileAlerts(tx, device, policy, sequence);
        await BaselineAlerts(tx, device, policy, sequence);
        // Sensitive files get one alert per file from SensitiveFileAlerts, and baseline checks one per finding from
        // BaselineAlerts, also when their rule makes the device fail.
        // The report says which evidence fails the device; judging each piece again in a snapshot of its own gave
        // the same answer at the cost of a whole evaluation per piece.
        var confirmed = report
            .ConfirmedEvidence.Select(i => snapshot.Evidence[i])
            .Where(e => e.Kind is not (EvidenceKind.SensitiveFile or EvidenceKind.Baseline))
            .ToArray();

        string ObjectId(Evidence e) =>
            e.ProductId + "|" + (e.UserSid ?? "machine") + (e.Kind == EvidenceKind.Proxy ? "|" + e.ObjectKey : "");
        // The module that found a piece of evidence, from the prefix every collector gives its object keys; recovery
        // waits for that module to check again.
        static string Module(Evidence e) =>
            e.ObjectKey.Split(':')[0] switch
            {
                "uninstall" => "installed",
                "install-dir" => "installed-paths",
                "service" => "services",
                "program" => "programs",
                "ide" or "jetbrains" => "extensions",
                "npm" or "pip" or "cli-file" or "cli-shim" => "cli",
                "appx" => "appx",
                "proxy" or "pac" => "proxy",
                "env" => "proxy-env",
                "connection-settings" => "proxy-advanced",
                "pid" => "processes",
                "tcp" => "ports",
                _ => e.Kind switch
                {
                    EvidenceKind.Installation => "installed",
                    EvidenceKind.Extension => "extensions",
                    EvidenceKind.Proxy => "proxy",
                    _ => "processes",
                },
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
                !present.Contains(x.Id) && !x.Modules.Any(m => m == SensitiveFiles.Module || Baseline.IsModule(m))
            )
        )
        {
            var previous = alerts.GetValueOrDefault(metadata.Id);
            if (previous == null || previous.LastSequence >= sequence)
                continue;
            // Modules the policy no longer runs cannot check again. The whole-drive scan reports per drive rather than
            // per user, so a module without a result for the alert's scope needs all of its results complete.
            var complete = metadata
                .Modules.Where(policy.RequiredModules.Contains)
                .All(module =>
                {
                    var results = snapshot.Modules.Where(m => m.Module == module).ToArray();
                    var scoped = results.Where(m => m.Scope == metadata.Scope).ToArray();
                    var relevant = scoped.Length > 0 ? scoped : results;
                    return relevant.Length > 0
                        && relevant.All(m =>
                            m.Status == "Complete"
                            && m.CollectedAt >= Now.AddMinutes(-policy.FreshMinutes(module))
                            && m.CollectedAt <= Now.AddMinutes(2)
                        );
                });
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
    /// One alert per baseline finding (a check, and the user or account it names), for administrators: "Alert" rules
    /// raise a Baseline alert and "Violation" rules a Violation alert. An alert resolves when a complete, fresh run
    /// of its check after the alert no longer reports it, or when the check is no longer enabled.
    /// </summary>
    async Task BaselineAlerts(Transaction tx, DeviceRecord device, PolicyDocument policy, long sequence)
    {
        var snapshot = device.Snapshot!;
        var fresh = Now.AddMinutes(-policy.InventoryFreshMinutes);
        DateTimeOffset Collected(Evidence e) =>
            e.CollectedAt
            ?? snapshot.Modules.FirstOrDefault(m => m.Module == Baseline.Module(e.ProductId))?.CollectedAt
            ?? snapshot.CollectedAt;
        var alerts = await tx.DeviceAlerts(device.Id);
        var incidents = await tx.SnapshotIncidents(device.Id);
        var present = new HashSet<string>();
        foreach (
            var e in snapshot.Evidence.Where(e =>
                e.Kind == EvidenceKind.Baseline
                && e.Confirmed
                && Baseline.Rule(policy, e.ProductId) is not null
                && Collected(e) >= fresh
            )
        )
        {
            var id = "baseline:" + device.Id + ":" + Secrets.Hash(e.ObjectKey);
            if (!present.Add(id))
                continue;
            var previous = alerts.GetValueOrDefault(id);
            if (previous != null && previous.LastSequence >= sequence)
                continue;
            var module = Baseline.Module(e.ProductId);
            await tx.PutSnapshotIncident(new SnapshotIncident(id, device.Id, e.UserSid ?? "machine", [module]));
            var seen = Collected(e);
            await tx.UpsertAlert(
                new AlertSummary(
                    id,
                    device.Id,
                    device.HostName,
                    Baseline.Rule(policy, e.ProductId)!.Action == "Violation" ? "Violation" : "Baseline",
                    e.ObjectKey,
                    e.ProductName + "：" + e.Summary,
                    "Active",
                    sequence,
                    previous?.State == "Active" ? previous.FirstSeen : seen,
                    seen,
                    previous?.State == "Active" && previous.Acknowledged
                )
            );
        }

        foreach (var metadata in incidents.Where(x => !present.Contains(x.Id) && x.Modules.Any(Baseline.IsModule)))
        {
            var previous = alerts.GetValueOrDefault(metadata.Id);
            if (previous == null || previous.State != "Active" || previous.LastSequence >= sequence)
                continue;
            var module = metadata.Modules.First(Baseline.IsModule);
            var checkedAgain = snapshot.Modules.Any(m =>
                m.Module == module
                && m.Status == "Complete"
                && m.CollectedAt >= fresh
                && m.CollectedAt > previous.LastSeen
                && m.CollectedAt <= Now.AddMinutes(2)
            );
            if (!Baseline.Runs(policy, module) || checkedAgain)
            {
                await tx.UpsertAlert(previous with { State = "Resolved", LastSeen = Now, LastSequence = sequence });
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
}
