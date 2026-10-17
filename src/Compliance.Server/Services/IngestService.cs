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
            await verdicts.StoreVerdict(tx, d, (await verdicts.Evaluate(tx, d)).Verdict);
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
        var policy = Wire.Read<PolicyDocument>((await policies.AssignedPolicy(tx, device)).Payload);
        var report = ReportEngine.Evaluate(policy, snapshot, Now);
        await SensitiveFileAlerts(tx, device, policy, sequence);
        // Sensitive files get one alert per file from SensitiveFileAlerts, also when their rule makes the device fail.
        // The report says which evidence fails the device; judging each piece again in a snapshot of its own gave
        // the same answer at the cost of a whole evaluation per piece.
        var confirmed = report
            .ConfirmedEvidence.Select(i => snapshot.Evidence[i])
            .Where(e => e.Kind != EvidenceKind.SensitiveFile)
            .ToArray();

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
}
