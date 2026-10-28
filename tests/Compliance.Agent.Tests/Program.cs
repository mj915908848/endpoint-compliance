using Compliance.Agent;
using Compliance.Core;

var failures = new List<string>();
async Task Check(string name, Func<Task> test)
{
    try
    {
        await test();
        Console.WriteLine($"PASS {name}");
    }
    catch (Exception e)
    {
        failures.Add(name + ": " + e.Message);
        Console.Error.WriteLine($"FAIL {name}: {e}");
    }
}

// SQLite keeps pooled connections open after dispose; Windows cannot delete a file that is still open.
void DeleteDatabase(string path)
{
    Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
    File.Delete(path);
}
void Assert(bool value, string message)
{
    if (!value)
        throw new Exception(message);
}
T Throws<T>(Action action)
    where T : Exception
{
    try
    {
        action();
    }
    catch (T e)
    {
        return e;
    }
    throw new Exception("expected " + typeof(T).Name);
}
await Check(
    "an enrolled device never replaces a lost or damaged key, but enrolling again does",
    () =>
    {
        var dir = Path.Combine(Path.GetTempPath(), "identity-" + Guid.NewGuid().ToString("N"));
        try
        {
            var identity = new DeviceIdentity(dir, simulation: true);
            var missing = Throws<DeviceIdentityLostException>(() => identity.Load());
            Assert(missing.Message.Contains("重新登记"), "a lost key says how to recover");
            string created;
            using (var key = identity.ForEnrollment())
                created = key.ExportSubjectPublicKeyInfoPem();
            using (var key = identity.Load())
                Assert(key.ExportSubjectPublicKeyInfoPem() == created, "the enrolled key is loaded back");
            using (var key = identity.ForEnrollment())
                Assert(key.ExportSubjectPublicKeyInfoPem() == created, "enrolling again keeps a readable key");

            var file = Directory.GetFiles(dir).Single();
            File.WriteAllBytes(file, File.ReadAllBytes(file)[..10]);
            Assert(
                !identity.TryLoad(out _, out var problem) && problem!.Contains("损坏"),
                "a truncated key is reported"
            );
            Throws<DeviceIdentityLostException>(() => identity.Load());
            using (var key = identity.ForEnrollment())
                Assert(key.ExportSubjectPublicKeyInfoPem() != created, "enrolling again replaces a damaged key");
            Assert(Directory.GetFiles(dir).Length == 1, "no temporary file is left behind");
            using (identity.Load()) { }
        }
        finally
        {
            Directory.Delete(dir, true);
        }
        return Task.CompletedTask;
    }
);
await Check(
    "uninstall clears the data directory but the enrollment, which the MSI removes and restores on rollback",
    () =>
    {
        var path = Path.Combine(Path.GetTempPath(), "uninstall-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(path, "logs"));
        Directory.CreateDirectory(Path.Combine(path, "updates"));
        foreach (
            var name in new[]
            {
                "agent.json",
                "device.dpapi",
                "sensitive-files.json",
                "outbox.sqlite-wal",
                "logs/agent.log",
                "updates/x.msi",
            }
        )
            File.WriteAllText(Path.Combine(path, name), "x");
        try
        {
            var left = NativeDataDirectory.ClearForUninstall(path);
            Assert(left.Count == 0, "left: " + string.Join("; ", left));
            var names = Directory.EnumerateFileSystemEntries(path).Select(Path.GetFileName).Order().ToArray();
            Assert(names.SequenceEqual(["agent.json", "device.dpapi"]), "kept " + string.Join(", ", names));
            Assert(
                NativeDataDirectory.ClearForUninstall(Path.Combine(path, "missing")).Count == 0,
                "missing directory"
            );
        }
        finally
        {
            Directory.Delete(path, recursive: true);
        }
        return Task.CompletedTask;
    }
);
await Check(
    "an enrollment failure is described in words the person enrolling can act on",
    () =>
    {
        string Describe(Exception e) => EnrollmentFailure.Describe(e);
        Assert(
            Describe(new AgentApiException("x", System.Net.HttpStatusCode.BadRequest, null)).Contains("登记码无效"),
            "rejected code"
        );
        Assert(
            Describe(
                    new HttpRequestException(
                        "ssl",
                        new System.Security.Authentication.AuthenticationException("bad cert")
                    )
                )
                .Contains("证书"),
            "certificate"
        );
        Assert(Describe(new HttpRequestException("No such host")).Contains("无法连接管理端"), "unreachable");
        Assert(
            Describe(new InvalidOperationException("The HTTP server has not enabled trial mode")).Contains("试用模式"),
            "trial"
        );
        Assert(
            Describe(
                    new InvalidOperationException(
                        "Agent server requires HTTPS; HTTP is allowed only for explicit loopback fixture simulation"
                    )
                )
                .Contains("https://"),
            "https"
        );
        Assert(Describe(new EnrollmentRefusedException("已登记")) == "已登记", "refusal kept");
        return Task.CompletedTask;
    }
);
await Check(
    "the asset inventory lists programs as Apps & Features does and drops placeholder serial numbers",
    () =>
    {
        static AssetInventoryReader.UninstallEntry E(
            string? name,
            bool system = false,
            string? parent = null,
            string? release = null,
            string scope = "machine"
        ) => new(name, " 1.0 ", "Vendor", "20250301", system, parent, release, scope);
        var programs = AssetInventoryReader.Programs([
            E("7-Zip"),
            E("WeChat", scope: "zhangsan"),
            E(null),
            E("  "),
            E("Microsoft Visual C++ Runtime Component", system: true),
            E("Security Update for Office (KB5002)", parent: "Office16"),
            E("Hotfix", release: "Hotfix"),
        ]);
        Assert(
            programs.Select(p => p.Name).SequenceEqual(["7-Zip", "WeChat"]),
            string.Join(",", programs.Select(p => p.Name))
        );
        Assert(programs[0] is { Version: "1.0", InstalledOn: "2025-03-01", Scope: "machine" }, "fields kept");
        Assert(programs[1].Scope == "zhangsan", "per-user scope kept");
        Assert(AssetInventoryReader.SerialNumber("To be filled by O.E.M.") == "", "placeholder");
        Assert(AssetInventoryReader.SerialNumber("Default string") == "", "default string");
        Assert(AssetInventoryReader.SerialNumber("0000000") == "", "zeros");
        Assert(AssetInventoryReader.SerialNumber("PF3ABCDE") == "PF3ABCDE", "real serial");
        return Task.CompletedTask;
    }
);
await Check(
    "the network inventory reports physical adapters with reachable addresses, the gateway's first",
    () =>
    {
        static NetworkInventory.Candidate Nic(
            string name,
            string mac,
            bool gateway = false,
            string description = "Intel(R) Ethernet",
            System.Net.NetworkInformation.NetworkInterfaceType type =
                System.Net.NetworkInformation.NetworkInterfaceType.Ethernet,
            System.Net.NetworkInformation.OperationalStatus status = System.Net.NetworkInformation.OperationalStatus.Up,
            params string[] addresses
        ) =>
            new(
                name,
                description,
                type,
                status,
                Convert.FromHexString(mac),
                [.. addresses.Select(System.Net.IPAddress.Parse)],
                gateway
            );
        var picked = NetworkInventory.Select([
            Nic("WLAN", "a0b1c2d3e4f5", addresses: ["fe80::1%12", "192.168.31.20"]),
            Nic("以太网", "001122334455", gateway: true, addresses: ["fd00::5", "10.0.0.5", "169.254.3.3"]),
            Nic(
                "vEthernet (WSL)",
                "00155d000001",
                description: "Hyper-V Virtual Ethernet Adapter",
                addresses: ["172.20.0.1"]
            ),
            Nic(
                "以太网 2",
                "665544332211",
                status: System.Net.NetworkInformation.OperationalStatus.Down,
                addresses: ["10.1.1.1"]
            ),
            Nic("本地连接", "000000000000", addresses: ["10.2.2.2"]),
            Nic("未连接", "112233445566", addresses: ["fe80::9"]),
        ]);
        Assert(picked.Length == 2, "picked " + string.Join(",", picked.Select(p => p.Name)));
        Assert(picked[0] is { Name: "以太网", Mac: "00-11-22-33-44-55", Primary: true }, "gateway adapter first");
        Assert(picked[0].Addresses.SequenceEqual(["10.0.0.5", "fd00::5"]), string.Join(",", picked[0].Addresses));
        Assert(picked[1] is { Name: "WLAN", Mac: "A0-B1-C2-D3-E4-F5", Primary: false }, "wireless second");
        Assert(picked[1].Addresses.SequenceEqual(["192.168.31.20"]), "link-local dropped");
        return Task.CompletedTask;
    }
);
await Check(
    "a timed-out collector run is not started again until it ends",
    async () =>
    {
        var runs = new AbandonedRuns();
        var release = new TaskCompletionSource();
        Assert(!runs.Running("installed|machine"), "nothing abandoned yet");
        runs.Add("installed|machine", release.Task);
        Assert(runs.Running("installed|machine"), "stuck run started again");
        Assert(!runs.Running("installed|S-1-5-21-1"), "other scope blocked");
        Assert(runs.Count == 1, "abandoned count");
        release.SetResult();
        await Task.Yield();
        Assert(!runs.Running("installed|machine"), "finished run still blocks");
        Assert(runs.Count == 0, "finished run still counted");
        var failed = new TaskCompletionSource();
        runs.Add("ports|machine", failed.Task);
        failed.SetException(new IOException("late failure"));
        Assert(!runs.Running("ports|machine"), "failed run still blocks");
    }
);
await Check(
    "outbox persists sequence and only deletes acknowledged ids",
    async () =>
    {
        var path = Path.Combine(Path.GetTempPath(), "compliance-outbox-" + Guid.NewGuid() + ".sqlite");
        try
        {
            await using (var q = new EventOutbox(path, 3))
            {
                var first = await q.EnqueueAsync("Health", "test:one", null, "first");
                var second = await q.EnqueueAsync("Violation", "test:two", null, "second");
                Assert(first.Sequence == 1 && second.Sequence == 2, "sequence order");
                Assert(await q.UnsentCountAsync() == 2, "undelivered count missed queued events");
                await q.AcknowledgeAsync([first.EventId]);
            }
            await using (var q = new EventOutbox(path, 3))
            {
                var pending = await q.PendingAsync(10);
                Assert(pending.Length == 1 && pending[0].Sequence == 2, "ack removed wrong row or persistence failed");
                Assert(
                    (await q.EnqueueAsync("Recovered", "test:two", null, "recovered")).Sequence == 3,
                    "sequence reset after restart"
                );
                bool full = false;
                await q.EnqueueAsync("Health", "test:three", null, "third");
                try
                {
                    await q.EnqueueAsync("Health", "test:four", null, "fourth");
                }
                catch (OutboxCapacityException)
                {
                    full = true;
                }
                Assert(full, "capacity did not fail closed");
            }
        }
        finally
        {
            DeleteDatabase(path);
        }
    }
);
await Check(
    "a full outbox drops its oldest snapshots, never other events",
    async () =>
    {
        var path = Path.Combine(Path.GetTempPath(), "compliance-full-" + Guid.NewGuid() + ".sqlite");
        try
        {
            await using (var q = new EventOutbox(path, 4))
            {
                // An hour apart: snapshots from the same hour replace each other before the queue is full.
                ScanSnapshot Hour(int h) =>
                    new() { HostName = h.ToString(), CollectedAt = DateTimeOffset.UtcNow.AddHours(h - 10) };
                var health = await q.EnqueueAsync("Health", "test:health", null, "kept");
                var oldest = await q.EnqueueAsync("Snapshot", "device:a", Hour(1), null);
                await q.EnqueueAsync("Snapshot", "device:a", Hour(2), null);
                await q.EnqueueAsync("Violation", "test:violation", null, "kept");
                var newest = await q.EnqueueAsync("Snapshot", "device:a", Hour(3), null);
                var pending = (await q.PendingAsync(10)).Select(e => e.EventId).ToArray();
                Assert(pending.Length == 4, "queue did not stay at its limit");
                Assert(!pending.Contains(oldest.EventId), "oldest snapshot kept");
                Assert(pending.Contains(health.EventId) && pending.Contains(newest.EventId), "wrong event dropped");
                Assert(q.Dropped == 1, "drop not counted");
            }
            await using (var q = new EventOutbox(path, 2))
            {
                // Only non-snapshot events left after dropping every snapshot: still refused.
                bool full = false;
                try
                {
                    await q.EnqueueAsync("Health", "test:more", null, "more");
                }
                catch (OutboxCapacityException)
                {
                    full = true;
                }
                Assert(full, "full queue of other events accepted more");
                Assert((await q.PendingAsync(10)).Length == 4, "refused enqueue still dropped snapshots");
            }
        }
        finally
        {
            DeleteDatabase(path);
        }
    }
);
await Check(
    "a queued snapshot replaces the ones from the same hour that are still waiting",
    async () =>
    {
        var path = Path.Combine(Path.GetTempPath(), "compliance-hourly-" + Guid.NewGuid() + ".sqlite");
        try
        {
            await using var q = new EventOutbox(path);
            var hour = new DateTimeOffset(2026, 10, 17, 8, 0, 0, TimeSpan.Zero);
            ScanSnapshot At(int minutes) => new() { HostName = "h", CollectedAt = hour.AddMinutes(minutes) };
            var earlier = await q.EnqueueAsync("Snapshot", "device:a", At(-5), null);
            await q.EnqueueAsync("Snapshot", "device:a", At(5), null);
            var health = await q.EnqueueAsync("Health", "test:health", null, "kept");
            // The same hour written with another offset is still the same hour.
            var last = await q.EnqueueAsync(
                "Snapshot",
                "device:a",
                new ScanSnapshot { HostName = "h", CollectedAt = hour.AddMinutes(50).ToOffset(TimeSpan.FromHours(8)) },
                null
            );
            var pending = (await q.PendingAsync(10)).Select(e => e.EventId).ToArray();
            Assert(
                pending.SequenceEqual([earlier.EventId, health.EventId, last.EventId]),
                "expected the previous hour's snapshot, the other event and the newest snapshot"
            );

            // Offline: a violation found and gone again within the hour keeps the snapshot that found it.
            Evidence Running(int pid) =>
                new("cursor", "Cursor", EvidenceKind.Process, "pid:" + pid, "进程", "Cursor 正在运行", "S-1-5-21-1");
            var found = await q.EnqueueAsync("Snapshot", "device:a", At(52) with { Evidence = [Running(10)] }, null);
            // The same finding again, under another process id, still replaces it.
            var again = await q.EnqueueAsync("Snapshot", "device:a", At(54) with { Evidence = [Running(11)] }, null);
            var clean = await q.EnqueueAsync("Snapshot", "device:a", At(56), null);
            pending = (await q.PendingAsync(10)).Select(e => e.EventId).ToArray();
            Assert(
                pending.SequenceEqual([earlier.EventId, health.EventId, again.EventId, clean.EventId]),
                "expected the violation and the clean snapshot after it: " + pending.Length
            );
            Assert(!pending.Contains(found.EventId), "the same finding twice is merged");
        }
        finally
        {
            DeleteDatabase(path);
        }
    }
);
await Check(
    "a state file a power cut emptied is read from its previous version",
    () =>
    {
        var path = Path.Combine(Path.GetTempPath(), "compliance-durable-" + Guid.NewGuid() + ".json");
        try
        {
            DurableFile.Write(path, "\"one\"");
            DurableFile.Write(path, "\"two\"");
            Assert(DurableFile.Read(path, Wire.Read<string>) == "two", "the newest version is read");
            File.WriteAllText(path, "");
            Assert(DurableFile.Read(path, Wire.Read<string>) == "one", "an empty file falls back to the one before");
            File.Delete(path);
            Assert(DurableFile.Exists(path), "the previous version alone still counts");
            Assert(DurableFile.Read(path, Wire.Read<string>) == "one", "a missing file falls back too");
            File.WriteAllText(DurableFile.BackupPath(path), "{");
            var threw = false;
            try
            {
                DurableFile.Read(path, Wire.Read<string>);
            }
            catch (FileNotFoundException)
            {
                threw = true;
            }
            Assert(threw, "with neither usable, reading the current file's error is thrown");
            Assert(
                Directory.GetFiles(Path.GetDirectoryName(path)!, Path.GetFileName(path) + ".*.tmp").Length == 0,
                "no temporary files left"
            );
        }
        finally
        {
            File.Delete(path);
            File.Delete(DurableFile.BackupPath(path));
        }
        return Task.CompletedTask;
    }
);
await Check(
    "a damaged local database is set aside and created afresh",
    async () =>
    {
        var path = Path.Combine(Path.GetTempPath(), "compliance-damaged-" + Guid.NewGuid() + ".sqlite");
        try
        {
            File.WriteAllBytes(path, [.. Enumerable.Repeat((byte)0x5A, 8192)]);
            var said = new List<string>();
            await using (var q = LocalDatabase.Open(path, p => new EventOutbox(p), said.Add))
            {
                await q.EnqueueAsync("Health", "test:health", null, "after");
                Assert((await q.PendingAsync(10)).Length == 1, "the new queue works");
            }
            Assert(
                said.Count == 1 && said[0].Contains(".corrupt-"),
                "the rebuild is reported: " + string.Join(";", said)
            );
            Assert(
                Directory.GetFiles(Path.GetDirectoryName(path)!, Path.GetFileName(path) + ".corrupt-*").Length == 1,
                "the damaged file is kept aside"
            );
        }
        finally
        {
            foreach (var f in Directory.GetFiles(Path.GetDirectoryName(path)!, Path.GetFileName(path) + ".corrupt-*"))
                File.Delete(f);
            DeleteDatabase(path);
        }
    }
);
await Check(
    "one-shot delivery count includes delayed retries",
    async () =>
    {
        var path = Path.Combine(Path.GetTempPath(), "compliance-unsent-" + Guid.NewGuid() + ".sqlite");
        try
        {
            await using var queue = new EventOutbox(path);
            var evt = await queue.EnqueueAsync("Health", "offline", null, "retain");
            await queue.RetryAsync([evt.EventId], TimeSpan.FromMinutes(1), "offline", false);
            Assert((await queue.PendingAsync(10)).Length == 0, "retry was not delayed");
            Assert(await queue.UnsentCountAsync() == 1, "undelivered count hid delayed retry");
        }
        finally
        {
            DeleteDatabase(path);
        }
    }
);
await Check(
    "fixture is always simulated",
    async () =>
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(
                path,
                Wire.Serialize(new ScanSnapshot { DeviceId = "device", Simulated = false })
            );
            var snapshot = await FixtureCollector.LoadAsync(path);
            Assert(snapshot.Simulated && snapshot.Platform == "Windows", "fixture claimed native coverage");
        }
        finally
        {
            DeleteDatabase(path);
        }
    }
);
await Check(
    "native collector rejects non-Windows",
    async () =>
    {
        if (OperatingSystem.IsWindows())
            return;
        bool blocked = false;
        try
        {
            await new WindowsCollector().CollectAsync("device", PolicySeed.Create(), CancellationToken.None);
        }
        catch (PlatformNotSupportedException)
        {
            blocked = true;
        }
        Assert(blocked, "non-Windows native collection was accepted");
    }
);
await Check(
    "domain compiler refuses overflow and preserves host boundary",
    async () =>
    {
        Assert(
            EdgePolicyCompiler.Compile(["example.com"]).Single() == "example.com",
            "Edge URLBlocklist domain pattern"
        );
        Assert(
            DomainRules.Matches("sub.example.com", "example.com")
                && !DomainRules.Matches("example.com.evil.test", "example.com"),
            "hostname boundary"
        );
        bool overflow = false;
        try
        {
            EdgePolicyCompiler.Compile(Enumerable.Range(0, 1001).Select(i => $"d{i}.example.com").ToArray());
        }
        catch (InvalidOperationException)
        {
            overflow = true;
        }
        Assert(overflow, "truncated domains");
        await Task.CompletedTask;
    }
);
await Check(
    "notification read and ack stay scoped to user SID",
    async () =>
    {
        var path = Path.Combine(Path.GetTempPath(), "compliance-notice-" + Guid.NewGuid() + ".sqlite");
        try
        {
            await using var store = new NotificationStore(path);
            await store.AddAsync("event-1", "S-1-5-21-1", "Restricted notice");
            var mine = await store.ListAsync("S-1-5-21-1");
            var others = await store.ListAsync("S-1-5-21-2");
            Assert(mine.Length == 1 && others.Length == 0, "other user could read notice");
            Assert(!await store.AckAsync("S-1-5-21-2", "event-1"), "other user could ack notice");
            Assert(await store.AckAsync("S-1-5-21-1", "event-1"), "own ack failed");
            Assert((await store.ListAsync("S-1-5-21-1"))[0].Acknowledged, "ack not persisted");
        }
        finally
        {
            DeleteDatabase(path);
        }
    }
);
await Check(
    "a reminder updates its finding's one notice as unread, and the store keeps only the newest notices",
    async () =>
    {
        var path = Path.Combine(Path.GetTempPath(), "compliance-notice-" + Guid.NewGuid() + ".sqlite");
        try
        {
            await using var store = new NotificationStore(path);
            const string sid = "S-1-5-21-1";
            await store.AddAsync("finding:x", sid, "Violation: x", replace: true);
            Assert(await store.AckAsync(sid, "finding:x"), "ack failed");
            await store.AddAsync("finding:x", sid, "Reminder: x", replace: true);
            var list = await store.ListAsync(sid);
            Assert(
                list.Length == 1 && list[0].Message == "Reminder: x" && !list[0].Acknowledged,
                "reminder did not replace the notice as unread"
            );
            await store.AddAsync("once", null, "first");
            await store.AddAsync("once", null, "second");
            Assert(
                (await store.ListAsync(sid)).Single(n => n.EventId == "once").Message == "first",
                "a plain add replaced a stored notice"
            );
            for (var i = 0; i < NotificationStore.Keep + 20; i++)
                await store.AddAsync("n" + i, null, "notice " + i);
            Assert(
                (await store.ListAsync(sid)).Any(n => n.EventId == "n" + (NotificationStore.Keep + 19)),
                "newest notice missing"
            );
            await using var raw = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=" + path);
            await raw.OpenAsync();
            using var count = raw.CreateCommand();
            count.CommandText = "SELECT COUNT(*) FROM notices";
            Assert(Convert.ToInt64(await count.ExecuteScalarAsync()) == NotificationStore.Keep, "old notices kept");
        }
        finally
        {
            DeleteDatabase(path);
        }
    }
);
await Check(
    "HTTP is limited to explicit loopback fixture",
    async () =>
    {
        Assert(
            AgentRuntime.ValidateServer("http://127.0.0.1:5050", true).Host == "127.0.0.1",
            "loopback fixture rejected"
        );
        foreach (var (url, fixture) in new[] { ("http://192.168.1.10:5050", true), ("http://localhost:5050", false) })
        {
            bool rejected = false;
            try
            {
                AgentRuntime.ValidateServer(url, fixture);
            }
            catch (InvalidOperationException)
            {
                rejected = true;
            }
            Assert(rejected, "unsafe HTTP accepted: " + url);
        }
        await Task.CompletedTask;
    }
);
await Check(
    "native HTTP trial accepts explicit private addresses only for one shot",
    async () =>
    {
        Compliance.Agent.Program.ValidateLocalDemoArguments(true, true, false);
        foreach (var (once, fixture) in new[] { (false, false), (true, true) })
        {
            bool rejected = false;
            try
            {
                Compliance.Agent.Program.ValidateLocalDemoArguments(true, once, fixture);
            }
            catch (InvalidOperationException)
            {
                rejected = true;
            }
            Assert(rejected, "invalid local demo launch accepted");
        }
        foreach (
            var url in new[]
            {
                "http://127.0.0.1:5080",
                "http://127.0.0.1:5090",
                "http://192.168.1.2:5080",
                "http://10.10.0.8:8090",
                "http://172.16.0.8:5000",
            }
        )
            Assert(
                AgentRuntime.ValidateServer(url, false, true).Scheme == "http",
                "private HTTP trial URL rejected: " + url
            );
        foreach (
            var url in new[]
            {
                "http://localhost:5080",
                "http://8.8.8.8:5080",
                "http://0.0.0.0:5080",
                "http://192.168.1.2:5080/path",
                "http://192.168.1.2:5080/?x=1",
                "http://user@192.168.1.2:5080",
            }
        )
        {
            bool rejected = false;
            try
            {
                AgentRuntime.ValidateServer(url, false, true);
            }
            catch (InvalidOperationException)
            {
                rejected = true;
            }
            Assert(rejected, "unsafe local demo URL accepted: " + url);
        }
        Assert(AgentRuntime.IsLoopbackDemoStatus("{\"mode\":\"LoopbackDemo\"}"), "demo server rejected");
        Assert(AgentRuntime.IsLoopbackDemoStatus("{\"mode\":\"LanHttpTrial\"}"), "LAN trial server rejected");
        Assert(!AgentRuntime.IsLoopbackDemoStatus("{\"mode\":\"Production\"}"), "production status accepted as demo");
        await Task.CompletedTask;
    }
);
await Check(
    "incident state survives restart and recovery waits for complete scan",
    async () =>
    {
        var path = Path.Combine(Path.GetTempPath(), "compliance-incidents-" + Guid.NewGuid() + ".sqlite");
        try
        {
            await using (var q = new EventOutbox(path))
            {
                var opened = await q.SyncFindingsAsync(
                    new Dictionary<string, string> { { "product:cursor:machine", "Cursor installed" } },
                    false
                );
                Assert(opened.Length == 1 && opened[0].Type == "Violation", "missing violation");
            }
            await using (var q = new EventOutbox(path))
            {
                Assert(
                    (
                        await q.SyncFindingsAsync(
                            new Dictionary<string, string> { { "product:cursor:machine", "Cursor installed" } },
                            false
                        )
                    ).Length == 0,
                    "duplicate violation after restart"
                );
                Assert(
                    (await q.SyncFindingsAsync(new Dictionary<string, string>(), false)).Length == 0,
                    "incomplete scan recovered violation"
                );
                var recovered = await q.SyncFindingsAsync(new Dictionary<string, string>(), true);
                Assert(recovered.Length == 1 && recovered[0].Type == "Recovered", "complete scan failed to recover");
            }
        }
        finally
        {
            DeleteDatabase(path);
        }
    }
);
await Check(
    "agent API timeout remains retryable network failure",
    async () =>
    {
        using var key = System.Security.Cryptography.ECDsa.Create(
            System.Security.Cryptography.ECCurve.NamedCurves.nistP256
        );
        using var client = new HttpClient(new DelayedHandler()) { Timeout = TimeSpan.FromMilliseconds(80) };
        var api = new AgentApi(client, new Uri("https://localhost"), "device", key);
        bool networkFailure = false;
        try
        {
            await api.SendAsync<System.Text.Json.JsonElement>(
                HttpMethod.Get,
                "/api/agent/commands",
                null,
                CancellationToken.None
            );
        }
        catch (HttpRequestException)
        {
            networkFailure = true;
        }
        Assert(networkFailure, "timeout escaped as service-cancelling exception");
    }
);
await Check(
    "large offline backlog is split below server request limit",
    async () =>
    {
        var path = Path.Combine(Path.GetTempPath(), "compliance-batch-" + Guid.NewGuid() + ".sqlite");
        try
        {
            await using var queue = new EventOutbox(path);
            for (var i = 0; i < 6; i++)
                await queue.EnqueueAsync("Health", "batch:" + i, null, new string('x', 120_000));
            var first = await queue.PendingBatchAsync(100, 300_000);
            Assert(first.Length is > 0 and < 6, "oversized batch was not split");
            Assert(
                System.Text.Encoding.UTF8.GetByteCount(Wire.Serialize(new EventBatch(first))) <= 300_000,
                "wire request exceeds declared limit"
            );
            await queue.AcknowledgeAsync(first.Select(e => e.EventId));
            var second = await queue.PendingBatchAsync(100, 300_000);
            Assert(
                second.Length > 0 && second.All(e => !first.Any(a => a.EventId == e.EventId)),
                "remaining events cannot drain"
            );
        }
        finally
        {
            DeleteDatabase(path);
        }
    }
);
await Check(
    "one oversized event is quarantined without blocking smaller queued events",
    async () =>
    {
        var path = Path.Combine(Path.GetTempPath(), "compliance-oversize-" + Guid.NewGuid() + ".sqlite");
        try
        {
            await using var queue = new EventOutbox(path);
            var huge = await queue.EnqueueAsync("Health", "huge", null, new string('x', 700_000));
            var small = await queue.EnqueueAsync("Health", "small", null, "deliver");
            var batch = await queue.PendingBatchAsync(100, 300_000);
            Assert(batch.Length == 1 && batch[0].EventId == small.EventId, "one huge event blocked all valid events");
            using var db = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=" + path);
            db.Open();
            using var cmd = db.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM quarantine WHERE id=$id";
            cmd.Parameters.AddWithValue("$id", huge.EventId);
            Assert(Convert.ToInt32(cmd.ExecuteScalar()) == 1, "oversized event not retained in quarantine");
        }
        finally
        {
            DeleteDatabase(path);
        }
    }
);
await Check(
    "a refused batch is sent again event by event and only the refused event is quarantined",
    async () =>
    {
        var path = Path.Combine(Path.GetTempPath(), "compliance-refused-" + Guid.NewGuid() + ".sqlite");
        try
        {
            await using var queue = new EventOutbox(path);
            await queue.EnqueueAsync("Violation", "good", null, "deliver");
            var bad = await queue.EnqueueAsync("Health", "bad", null, "refused");
            await queue.EnqueueAsync("Health", "later", null, "deliver");
            var requests = new List<int>();
            var result = await EventUpload.SendAsync(
                queue,
                await queue.PendingBatchAsync(100, 1_500_000),
                (batch, _) =>
                {
                    requests.Add(batch.Events.Length);
                    if (batch.Events.Any(e => e.EventId == bad.EventId))
                        throw new AgentApiException("invalid", System.Net.HttpStatusCode.BadRequest, null);
                    return Task.FromResult(new EventReceipt(batch.Events.Select(e => e.EventId).ToArray()));
                },
                CancellationToken.None
            );
            Assert(requests.SequenceEqual([3, 1, 1, 1]), "requests: " + string.Join(",", requests));
            Assert(result is { Accepted: 2, Quarantined: 1, Failure: null }, "result: " + result);
            Assert(await queue.UnsentCountAsync() == 0, "accepted or quarantined events left in the queue");
            using var db = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=" + path);
            db.Open();
            using var cmd = db.CreateCommand();
            cmd.CommandText = "SELECT group_concat(id) FROM quarantine";
            Assert((string)cmd.ExecuteScalar()! == bad.EventId, "wrong events quarantined");
        }
        finally
        {
            DeleteDatabase(path);
        }
    }
);
await Check(
    "a network failure keeps the whole batch for a retry, and a lost connection mid-isolation keeps the rest",
    async () =>
    {
        var path = Path.Combine(Path.GetTempPath(), "compliance-offline-" + Guid.NewGuid() + ".sqlite");
        try
        {
            await using var queue = new EventOutbox(path);
            for (var i = 0; i < 3; i++)
                await queue.EnqueueAsync("Health", "e" + i, null, "x");
            var offline = await EventUpload.SendAsync(
                queue,
                await queue.PendingBatchAsync(100, 1_500_000),
                (_, _) => throw new HttpRequestException("offline"),
                CancellationToken.None
            );
            Assert(offline is { Accepted: 0, Quarantined: 0, Failure: not null }, "offline: " + offline);
            Assert(await queue.UnsentCountAsync() == 3, "offline lost events");

            var path2 = path + "-2";
            await using var second = new EventOutbox(path2);
            for (var i = 0; i < 3; i++)
                await second.EnqueueAsync("Health", "e" + i, null, "x");
            var calls = 0;
            var cut = await EventUpload.SendAsync(
                second,
                await second.PendingBatchAsync(100, 1_500_000),
                (batch, _) =>
                    ++calls switch
                    {
                        1 => throw new AgentApiException("conflict", System.Net.HttpStatusCode.Conflict, null),
                        2 => Task.FromResult(new EventReceipt([batch.Events[0].EventId])),
                        _ => throw new HttpRequestException("offline"),
                    },
                CancellationToken.None
            );
            Assert(cut is { Accepted: 1, Quarantined: 0, Failure: not null }, "cut: " + cut);
            Assert(await second.UnsentCountAsync() == 2, "events after the lost connection were not kept");
            await second.DisposeAsync();
            DeleteDatabase(path2);
        }
        finally
        {
            DeleteDatabase(path);
        }
    }
);
await Check(
    "quarantined events are kept 30 days at most and do not fill the queue",
    async () =>
    {
        var path = Path.Combine(Path.GetTempPath(), "compliance-prune-" + Guid.NewGuid() + ".sqlite");
        try
        {
            await using var queue = new EventOutbox(path, 3);
            var old = await queue.EnqueueAsync("Health", "old", null, "x");
            var recent = await queue.EnqueueAsync("Health", "recent", null, "x");
            await queue.RetryAsync([old.EventId, recent.EventId], TimeSpan.Zero, "refused", true);
            using (var db = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=" + path))
            {
                db.Open();
                using var age = db.CreateCommand();
                age.CommandText = "UPDATE quarantine SET at=$at WHERE id=$id";
                age.Parameters.AddWithValue("$at", DateTimeOffset.UtcNow.AddDays(-31).ToString("O"));
                age.Parameters.AddWithValue("$id", old.EventId);
                age.ExecuteNonQuery();
            }
            // The queue holds 3; the expired quarantined event makes room for a second new one.
            await queue.EnqueueAsync("Health", "a", null, "x");
            await queue.EnqueueAsync("Health", "b", null, "x");
            Assert(await queue.UnsentCountAsync() == 2, "expired quarantine still counted against the limit");
        }
        finally
        {
            DeleteDatabase(path);
        }
    }
);
await Check(
    "a new queue file carries on after the highest sequence the server holds",
    async () =>
    {
        var path = Path.Combine(Path.GetTempPath(), "compliance-sequence-" + Guid.NewGuid() + ".sqlite");
        try
        {
            await using var queue = new EventOutbox(path);
            Assert(await queue.AdvanceSequenceAsync(41), "a new file was not advanced");
            Assert((await queue.EnqueueAsync("Health", "a", null, "x")).Sequence == 42, "sequence not advanced");
            Assert(!await queue.AdvanceSequenceAsync(10), "a lower sequence moved the queue back");
            Assert(!await queue.AdvanceSequenceAsync(0), "zero changed the sequence");
            Assert((await queue.EnqueueAsync("Health", "b", null, "x")).Sequence == 43, "sequence moved back");
            Assert(await queue.AdvanceSequenceAsync(100), "a higher sequence was not taken");
            Assert((await queue.EnqueueAsync("Health", "c", null, "x")).Sequence == 101, "sequence not advanced again");
        }
        finally
        {
            DeleteDatabase(path);
        }
    }
);
await Check(
    "Store package evidence stays scoped to the owning user, one record per app",
    async () =>
    {
        var policy = PolicySeed.Create();
        var evidence = WindowsCollector.ParseAppxPackages(
            [
                "Microsoft.Copilot_1.1.0.0_x64__8wekyb3d8bbwe",
                "Microsoft.Copilot_1.2.0.0_neutral_~_8wekyb3d8bbwe",
                "Microsoft.WindowsCalculator_11.0_x64__8wekyb3d8bbwe",
            ],
            "S-1-5-21-1-2-3-1001",
            policy
        );
        Assert(
            evidence.Length == 1 && evidence[0].UserSid == "S-1-5-21-1-2-3-1001",
            "Appx versions were not merged or scope was lost"
        );
        Assert(
            evidence[0].Summary.Contains("1.1.0.0") && evidence[0].Summary.Contains("1.2.0.0"),
            "installed versions missing from the record"
        );
        await Task.CompletedTask;
    }
);
await Check(
    "HTTP trial mode is opt-in and survives enrollment",
    async () =>
    {
        var path = Path.Combine(Path.GetTempPath(), "agent-config-" + Guid.NewGuid() + ".json");
        try
        {
            File.WriteAllText(path, "{\"serverUrl\":\"https://intranet.example\",\"dataDirectory\":\"C:\\\\data\"}");
            Assert(!AgentConfiguration.Read(path).HttpTrial, "a configuration without the flag enabled HTTP trial");
            File.WriteAllText(
                path,
                "{\"serverUrl\":\"http://192.168.1.15:5080\",\"dataDirectory\":\"C:\\\\data\",\"httpTrial\":true}",
                // install.ps1 writes with Windows PowerShell 5.1's Set-Content -Encoding UTF8, which adds a BOM.
                new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: true)
            );
            var trial = AgentConfiguration.Read(path);
            AgentConfiguration.Save(path, trial with { DeviceId = "device-1" });
            var enrolled = AgentConfiguration.Read(path);
            Assert(enrolled.HttpTrial && enrolled.DeviceId == "device-1", "enrollment dropped the trial flag");
            Assert(
                AgentRuntime.ValidateServer(enrolled.ServerUrl, false, localDemo: true).Port == 5080,
                "private HTTP trial server rejected"
            );
        }
        finally
        {
            DeleteDatabase(path);
        }
        await Task.CompletedTask;
    }
);
await Check(
    "listening socket table decodes ports in network byte order and owning PIDs",
    async () =>
    {
        // IPv4 row: state, local addr, local port, remote addr, remote port, pid (little-endian DWORDs).
        var v4 = new byte[4 + 24];
        BitConverter.GetBytes(1).CopyTo(v4, 0);
        BitConverter.GetBytes(2).CopyTo(v4, 4); // MIB_TCP_STATE_LISTEN
        new byte[] { 127, 0, 0, 1 }.CopyTo(v4, 8);
        new byte[] { 0x1E, 0xD9 }.CopyTo(v4, 12); // 7897
        BitConverter.GetBytes(230732).CopyTo(v4, 24);
        var listener = Assert1(TcpListeners.Parse(v4, ipv6: false));
        Assert(
            listener.Port == 7897 && listener.Pid == 230732 && System.Net.IPAddress.IsLoopback(listener.Address),
            "IPv4 listener decoded wrong"
        );
        var v6 = new byte[4 + 56];
        BitConverter.GetBytes(1).CopyTo(v6, 0);
        System.Net.IPAddress.IPv6Loopback.GetAddressBytes().CopyTo(v6, 4);
        new byte[] { 0x1E, 0xD9 }.CopyTo(v6, 24);
        BitConverter.GetBytes(42).CopyTo(v6, 56);
        var six = Assert1(TcpListeners.Parse(v6, ipv6: true));
        Assert(six.Port == 7897 && six.Pid == 42, "IPv6 listener decoded wrong");
        bool truncated = false;
        try
        {
            TcpListeners.Parse([5, 0, 0, 0, 1, 2], ipv6: false);
        }
        catch (InvalidDataException)
        {
            truncated = true;
        }
        Assert(truncated, "truncated socket table accepted");
        await Task.CompletedTask;

        static PortListener Assert1(PortListener[] rows) =>
            rows.Length == 1 ? rows[0] : throw new Exception("expected one listener, got " + rows.Length);
    }
);
await Check(
    "listening ports name their owning program and stay clues",
    async () =>
    {
        var policy = PolicySeed.Create();
        var loopback = System.Net.IPAddress.Loopback;
        var clash = WindowsCollector.PortEvidence(new(loopback, 7897, 10, "verge-mihomo.exe"), policy);
        Assert(
            clash is { ProductId: "clash", Kind: EvidenceKind.Clue, Confirmed: false }
                && clash.Summary.Contains("verge-mihomo.exe")
                && clash.Summary.Contains("7897"),
            "proxy port not attributed to Clash"
        );
        var odd = WindowsCollector.PortEvidence(new(loopback, 53000, 10, "verge-mihomo.exe"), policy);
        Assert(odd?.ProductId == "clash", "a known product on an unusual port was ignored");
        var unknown = WindowsCollector.PortEvidence(new(loopback, 7890, 11, "something.exe"), policy);
        Assert(unknown?.ProductId == "port-clue" && unknown.Summary.Contains("something.exe"), "owner missing");
        Assert(
            WindowsCollector.PortEvidence(new(loopback, 5432, 12, "postgres.exe"), policy) is null,
            "an ordinary service port was reported"
        );
        await Task.CompletedTask;
    }
);
await Check(
    "loopback proxy settings name the local program; other proxy addresses stay private",
    async () =>
    {
        var policy = PolicySeed.Create();
        Assert(WindowsCollector.LoopbackProxyPort("127.0.0.1:7897") == 7897, "plain loopback proxy");
        Assert(
            WindowsCollector.LoopbackProxyPort("http=127.0.0.1:7890;https=127.0.0.1:7890") == 7890,
            "per-scheme proxy"
        );
        Assert(WindowsCollector.LoopbackProxyPort("http://localhost:1080") == 1080, "localhost URL proxy");
        Assert(WindowsCollector.LoopbackProxyPort("[::1]:7897") == 7897, "IPv6 loopback proxy");
        Assert(WindowsCollector.LoopbackProxyPort("proxy.corp.example:8080") is null, "remote proxy treated as local");
        PortListener[] listeners = [new(System.Net.IPAddress.Any, 7897, 10, "clash-verge-service.exe")];
        var local = WindowsCollector.ProxySummary("已启用代理服务器", "127.0.0.1:7897", listeners, policy);
        Assert(local.Contains("7897") && local.Contains("Clash / Mihomo"), "loopback proxy owner missing: " + local);
        var remote = WindowsCollector.ProxySummary("已启用代理服务器", "10.1.2.3:8080", listeners, policy);
        Assert(!remote.Contains("10.1.2.3") && remote.Contains("不记录地址"), "remote proxy address leaked");
        var idle = WindowsCollector.ProxySummary("已启用代理服务器", "127.0.0.1:9999", listeners, policy);
        Assert(idle.Contains("没有程序监听"), "stale proxy setting not explained");
        await Task.CompletedTask;
    }
);
await Check(
    "user accounts are shown by name, falling back to the profile folder",
    async () =>
    {
        Assert(WindowsCollector.DisplayAccountName(@"LAPTOP-U6EEGUHI\kaiyu", @"C:\Users\kaiyu") == "kaiyu", "local");
        Assert(WindowsCollector.DisplayAccountName(@"CORP\zhang.san", @"C:\Users\zs") == "zhang.san", "domain");
        Assert(WindowsCollector.DisplayAccountName(null, @"C:\Users\AzureAD_lisi") == "AzureAD_lisi", "folder");
        Assert(WindowsCollector.DisplayAccountName(null, "") is null, "no name invented");
        await Task.CompletedTask;
    }
);
await Check(
    "approved VPN adapters are skipped and known proxy tunnels name their product as a clue",
    async () =>
    {
        var policy = PolicySeed.Create();
        Assert(
            WindowsCollector.TunnelEvidence("1", "aTrustVNIC", "aTrust Tunnel", false, policy) is null,
            "approved aTrust adapter reported"
        );
        var clash = WindowsCollector.TunnelEvidence("2", "Mihomo", "Meta Tunnel", false, policy);
        Assert(clash is { ProductId: "clash", Kind: EvidenceKind.Clue, Confirmed: false }, "Mihomo TUN not attributed");
        var singBox = WindowsCollector.TunnelEvidence("3", "singbox_tun", "sing-tun Tunnel", false, policy);
        Assert(singBox?.ProductId == "sing-box", "sing-box TUN not attributed");
        var unknown = WindowsCollector.TunnelEvidence("4", "et_12_1omv", "et_12_1omv Tunnel", false, policy);
        Assert(unknown?.ProductId == "interface-clue", "unknown tunnel lost");
        var report = ReportEngine.Evaluate(
            policy with
            {
                Version = 1,
            },
            new ScanSnapshot
            {
                DeviceId = "d",
                HostName = "h",
                Platform = "Windows",
                CollectedAt = DateTimeOffset.UtcNow,
                PolicyVersion = 1,
                Evidence = [clash!],
                Modules = [],
                Controls = [],
            },
            DateTimeOffset.UtcNow
        );
        Assert(report.ViolationCount == 0, "an adapter-name clue was counted as a violation");
        await Task.CompletedTask;
    }
);
await Check(
    "Windows built-in tunnels are not reported as proxy clues",
    async () =>
    {
        Assert(!WindowsCollector.IsTunnelClue("Teredo Tunneling Pseudo-Interface", "Teredo", true), "Teredo reported");
        Assert(!WindowsCollector.IsTunnelClue("6to4 Adapter", "Microsoft 6to4 Adapter", true), "6to4 reported");
        Assert(
            !WindowsCollector.IsTunnelClue("iphttpsinterface", "IP-HTTPS Platform Interface", true),
            "IP-HTTPS reported"
        );
        Assert(WindowsCollector.IsTunnelClue("Mihomo", "Meta Tunnel", false), "Mihomo TUN missed");
        Assert(WindowsCollector.IsTunnelClue("wg0", "WireGuard Tunnel", false), "WireGuard missed");
        Assert(WindowsCollector.IsTunnelClue("Meta", "Meta Tunnel", false), "Clash Meta TUN missed");
        Assert(!WindowsCollector.IsTunnelClue("以太网", "Intel(R) Ethernet Connection", false), "Ethernet reported");
        Assert(!WindowsCollector.IsTunnelClue("本地连接* 3", "WAN Miniport (SSTP)", true), "WAN Miniport reported");
        await Task.CompletedTask;
    }
);
await Check(
    "system connection settings report proxy, PAC and auto-detect without retaining addresses",
    async () =>
    {
        static byte[] Blob(int flags, string proxy, string pac)
        {
            var bytes = new List<byte>();
            void Int(int v) => bytes.AddRange(BitConverter.GetBytes(v));
            void Str(string v)
            {
                Int(v.Length);
                bytes.AddRange(System.Text.Encoding.ASCII.GetBytes(v));
            }
            Int(0x46);
            Int(1);
            Int(flags);
            Str(proxy);
            Str("<local>");
            Str(pac);
            return bytes.ToArray();
        }
        var proxy = WindowsCollector.ParseConnectionSettings(Blob(0x3, "127.0.0.1:7890", ""));
        Assert(proxy.Proxy && !proxy.Pac && !proxy.AutoDetect, "system proxy missed");
        var pac = WindowsCollector.ParseConnectionSettings(Blob(0x5, "", "https://example.test/pac"));
        Assert(!pac.Proxy && pac.Pac, "system PAC missed");
        var direct = WindowsCollector.ParseConnectionSettings(Blob(0x9, "127.0.0.1:7890", ""));
        Assert(!direct.Proxy && direct.AutoDetect, "disabled proxy server was reported as active");
        bool bad = false;
        try
        {
            WindowsCollector.ParseConnectionSettings([1, 2, 3]);
        }
        catch (InvalidDataException)
        {
            bad = true;
        }
        Assert(bad, "truncated connection settings were accepted");
        await Task.CompletedTask;
    }
);
await Check(
    "extension manifests with comments or trailing commas are read like VS Code does",
    async () =>
    {
        var root = Path.Combine(Path.GetTempPath(), "compliance-extensions-" + Guid.NewGuid());
        try
        {
            var dir = Path.Combine(root, "openai.chatgpt-1.0");
            Directory.CreateDirectory(dir);
            await File.WriteAllTextAsync(
                Path.Combine(dir, "package.json"),
                "{\n  // bundled\n  \"publisher\": \"openai\",\n  \"name\": \"chatgpt\",\n}"
            );
            var result = WindowsCollector.ScanVsCodeExtensions(root, "S-1-5-21-1-2-3-1001", PolicySeed.Create());
            Assert(result.Errors == 0 && result.Evidence.Any(e => e.ProductId == "codex"), "lenient manifest rejected");
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }
);
await Check(
    "broken leftovers of an updated extension are not a coverage gap",
    async () =>
    {
        var root = Path.Combine(Path.GetTempPath(), "compliance-extensions-" + Guid.NewGuid());
        try
        {
            foreach (var version in new[] { "0.115.1", "0.117.1" })
            {
                var stale = Path.Combine(root, "ms-vscode-remote.remote-ssh-" + version);
                Directory.CreateDirectory(stale);
                await File.WriteAllTextAsync(Path.Combine(stale, "package.json"), "");
            }
            var current = Path.Combine(root, "ms-vscode-remote.remote-ssh-0.120.0");
            Directory.CreateDirectory(current);
            await File.WriteAllTextAsync(
                Path.Combine(current, "package.json"),
                "{\"publisher\":\"ms-vscode-remote\",\"name\":\"remote-ssh\"}"
            );
            var result = WindowsCollector.ScanVsCodeExtensions(root, "S-1-5-21-1-2-3-1001", PolicySeed.Create());
            Assert(result.Errors == 0, "superseded versions reported: " + string.Join(",", result.Failed));
            Directory.Delete(current, true);
            result = WindowsCollector.ScanVsCodeExtensions(root, "S-1-5-21-1-2-3-1001", PolicySeed.Create());
            Assert(
                result.Errors == 2 && result.Failed.All(f => f.EndsWith("（文件为空）")),
                "a broken extension without a readable version was hidden"
            );
            Assert(
                WindowsCollector.ExtensionIdFromFolder("github.copilot-chat-0.32.2025101401") == "github.copilot-chat",
                "folder name parsing"
            );
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }
);
await Check(
    "one malformed VS Code extension does not hide a later forbidden extension",
    async () =>
    {
        var root = Path.Combine(Path.GetTempPath(), "compliance-extensions-" + Guid.NewGuid());
        try
        {
            var broken = Path.Combine(root, "a-broken");
            var forbidden = Path.Combine(root, "z-gemini");
            Directory.CreateDirectory(broken);
            Directory.CreateDirectory(forbidden);
            await File.WriteAllTextAsync(Path.Combine(broken, "package.json"), "{not valid json");
            await File.WriteAllTextAsync(
                Path.Combine(forbidden, "package.json"),
                "{\"publisher\":\"google\",\"name\":\"geminicodeassist\"}"
            );
            var result = WindowsCollector.ScanVsCodeExtensions(root, "S-1-5-21-1-2-3-1001", PolicySeed.Create());
            Assert(
                result.Evidence.Any(e => e.ProductId == "gemini-code-assist" && e.UserSid == "S-1-5-21-1-2-3-1001"),
                "valid forbidden extension was hidden after malformed manifest"
            );
            Assert(
                result.Errors == 1 && result.Failed.Single() == "a-broken（JSON 格式错误）",
                "malformed manifest did not mark coverage incomplete or name the folder"
            );
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }
);
await Check(
    "obsolete extension directory is not reported as installed",
    async () =>
    {
        var root = Path.Combine(Path.GetTempPath(), "compliance-obsolete-" + Guid.NewGuid());
        try
        {
            var stale = Path.Combine(root, "google.geminicodeassist-2.0");
            Directory.CreateDirectory(stale);
            await File.WriteAllTextAsync(
                Path.Combine(stale, "package.json"),
                "{\"publisher\":\"google\",\"name\":\"geminicodeassist\"}"
            );
            await File.WriteAllTextAsync(Path.Combine(root, ".obsolete"), "{\"google.geminicodeassist-2.0\":true}");
            var result = WindowsCollector.ScanVsCodeExtensions(root, "S-1-5-21-1-2-3-1001", PolicySeed.Create());
            Assert(result.Evidence.Length == 0 && result.Errors == 0, "obsolete extension was treated as installed");
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }
);
await Check(
    "Cursor and Windsurf user extension roots are included",
    async () =>
    {
        var profile = Path.Combine(Path.GetTempPath(), "compliance-profile-" + Guid.NewGuid());
        try
        {
            foreach (var host in new[] { ".cursor", ".windsurf" })
            {
                var extension = Path.Combine(profile, host, "extensions", "google.geminicodeassist-2.0");
                Directory.CreateDirectory(extension);
                await File.WriteAllTextAsync(
                    Path.Combine(extension, "package.json"),
                    "{\"publisher\":\"google\",\"name\":\"geminicodeassist\"}"
                );
            }
            var result = WindowsCollector.ScanKnownExtensionRoots(profile, "S-1-5-21-1-2-3-1001", PolicySeed.Create());
            Assert(
                result.Evidence.Length == 2 && result.Errors == 0,
                "AI extensions in Cursor or Windsurf were missed"
            );
            Assert(
                result.Evidence.Select(e => e.ObjectKey).Distinct().Count() == 2,
                "two IDE hosts shared one evidence identity"
            );
        }
        finally
        {
            Directory.Delete(profile, true);
        }
    }
);
await Check(
    "known service key identifies Codex without misclassifying its ChatGPT display name",
    async () =>
    {
        var policy = PolicySeed.Create();
        var codex = WindowsCollector.MatchServiceRegistration("CodexSandboxService.OpenAI.Codex", "ChatGPT", policy);
        Assert(codex is { ProductId: "codex", Kind: EvidenceKind.Installation }, "Codex service was not identified");
        Assert(
            WindowsCollector.MatchServiceRegistration("UnrelatedService", "ChatGPT", policy) is null,
            "service display name caused false ChatGPT detection"
        );
        Assert(
            WindowsCollector.MatchServiceRegistration("clash_verge_service", "Clash Verge Service", policy)?.ProductId
                == "clash",
            "Clash service was missed"
        );
        await Task.CompletedTask;
    }
);
await Check(
    "known installation folder requires matching executable",
    async () =>
    {
        var root = Path.Combine(Path.GetTempPath(), "compliance-install-" + Guid.NewGuid());
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "Cursor"));
            Directory.CreateDirectory(Path.Combine(root, "Claude"));
            Directory.CreateDirectory(Path.Combine(root, "Unrelated"));
            await File.WriteAllTextAsync(Path.Combine(root, "Cursor", "Cursor.exe"), "");
            await File.WriteAllTextAsync(Path.Combine(root, "Unrelated", "Claude.exe"), "");
            var matches = WindowsCollector.ScanKnownInstallRoot(root, "S-1-5-21-1-2-3-1001", PolicySeed.Create());
            Assert(
                matches.Length == 1 && matches[0].ProductId == "cursor" && matches[0].UserSid == "S-1-5-21-1-2-3-1001",
                "common install root either missed product or accepted weak name"
            );
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }
);
await Check(
    "installed Claude CLI in known user bin is a violation, not a clue",
    async () =>
    {
        var root = Path.Combine(Path.GetTempPath(), "compliance-cli-" + Guid.NewGuid());
        try
        {
            Directory.CreateDirectory(root);
            await File.WriteAllTextAsync(Path.Combine(root, "claude.exe"), "");
            var matches = WindowsCollector.ScanKnownCliBin(root, "S-1-5-21-1-2-3-1001", PolicySeed.Create());
            Assert(
                matches.Length == 1
                    && matches[0].ProductId == "claude"
                    && matches[0].Kind == EvidenceKind.Installation
                    && matches[0].Confirmed,
                "known Claude CLI was not a confirmed installation"
            );
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }
);
await Check(
    "installed names may carry versions and architectures but not other words",
    () =>
    {
        foreach (
            var name in new[]
            {
                "Clash Verge",
                "clash verge 2.0.3 (x64)",
                "Clash Verge_2.0.3_x64",
                "Clash Verge v1.7.7 64-bit",
                "Clash Verge (User)",
                "Clash Verge 2.0.0-beta.2",
            }
        )
            Assert(WindowsCollector.NameMatches(name, "Clash Verge"), name + " did not match");
        foreach (
            var (name, rule) in new[]
            {
                ("Zed Attack Proxy", "Zed"),
                ("Clash Verge Rev", "Clash Verge"),
                ("Cursors", "Cursor"),
            }
        )
            Assert(!WindowsCollector.NameMatches(name, rule), name + " matched " + rule);
        return Task.CompletedTask;
    }
);
await Check(
    "install folders with a version suffix are recognised",
    async () =>
    {
        var root = Path.Combine(Path.GetTempPath(), "compliance-install-" + Guid.NewGuid());
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "v2rayN-6.42-windows-64"));
            await File.WriteAllTextAsync(Path.Combine(root, "v2rayN-6.42-windows-64", "v2rayN.exe"), "");
            var matches = WindowsCollector.ScanKnownInstallRoot(root, null, PolicySeed.Create());
            Assert(matches.Length == 1 && matches[0].ProductId == "v2ray", "versioned install folder was missed");
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }
);
await Check(
    "npm and Python packages come from the rules, with the old built-in npm list for older policies",
    async () =>
    {
        var root = Path.Combine(Path.GetTempPath(), "compliance-pkg-" + Guid.NewGuid());
        try
        {
            void Package(string name)
            {
                var dir = Path.Combine([root, "node_modules", .. name.Split('/')]);
                Directory.CreateDirectory(dir);
                File.WriteAllText(Path.Combine(dir, "package.json"), $$"""{"name": "{{name}}", "version": "1.0.0"}""");
            }
            Package("@openai/codex");
            Package("opencode-ai");
            var seed = PolicySeed.Create();
            var policy = seed with
            {
                Products =
                [
                    .. seed.Products.Select(r => r.Id == "codex" ? r with { NpmPackages = [] } : r),
                    new ProductRule("opencode", "OpenCode", "ai", [], ["opencode.exe"], [], [])
                    {
                        NpmPackages = ["opencode-ai"],
                        PipPackages = ["Aider_Chat"],
                    },
                ],
            };
            var npm = WindowsCollector.ScanNpmRoot(Path.Combine(root, "node_modules"), "S-1-5-21-1-2-3-1001", policy);
            Assert(
                npm.Select(e => e.ProductId).Order().SequenceEqual(["codex", "opencode"]) && npm.All(e => e.Confirmed),
                "npm packages: " + string.Join(",", npm.Select(e => e.ProductId))
            );
            Assert(
                WindowsCollector.NpmShimNames(policy).Contains("opencode.cmd")
                    && WindowsCollector.NpmShimNames(policy).Contains("claude.cmd"),
                "npm launchers were not derived from the rules"
            );

            var site = Path.Combine(root, "site-packages");
            Directory.CreateDirectory(Path.Combine(site, "aider_chat-0.86.1.dist-info"));
            Directory.CreateDirectory(Path.Combine(site, "requests-2.32.0.dist-info"));
            var pip = WindowsCollector.ScanSitePackages(site, null, policy);
            Assert(
                pip.Length == 1 && pip[0].ProductId == "opencode",
                "Python package was not matched by normalized name"
            );
            Assert(
                WindowsCollector.ScanSitePackages(site, null, seed).Length == 0,
                "seed rules name no Python packages"
            );

            Directory.CreateDirectory(Path.Combine(root, "Python", "Python312", "site-packages"));
            Directory.CreateDirectory(Path.Combine(root, "Python", "Other", "site-packages"));
            var found = WindowsCollector.ExpandFolders(root, "Python", "Python3*", "site-packages").ToArray();
            Assert(found.Length == 1 && found[0].Contains("Python312"), "wildcard folders were not expanded");
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }
);
await Check(
    "program files are found anywhere on a drive and confirmed only by their version information",
    async () =>
    {
        var root = Path.Combine(Path.GetTempPath(), "compliance-programs-" + Guid.NewGuid());
        try
        {
            var user = Path.Combine(root, "Users", "alice");
            foreach (
                var dir in new[]
                {
                    Path.Combine(user, "Downloads", "v2rayN-windows-64"),
                    Path.Combine(root, "$Recycle.Bin", "S-1"),
                    Path.Combine(root, "Tools"),
                }
            )
                Directory.CreateDirectory(dir);
            await File.WriteAllTextAsync(Path.Combine(user, "Downloads", "v2rayN-windows-64", "v2rayN.exe"), "");
            await File.WriteAllTextAsync(Path.Combine(root, "$Recycle.Bin", "S-1", "v2rayN.exe"), "");
            await File.WriteAllTextAsync(Path.Combine(root, "Tools", "xray.exe"), "");
            await File.WriteAllTextAsync(Path.Combine(root, "Tools", "notes.txt"), "");
            var policy = PolicySeed.Create();
            var names = policy.Products.SelectMany(r => r.ExecutableNames).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var paths = WindowsCollector.FindProgramFiles(new FakeVolume(root), names, 50, CancellationToken.None);
            Assert(
                paths.Count == 2 && paths.All(p => !p.Contains("$Recycle.Bin")),
                "program files: " + string.Join(",", paths)
            );
            var downloaded = paths.Single(p => p.EndsWith("v2rayN.exe"));
            Profile[] profiles = [new("S-1-5-21-1-2-3-1001", user, true, true)];
            var confirmed = WindowsCollector
                .ProgramFileEvidence(downloaded, "v2rayN", "v2rayN", policy, profiles)
                .Single();
            Assert(
                confirmed.ProductId == "v2ray"
                    && confirmed.Confirmed
                    && confirmed.Kind == EvidenceKind.Installation
                    && confirmed.UserSid == "S-1-5-21-1-2-3-1001",
                "named program file was not a confirmed installation of its user"
            );
            var clue = WindowsCollector
                .ProgramFileEvidence(paths.Single(p => p.EndsWith("xray.exe")), null, null, policy, profiles)
                .Single();
            Assert(
                clue.Kind == EvidenceKind.Clue && !clue.Confirmed && clue.UserSid is null,
                "program file without version information was not a machine clue"
            );
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }
);
await Check(
    "persistent machine proxy variable is detected without recording its value",
    async () =>
    {
        var hit = WindowsCollector.ProxyEnvironmentEvidence("HTTPS_PROXY", "http://127.0.0.1:7890", null);
        Assert(
            hit is { Kind: EvidenceKind.Proxy, Confirmed: true, UserSid: null } && !hit.Summary.Contains("7890"),
            "machine proxy setting was missed or leaked"
        );
        Assert(
            WindowsCollector.ProxyEnvironmentEvidence("HTTPS_PROXY", "", null) is null,
            "empty proxy setting was reported"
        );
        Assert(
            WindowsCollector.ProxyEnvironmentEvidence("UNRELATED", "x", null) is null,
            "unrelated variable was reported"
        );
        await Task.CompletedTask;
    }
);
await Check(
    "scan-process proxy variable is only a clue",
    async () =>
    {
        var clue = WindowsCollector.ProcessProxyEnvironmentClue("HTTP_PROXY", "http://127.0.0.1:36005");
        Assert(
            clue is { Kind: EvidenceKind.Clue, Confirmed: false } && !clue.Summary.Contains("36005"),
            "scan-process proxy was treated as machine violation or leaked"
        );
        await Task.CompletedTask;
    }
);
await Check(
    "sensitive file walk matches Chinese names and honors exclusions",
    async () =>
    {
        var root = Path.Combine(Path.GetTempPath(), "compliance-sensitive-" + Guid.NewGuid());
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "项目机密资料", "子目录"));
            Directory.CreateDirectory(Path.Combine(root, "AppData"));
            Directory.CreateDirectory(Path.Combine(root, "skipme"));
            Directory.CreateDirectory(Path.Combine(root, "普通"));
            File.WriteAllText(Path.Combine(root, "项目机密资料", "子目录", "机密名单.docx"), "");
            File.WriteAllText(Path.Combine(root, "AppData", "机密.txt"), "");
            File.WriteAllText(Path.Combine(root, "skipme", "机密.txt"), "");
            File.WriteAllText(Path.Combine(root, "普通", "ＳＡＬＡＲＹ表.XLSX"), "");
            File.WriteAllText(Path.Combine(root, "普通", "salary-notes.txt"), "");
            File.WriteAllText(Path.Combine(root, "普通", "说明.txt"), "");
            var policy = new SensitiveFilePolicy
            {
                Enabled = true,
                Rules =
                [
                    new("secret", "机密文件", ["机密"]),
                    new("salary", "薪资表", ["salary"]) { Extensions = [".xlsx"], Action = "Violation" },
                ],
                ExcludePaths = ["AppData", Path.Combine(root, "skipme")],
            };
            var result = SensitiveFileWalker.Scan(
                new("user-1", root, "S-1-5-21-1-2-3-1001", false, []),
                policy,
                null,
                CancellationToken.None
            );
            Assert(result.Status == "Complete" && result.Error is null, "walk did not complete: " + result.Error);
            Assert(
                result.Evidence.Length == 2,
                "unexpected hits: " + string.Join(",", result.Evidence.Select(e => e.ObjectKey))
            );
            var folder = result.Evidence.Single(e => e.ProductId == "secret");
            Assert(
                folder.ObjectKey.EndsWith("项目机密资料") && folder.Summary.StartsWith("文件夹名包含“机密”"),
                "folder hit missing or file inside a reported folder was repeated"
            );
            var salary = result.Evidence.Single(e => e.ProductId == "salary");
            Assert(
                salary.Kind == EvidenceKind.SensitiveFile
                    && salary.Source == "user-1"
                    && salary.UserSid == "S-1-5-21-1-2-3-1001"
                    && salary.ObjectKey.EndsWith("ＳＡＬＡＲＹ表.XLSX"),
                "full-width name or extension filter was not applied"
            );
        }
        finally
        {
            Directory.Delete(root, true);
        }
        await Task.CompletedTask;
    }
);
await Check(
    "sensitive file walk caps hits, skips drive system folders and linked folders",
    async () =>
    {
        var root = Path.Combine(Path.GetTempPath(), "compliance-sensitive-" + Guid.NewGuid());
        var outside = Path.Combine(Path.GetTempPath(), "compliance-sensitive-out-" + Guid.NewGuid());
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "Program Files"));
            Directory.CreateDirectory(Path.Combine(root, "data"));
            Directory.CreateDirectory(outside);
            File.WriteAllText(Path.Combine(root, "Program Files", "confidential.txt"), "");
            File.WriteAllText(Path.Combine(outside, "confidential-linked.txt"), "");
            for (var i = 0; i < 5; i++)
                File.WriteAllText(Path.Combine(root, "data", $"confidential-{i}.txt"), "");
            Directory.CreateSymbolicLink(Path.Combine(root, "data", "link"), outside);
            var policy = new SensitiveFilePolicy
            {
                Enabled = true,
                Rules = [new("conf", "机密", ["CONFIDENTIAL"]) { MatchFolders = false }],
                MaxHitsPerScope = 3,
            };
            var result = SensitiveFileWalker.Scan(
                new("drive:D", root, null, true, []),
                policy,
                path => "S-1-5-21-9-9-9-1002",
                CancellationToken.None
            );
            Assert(
                result.Status == "Truncated" && result.Evidence.Length == 3,
                "cap was not applied: " + result.Status
            );
            Assert(result.Error!.Contains("共命中 5 项"), "truncation note missing: " + result.Error);
            Assert(
                result.Evidence.All(e => e.ObjectKey.Contains("data") && !e.ObjectKey.Contains("linked"))
                    && result.Evidence.All(e => e.UserSid == "S-1-5-21-9-9-9-1002"),
                "system folder or linked folder was scanned, or owner missing"
            );
        }
        finally
        {
            Directory.Delete(root, true);
            Directory.Delete(outside, true);
        }
        await Task.CompletedTask;
    }
);
await Check(
    "sensitive file scanner persists results and rescans when rules change",
    async () =>
    {
        var root = Path.Combine(Path.GetTempPath(), "compliance-sensitive-" + Guid.NewGuid());
        var state = Path.Combine(root, "state", "sensitive-files.json");
        var docs = Path.Combine(root, "docs");
        try
        {
            Directory.CreateDirectory(docs);
            File.WriteAllText(Path.Combine(docs, "机密合同.pdf"), "");
            var gone = true;
            IReadOnlyList<SensitiveScanTarget> Targets(SensitiveFilePolicy p) =>
                gone
                    ? [new("user-1", docs, "S-1-5-21-1", false, []), new("drive:E", root, null, true, [], "磁盘未就绪")]
                    : [new("user-1", docs, "S-1-5-21-1", false, [])];
            var policy = new SensitiveFilePolicy { Enabled = true, Rules = [new("secret", "机密文件", ["机密"])] };
            var now = DateTimeOffset.UtcNow;
            using (var scanner = new SensitiveFileScanner(state, Targets))
            {
                var (_, pending) = scanner.Results(policy, now);
                Assert(
                    pending is [{ Scope: "machine", Status: "Unknown" }],
                    "missing results were not reported as unknown"
                );
                scanner.Update(policy, false, now);
                await scanner.Completion;
                var (evidence, modules) = scanner.Results(policy, now);
                Assert(evidence is [{ ProductId: "secret" }], "hit missing");
                var revision = scanner.Revision;
                Assert(revision > 0, "a finished scan did not count as new results");
                Assert(
                    modules.Single(m => m.Scope == "user-1").Status == "Complete"
                        && modules.Single(m => m.Scope == "drive:E") is { Status: "Unknown", Error: "磁盘未就绪" },
                    "scope status wrong"
                );
                // Without a change journal only the interval (or a vanished path) brings a rescan.
                File.WriteAllText(Path.Combine(docs, "机密附件.pdf"), "");
                scanner.Update(policy, false, now.AddHours(1));
                await scanner.Completion;
                Assert(scanner.Results(policy, now).Evidence.Length == 1, "rescanned before the interval");
                Assert(scanner.Revision == revision, "a change check without changes counted as new results");
                File.Delete(Path.Combine(docs, "机密附件.pdf"));
            }
            gone = false;
            using (var scanner = new SensitiveFileScanner(state, Targets))
            {
                Assert(scanner.Results(policy, now).Evidence.Length == 1, "results were not kept across restart");
                var changed = policy with { Rules = [new("secret", "机密文件", ["合同"])] };
                var (_, stale) = scanner.Results(changed, now);
                Assert(stale is [{ Scope: "machine", Status: "Unknown" }], "old rule results reused");
                scanner.Update(changed, false, now);
                await scanner.Completion;
                var (evidence, modules) = scanner.Results(changed, now);
                Assert(
                    evidence is [{ Summary: var summary }] && summary.Contains("合同"),
                    "rescan with new rules missing"
                );
                Assert(modules.All(m => m.Scope != "drive:E"), "removed drive was kept");
                scanner.Update(changed with { Enabled = false }, false, now);
                Assert(
                    scanner.Results(changed with { Enabled = false }, now).Modules.Length == 0,
                    "disabled scan still reported"
                );
            }
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }
);
await Check(
    "sensitive file scanner retries when targets cannot be listed",
    async () =>
    {
        var root = Path.Combine(Path.GetTempPath(), "compliance-sensitive-" + Guid.NewGuid());
        try
        {
            var calls = 0;
            IReadOnlyList<SensitiveScanTarget> Targets(SensitiveFilePolicy p) =>
                ++calls == 1 ? throw new IOException("registry busy") : [];
            var policy = new SensitiveFilePolicy { Enabled = true, Rules = [new("secret", "机密文件", ["机密"])] };
            using var scanner = new SensitiveFileScanner(Path.Combine(root, "s.json"), Targets);
            var now = DateTimeOffset.UtcNow;
            scanner.Update(policy, false, now);
            await scanner.Completion;
            var (_, modules) = scanner.Results(policy, now);
            Assert(modules is [{ Scope: "machine", Status: "Error" }], "listing failure was not reported");
            scanner.Update(policy, false, now);
            await scanner.Completion;
            Assert(calls == 2, "listing failure was not retried");
            Assert(
                scanner.Results(policy, now).Modules is [{ Scope: "machine", Status: "Complete" }],
                "machine without scan scopes was left unknown"
            );
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, true);
        }
    }
);

await Check(
    "volume index scan reports the same names as the folder walk",
    async () =>
    {
        var root = Path.Combine(Path.GetTempPath(), "compliance-index-" + Guid.NewGuid());
        var outside = root + "-out";
        try
        {
            var alice = Path.Combine(root, "Users", "alice");
            foreach (
                var dir in new[]
                {
                    "项目机密资料/子目录",
                    "AppData/机密",
                    "skipme",
                    "普通/深层/更深",
                    "Program Files",
                    "Users/alice/文档",
                }
            )
                Directory.CreateDirectory(Path.Combine(root, dir));
            Directory.CreateDirectory(outside);
            foreach (
                var file in new[]
                {
                    "项目机密资料/子目录/机密名单.docx",
                    "项目机密资料/salary.xlsx",
                    "AppData/机密/机密.txt",
                    "skipme/机密.txt",
                    "普通/深层/更深/ＳＡＬＡＲＹ表.XLSX",
                    "普通/salary-notes.txt",
                    "Program Files/机密.txt",
                    "Users/alice/文档/机密计划.txt",
                    "机密在根目录.txt",
                }
            )
                File.WriteAllText(Path.Combine(root, file), "");
            File.WriteAllText(Path.Combine(outside, "机密-linked.txt"), "");
            Directory.CreateSymbolicLink(Path.Combine(root, "普通", "云盘机密"), outside);
            var policy = new SensitiveFilePolicy
            {
                Enabled = true,
                Rules =
                [
                    new("secret", "机密文件", ["机密"]),
                    new("salary", "薪资表", ["salary"]) { Extensions = [".xlsx"], Action = "Violation" },
                ],
                ExcludePaths = ["AppData", Path.Combine(root, "skipme")],
            };
            SensitiveScanTarget[] targets =
            [
                new("drive:D", root, null, true, [alice]),
                new("user-1", alice, "S-1-5-21-1-2-3-1001", false, []),
            ];
            var volume = new FakeVolume(root);
            // A cloud-only folder: linked, yet the file table lists names under it. They are not reported.
            volume.Extra.Add(
                new(9999, volume.Id(Path.Combine(root, "普通", "云盘机密")), "机密-cloud.txt", FileAttributes.Normal)
            );
            var indexed = SensitiveIndexScan.Scan(
                volume,
                targets,
                policy,
                p => "S-1-5-21-9",
                CancellationToken.None,
                out var names
            );
            Assert(names > 15, "file table not read: " + names);
            static string Describe(SensitiveScopeResult r) =>
                r.Scope
                + " "
                + r.Status
                + ": "
                + string.Join(
                    " | ",
                    r.Evidence.Select(e => $"{e.ObjectKey} {e.ProductId} {e.Summary} {e.UserSid}")
                        .Order(StringComparer.Ordinal)
                );
            foreach (var target in targets)
            {
                var walked = Describe(
                    SensitiveFileWalker.Scan(target, policy, p => "S-1-5-21-9", CancellationToken.None)
                );
                var fromIndex = Describe(indexed.Single(r => r.Scope == target.Scope));
                Assert(walked == fromIndex, $"index and walk differ:\n  walk:  {walked}\n  index: {fromIndex}");
            }
            var drive = indexed.Single(r => r.Scope == "drive:D");
            Assert(
                // The linked folder's own name is reported; nothing under it is.
                drive.Evidence.Length == 5
                    && drive.Evidence.All(e => !e.ObjectKey.Contains("cloud") && !e.ObjectKey.Contains("alice")),
                "unexpected drive hits: " + Describe(drive)
            );
        }
        finally
        {
            Directory.Delete(root, true);
            Directory.Delete(outside, true);
        }
        await Task.CompletedTask;
    }
);
await Check(
    "sensitive file scanner reads the change journal and rescans only for relevant changes",
    async () =>
    {
        var root = Path.Combine(Path.GetTempPath(), "compliance-journal-" + Guid.NewGuid());
        var docs = Path.Combine(root, "docs");
        try
        {
            Directory.CreateDirectory(Path.Combine(docs, "node_modules", "pkg"));
            File.WriteAllText(Path.Combine(docs, "机密合同.pdf"), "");
            File.WriteAllText(Path.Combine(docs, "node_modules", "pkg", "机密-包.txt"), "");
            var volume = new FakeVolume(root);
            var policy = new SensitiveFilePolicy { Enabled = true, Rules = [new("secret", "机密文件", ["机密"])] };
            using var scanner = new SensitiveFileScanner(
                Path.Combine(root, "state.json"),
                _ => [new("user-1", docs, "S-1-5-21-1", false, [])],
                null,
                _ => volume
            );
            var now = DateTimeOffset.UtcNow;
            string[] Keys() =>
                scanner
                    .Results(policy, now)
                    .Evidence.Select(e => Path.GetFileName(e.ObjectKey))
                    .Order(StringComparer.Ordinal)
                    .ToArray();
            async Task Cycle()
            {
                scanner.Update(policy, false, now);
                await scanner.Completion;
            }
            await Cycle();
            Assert(volume.Scans == 1 && Keys() is ["机密合同.pdf"], "first scan: " + string.Join(",", Keys()));
            var first = scanner.Results(policy, now).Modules.Single().CollectedAt;

            await Task.Delay(20);
            volume.Change(Path.Combine(docs, "普通.txt"), JournalReasons.Create);
            await Cycle();
            Assert(volume.Scans == 1, "unrelated change caused a rescan");
            Assert(
                scanner.Results(policy, now).Modules.Single().CollectedAt > first,
                "unchanged result not confirmed as current"
            );

            volume.Change(Path.Combine(docs, "机密附件.pdf"), JournalReasons.Create);
            await Cycle();
            Assert(
                volume.Scans == 2 && Keys() is ["机密合同.pdf", "机密附件.pdf"],
                "new file missed: " + string.Join(",", Keys())
            );

            // An installer fills a temporary folder and renames it (VS Code extensions do this): every name inside
            // was created in the same window and already checked, so the rename alone does not rescan.
            var temp = Path.Combine(docs, "ext.vsctmp");
            Directory.CreateDirectory(temp);
            volume.Change(temp, JournalReasons.Create, folder: true);
            volume.Change(Path.Combine(temp, "package.json"), JournalReasons.Create);
            Directory.Move(temp, Path.Combine(docs, "ext"));
            volume.Change(Path.Combine(docs, "ext"), JournalReasons.RenameNewName, folder: true, renamedFrom: temp);
            await Cycle();
            Assert(volume.Scans == 2, "renaming a folder created in the same window caused a rescan");

            // Renaming a folder that was already in view brings nothing new (VS Code renames old extensions to
            // "<name>.vsctmp" before deleting them).
            var old = Path.Combine(docs, "ext");
            volume.Change(old, JournalReasons.RenameOldName, folder: true);
            Directory.Move(old, Path.Combine(docs, "ext-1.0.vsctmp"));
            volume.Change(
                Path.Combine(docs, "ext-1.0.vsctmp"),
                JournalReasons.RenameNewName,
                folder: true,
                renamedFrom: old
            );
            await Cycle();
            Assert(volume.Scans == 2, "renaming a folder already in view caused a rescan");

            // Renaming an excluded folder brings the names under it into view.
            Directory.Move(Path.Combine(docs, "node_modules"), Path.Combine(docs, "vendor"));
            volume.Change(Path.Combine(docs, "vendor"), JournalReasons.RenameNewName, folder: true);
            await Cycle();
            Assert(
                volume.Scans == 3 && Keys().Contains("机密-包.txt"),
                "folder moved into view missed: " + string.Join(",", Keys())
            );

            // Moved away with its folder: no record names the file, but its reported path is gone.
            Directory.Move(Path.Combine(docs, "vendor"), Path.Combine(root, "vendor"));
            await Cycle();
            Assert(
                volume.Scans == 4 && !Keys().Contains("机密-包.txt"),
                "vanished path kept: " + string.Join(",", Keys())
            );

            volume.Journal++;
            await Cycle();
            Assert(volume.Scans == 5, "recreated journal did not cause a rescan");
            await Cycle();
            Assert(volume.Scans == 5, "rescanned again after the journal was re-read");
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }
);

await Check(
    "volume catalog reads a file table once and follows the change journal",
    async () =>
    {
        var root = Path.Combine(Path.GetTempPath(), "compliance-catalog-" + Guid.NewGuid());
        try
        {
            var docs = Path.Combine(root, "docs");
            Directory.CreateDirectory(Path.Combine(docs, "old"));
            File.WriteAllText(Path.Combine(docs, "old", "机密合同.pdf"), "");
            File.WriteAllText(Path.Combine(docs, "普通.txt"), "");
            var volume = new FakeVolume(root);
            var clock = new ManualClock(DateTimeOffset.UtcNow);
            var catalog = new VolumeCatalog(_ => volume, clock);
            catalog.Want("sensitive", new("v1", n => n.Contains("机密")));
            string[] Held()
            {
                using var view = catalog.Open(root)!;
                var folders = view.Entries(CancellationToken.None).Where(e => e.IsDirectory).ToDictionary(e => e.Id);
                string PathOf(VolumeEntry e) =>
                    e.ParentId == view.RootId ? e.Name : PathOf(folders[e.ParentId]) + "/" + e.Name;
                return view.Entries(CancellationToken.None)
                    .Where(e => !e.IsDirectory)
                    .Select(PathOf)
                    .Order(StringComparer.Ordinal)
                    .ToArray();
            }
            Assert(Held() is ["docs/old/机密合同.pdf"] && volume.Scans == 1, "first read: " + string.Join(",", Held()));

            volume.Change(Path.Combine(docs, "机密附件.pdf"), JournalReasons.Create);
            volume.Change(Path.Combine(docs, "普通2.txt"), JournalReasons.Create);
            // A folder renamed keeps its id: the names under it follow without records of their own.
            volume.Change(Path.Combine(docs, "old"), JournalReasons.RenameOldName, folder: true);
            Directory.Move(Path.Combine(docs, "old"), Path.Combine(docs, "new"));
            volume.Change(
                Path.Combine(docs, "new"),
                JournalReasons.RenameNewName,
                folder: true,
                renamedFrom: Path.Combine(docs, "old")
            );
            Assert(
                Held() is ["docs/new/机密合同.pdf", "docs/机密附件.pdf"] && volume.Scans == 1,
                "journal not applied: " + string.Join(",", Held())
            );

            File.Delete(Path.Combine(docs, "机密附件.pdf"));
            volume.Change(Path.Combine(docs, "机密附件.pdf"), JournalReasons.Delete);
            Assert(Held() is ["docs/new/机密合同.pdf"] && volume.Scans == 1, "deletion not applied");

            volume.Journal++;
            Held();
            Assert(volume.Scans == 2 && catalog.Reads == 2, "recreated journal did not cause a read");
            // Rules that need names passed over read the table again; narrower ones do not.
            catalog.Want("programs", new("p1", n => n.EndsWith(".txt")));
            Assert(Held().Length == 3 && volume.Scans == 3, "new interest did not cause a read");
            catalog.Want("programs", null);
            Held();
            Assert(volume.Scans == 3, "dropping an interest caused a read");
            clock.Now += VolumeCatalog.Reread;
            Held();
            Assert(volume.Scans == 4, "weekly read missing");
            // With nothing wanted (both scans turned off) the records are let go of, and read again when wanted.
            catalog.Want("sensitive", null);
            Assert(!catalog.FirstReadRunning(root), "nothing is being read");
            catalog.Want("sensitive", new("v1", n => n.Contains("机密")));
            Assert(Held() is ["docs/new/机密合同.pdf"] && volume.Scans == 5, "released volume was not read again");
            using (catalog.Open(root))
                Assert(!catalog.FirstReadRunning(root), "a volume already read is not a first read");
            VolumeCatalog? first = null;
            var during = false;
            first = new VolumeCatalog(v =>
            {
                during = first!.FirstReadRunning(v);
                return volume;
            });
            first.Want("sensitive", new("v1", n => n.Contains("机密")));
            first.Open(root)?.Dispose();
            Assert(during, "the first read of a volume is reported while it runs");
        }
        finally
        {
            Directory.Delete(root, true);
        }
        await Task.CompletedTask;
    }
);

await Check(
    "sensitive and program file scans share one read of the file table",
    async () =>
    {
        var root = Path.Combine(Path.GetTempPath(), "compliance-shared-" + Guid.NewGuid());
        var docs = Path.Combine(root, "docs");
        try
        {
            Directory.CreateDirectory(Path.Combine(docs, "node_modules", "pkg"));
            Directory.CreateDirectory(Path.Combine(root, "Tools"));
            File.WriteAllText(Path.Combine(docs, "机密合同.pdf"), "");
            File.WriteAllText(Path.Combine(docs, "node_modules", "pkg", "机密-包.txt"), "");
            File.WriteAllText(Path.Combine(root, "Tools", "xray.exe"), "");
            var volume = new FakeVolume(root);
            var catalog = new VolumeCatalog(_ => volume);
            var policy = new SensitiveFilePolicy { Enabled = true, Rules = [new("secret", "机密文件", ["机密"])] };
            var products = PolicySeed.Create();
            catalog.Want(VolumeInterest.SensitiveFiles, VolumeInterest.Sensitive(policy));
            catalog.Want(VolumeInterest.ProgramFiles, VolumeInterest.Programs(products));
            var exes = products.Products.SelectMany(r => r.ExecutableNames).ToHashSet(StringComparer.OrdinalIgnoreCase);
            List<string> Programs()
            {
                using var view = catalog.Open(root)!;
                return WindowsCollector.FindProgramFiles(view, exes, 50, CancellationToken.None);
            }
            using var scanner = new SensitiveFileScanner(
                Path.Combine(root, "state.json"),
                _ => [new("user-1", docs, "S-1-5-21-1", false, [])],
                null,
                _ => catalog.Open(root)
            );
            var now = DateTimeOffset.UtcNow;
            string[] Keys() =>
                scanner
                    .Results(policy, now)
                    .Evidence.Select(e => Path.GetFileName(e.ObjectKey))
                    .Order(StringComparer.Ordinal)
                    .ToArray();
            async Task Cycle()
            {
                scanner.Update(policy, false, now);
                await scanner.Completion;
            }
            await Cycle();
            Assert(Keys() is ["机密合同.pdf"], "first scan: " + string.Join(",", Keys()));
            Assert(Programs() is [var tool] && tool.EndsWith("xray.exe"), "program file missed");

            volume.Change(Path.Combine(docs, "机密附件.pdf"), JournalReasons.Create);
            volume.Change(Path.Combine(root, "Tools", "v2rayN.exe"), JournalReasons.Create);
            await Cycle();
            Assert(Keys() is ["机密合同.pdf", "机密附件.pdf"], "new file missed: " + string.Join(",", Keys()));
            Assert(Programs().Count == 2, "new program file missed");

            // Renaming an excluded folder brings the names under it into view.
            var modules = Path.Combine(docs, "node_modules");
            volume.Change(modules, JournalReasons.RenameOldName, folder: true);
            Directory.Move(modules, Path.Combine(docs, "vendor"));
            volume.Change(
                Path.Combine(docs, "vendor"),
                JournalReasons.RenameNewName,
                folder: true,
                renamedFrom: modules
            );
            await Cycle();
            Assert(Keys().Contains("机密-包.txt"), "folder moved into view missed: " + string.Join(",", Keys()));
            Assert(volume.Scans == 1, $"file table read {volume.Scans} times");

            // A restart finds the saved results; the state file is written when a scan ends.
            Assert(File.Exists(Path.Combine(root, "state.json")), "scan state not saved");
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }
);

await Check(
    "service log stamps each line and keeps at most two files",
    async () =>
    {
        var dir = Path.Combine(Path.GetTempPath(), "compliance-log-" + Guid.NewGuid());
        Directory.CreateDirectory(dir);
        try
        {
            var path = Path.Combine(dir, "agent.log");
            using var log = new AgentLog(path, 200);
            log.WriteLine("敏感文件扫描：C:\\ 通过文件索引比对 10 个名称");
            log.Write("partial ");
            log.Write("line\n");
            var lines = File.ReadAllLines(path);
            Assert(
                lines.Length == 2 && lines[0].EndsWith("比对 10 个名称") && lines[1].EndsWith(" partial line"),
                "unexpected log: " + string.Join(" / ", lines)
            );
            Assert(
                System.Text.RegularExpressions.Regex.IsMatch(lines[0], @"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d "),
                "no timestamp"
            );
            for (var i = 0; i < 20; i++)
                log.WriteLine("line " + i);
            Assert(File.Exists(path + ".1") && new FileInfo(path).Length < 400, "log was not rotated");
        }
        finally
        {
            Directory.Delete(dir, true);
        }
        await Task.CompletedTask;
    }
);

// Native checks run on Windows only (CI runs them on windows-latest); elsewhere they are skipped.
await Check(
    "process measure ends only confirmed forbidden programs, and only while enforcing",
    async () =>
    {
        var table = new FakeProcesses([
            new(10, "Cursor.exe", () => "Cursor", () => "S-1-5-21-1"),
            new(11, "cursor.exe", () => "Some Other Cursor", () => "S-1-5-21-1"),
            new(12, "notepad.exe", () => "Notepad", () => null),
        ]);
        var enforcer = new ProcessEnforcer(table);
        var policy = PolicySeed.Create() with { Version = 3 };
        Assert(
            enforcer.Sweep(policy, DateTimeOffset.UtcNow).Count == 0 && table.Killed.Count == 0,
            "audit mode must not end anything"
        );
        var ready = enforcer.State(policy);
        Assert(
            ready is { State: "Ready", Verified: true, Version: 3 },
            "audit mode reports the measure as ready: " + ready
        );

        var enforce = policy with
        {
            Mode = "Enforce",
            RequiredControls = ["process", "browser"],
            TargetDeviceIds = ["d"],
        };
        var blocked = enforcer.Sweep(enforce, DateTimeOffset.UtcNow);
        Assert(
            table.Killed.SequenceEqual([10]),
            "only the process whose product name is confirmed: " + string.Join(",", table.Killed)
        );
        Assert(
            blocked.Single() is { ProductId: "cursor", UserSid: "S-1-5-21-1" },
            "blocked record names product and user"
        );
        Assert(
            enforcer.State(enforce) is { State: "Applied", Verified: true },
            "enforcing reports the measure in effect"
        );

        Assert(
            enforcer.Skipped.Single().Contains("Some Other Cursor"),
            "a same-named program left running says why: " + string.Join(";", enforcer.Skipped)
        );

        // A process that cannot be inspected does not shield the ones after it.
        var failing = new FakeProcesses([
            new(20, "Cursor.exe", () => throw new UnauthorizedAccessException(), () => null),
            new(21, "Cursor.exe", () => "Cursor", () => null),
        ]);
        var past = new ProcessEnforcer(failing);
        Assert(past.Sweep(enforce, DateTimeOffset.UtcNow).Single().Pid == 21, "the next process is still ended");

        // A renamed copy is found by its original file name (product name still checked) or by an uploaded hash.
        const string hash = "AB12";
        var renamed = new FakeProcesses([
            new(40, "notes.exe", () => "Cursor", () => null, OriginalName: () => "Cursor.exe"),
            new(41, "tool.exe", () => "Other", () => null, OriginalName: () => "Cursor.exe"),
            new(42, "x.exe", () => null, () => null, OriginalName: () => null, Sha256: () => "ab12"),
            new(43, "y.exe", () => null, () => null, OriginalName: () => null, Sha256: () => "CD34"),
        ]);
        var hashed = enforce with { ApplicationRules = [new("cursor", "Cursor", hash)] };
        new ProcessEnforcer(renamed).Sweep(hashed, DateTimeOffset.UtcNow);
        Assert(
            renamed.Killed.SequenceEqual([40, 42]),
            "renamed copies are ended by original name or hash: " + string.Join(",", renamed.Killed)
        );

        // Microsoft Store apps are confirmed by their protected install folder, whatever the version info says.
        const string store = @"C:\Program Files\WindowsApps\OpenAI.ChatGPT-Desktop_1.2025.1.0_x64__2p2nqsd0c76g0\app\";
        var packaged = new FakeProcesses([
            new(30, "ChatGPT.exe", () => null, () => "S-1-5-21-2", () => store + "ChatGPT.exe"),
            new(31, "helper.exe", () => null, () => "S-1-5-21-2", () => store + "helper.exe"),
            new(32, "ChatGPT.exe", () => null, () => null, () => @"C:\Users\a\Downloads\ChatGPT.exe"),
        ]);
        var storeBlocked = new ProcessEnforcer(packaged).Sweep(enforce, DateTimeOffset.UtcNow);
        Assert(
            packaged.Killed.SequenceEqual([30, 31]) && storeBlocked.All(b => b.ProductId == "chatgpt"),
            "Store app processes are ended, an unconfirmed copy elsewhere is not: " + string.Join(",", packaged.Killed)
        );
        Assert(
            ProcessEnforcer.PackageName(@"C:\WindowsApps\Foo.exe") is null
                && ProcessEnforcer.PackageName(@"D:\WindowsApps\Anthropic.Claude_1.0.0.0_x64__abc\Claude.exe")
                    == "Anthropic.Claude",
            "package name comes only from a package folder"
        );

        var stuck = new ProcessEnforcer(
            new FakeProcesses([new(20, "Cursor.exe", () => "Cursor", () => null)]) { Refuse = true }
        );
        stuck.Sweep(enforce, DateTimeOffset.UtcNow);
        Assert(
            stuck.State(enforce) is { State: "Error", Verified: false },
            "a process that cannot be ended is an error"
        );
        Assert(
            new ProcessEnforcer(new FakeProcesses([]) { System = false }).State(enforce).State == "Uncovered",
            "without SYSTEM rights the measure is not available"
        );
        await Task.CompletedTask;
    }
);
await Check(
    "browser measure writes numbered URLBlocklist values, keeps others' entries and removes only its own",
    async () =>
    {
        var state = Path.Combine(Path.GetTempPath(), "compliance-blocklist-" + Guid.NewGuid() + ".json");
        try
        {
            var store = new FakeBlocklist();
            store.Values["Edge"] = ["gpo.example.com"];
            var blocklist = new BrowserBlocklist(store, state);
            var policy = PolicySeed.Create() with { Version = 4, BlockDomains = ["chatgpt.com", "gpo.example.com"] };
            blocklist.Apply(policy);
            Assert(store.Writes == 0, "audit mode writes nothing");
            Assert(blocklist.State(policy) is { State: "Ready", Verified: true }, "audit mode reports ready");

            var enforce = policy with
            {
                Mode = "Enforce",
                RequiredControls = ["process", "browser"],
                TargetDeviceIds = ["d"],
            };
            blocklist.Apply(enforce);
            var wanted = EdgePolicyCompiler.Compile(enforce.BlockDomains);
            Assert(
                store.Values["Edge"].SequenceEqual(["gpo.example.com", .. wanted.Where(w => w != "gpo.example.com")]),
                "Edge keeps the group policy entry first: " + string.Join(",", store.Values["Edge"])
            );
            Assert(store.Values["Chrome"].SequenceEqual(wanted), "Chrome gets every rule");
            Assert(blocklist.State(enforce) is { State: "Applied", Verified: true }, "read back as in effect");
            var writes = store.Writes;
            blocklist.Apply(enforce);
            Assert(store.Writes == writes, "unchanged rules are not rewritten");

            // Group policy refresh replaced the list: reported, then written again on the next cycle.
            store.Values["Chrome"] = ["other.example.com"];
            Assert(blocklist.State(enforce).State == "Error", "a list overwritten by someone else is reported");
            blocklist.Apply(enforce);
            Assert(
                store.Values["Chrome"].SequenceEqual(["other.example.com", .. wanted]),
                "rules restored after the other entry"
            );

            // Back to audit (or a restart of the agent): only this agent's entries go away.
            new BrowserBlocklist(store, state).Apply(policy);
            Assert(store.Values["Edge"].SequenceEqual(["gpo.example.com"]), "Edge back to the group policy entry");
            Assert(store.Values["Chrome"].SequenceEqual(["other.example.com"]), "Chrome back to the other entry");
            Assert(!File.Exists(state) || File.ReadAllText(state).Trim() == "{}", "nothing left owned");

            // Edge written, Chrome refused: Edge's rules stay this agent's, so turning enforcement off removes them.
            store.Failing = "Chrome";
            blocklist = new BrowserBlocklist(store, state);
            blocklist.Apply(enforce);
            Assert(blocklist.State(enforce).State == "Error", "a refused write is reported");
            store.Failing = null;
            blocklist.Apply(enforce);
            Assert(store.Values["Chrome"].SequenceEqual(["other.example.com", .. wanted]), "Chrome written on retry");
            new BrowserBlocklist(store, state).Apply(policy);
            Assert(
                store.Values["Edge"].SequenceEqual(["gpo.example.com"]),
                "Edge's rules removed after a partial write: " + string.Join(",", store.Values["Edge"])
            );
            Assert(store.Values["Chrome"].SequenceEqual(["other.example.com"]), "Chrome's rules removed too");
        }
        finally
        {
            File.Delete(state);
        }
        await Task.CompletedTask;
    }
);
await Check(
    "USB disks get the access the policy allows, allowed ones are left alone and only own changes are undone",
    async () =>
    {
        var state = Path.Combine(Path.GetTempPath(), "compliance-usb-" + Guid.NewGuid() + ".json");
        try
        {
            const string stick = @"USBSTOR\DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00\4C530001&0";
            const string ironkey = @"USBSTOR\DISK&VEN_KINGSTON&PROD_IRONKEY&REV_1.00\IK0042&0";
            var usb = new FakeUsb();
            usb.Plug(stick, "SanDisk Ultra USB Device", "4C530001");
            var guard = new UsbGuard(usb, state);
            var audit = PolicySeed.Create() with
            {
                Version = 3,
                Usb = new()
                {
                    Storage = UsbStorage.Block,
                    AllowedDevices = [new("PROD_IRONKEY") { Note = "公司加密盘" }],
                },
            };
            var events = guard.Sweep(audit);
            Assert(
                events.Single() is { Type: UsbStorage.Connected } e
                    && e.Detail
                        == "SanDisk Ultra USB Device（30 GB，序列号 4C530001），可读写，策略为“禁止使用”，未启用强制执行"
                    && e.Notice is null,
                "audit mode reports the disk and what the policy would do: " + events.Single().Detail
            );
            Assert(!usb.Disks[stick].Disabled, "audit mode switches nothing");
            Assert(guard.State(audit) is { State: "Ready", Verified: true }, "audit mode reports ready");
            Assert(guard.Sweep(audit).Count == 0, "an attached disk is reported once");

            var enforce = audit with { Mode = "Enforce", RequiredControls = ["usb"], TargetDeviceIds = ["d"] };
            events = guard.Sweep(enforce);
            Assert(
                events.Single() is { Type: UsbStorage.Blocked, Notice: not null } && usb.Disks[stick].Disabled,
                "turning enforcement on switches the attached disk off and says so"
            );
            usb.Plug(ironkey, "Kingston IronKey", "IK0042");
            events = guard.Sweep(enforce);
            Assert(
                events.Single() is { Type: UsbStorage.Connected } k
                    && k.Detail.EndsWith("，可读写，已放行（公司加密盘）"),
                "the allowed stick stays usable: " + events.Single().Detail
            );
            Assert(guard.State(enforce).State == "Applied", "in effect");

            // Removed and plugged in again: still switched off from before, still blocked, still an alert.
            usb.Disks.Remove(stick);
            events = guard.Sweep(enforce);
            Assert(events.Single() is { Type: UsbStorage.Removed }, "removal is reported");
            usb.Plug(stick, "SanDisk Ultra USB Device", "4C530001");
            usb.Disks[stick] = usb.Disks[stick] with { Disabled = true };
            Assert(
                guard.Sweep(enforce).Single().Type == UsbStorage.Blocked,
                "a disk plugged in again is blocked again"
            );

            // Read-only: the stick is switched back on and made read-only; a restarted client remembers what it did.
            var readOnly = enforce with
            {
                Usb = enforce.Usb with { Storage = UsbStorage.ReadOnly },
            };
            guard = new UsbGuard(usb, state);
            Assert(guard.Sweep(readOnly).Count == 0, "a restart does not report attached disks again");
            Assert(usb.Disks[stick] is { Disabled: false, ReadOnly: true }, "switched on again and made read-only");
            Assert(!usb.Disks[ironkey].ReadOnly, "the allowed stick stays writable");

            // Someone else switched a disk off in Device Manager: the client leaves it so.
            const string other = @"USBSTOR\DISK&VEN_WD&PROD_PASSPORT&REV_1.00\WX01&0";
            usb.Plug(other, "WD My Passport", "WX01");
            usb.Disks[other] = usb.Disks[other] with { Disabled = true };
            var allow = audit with { Usb = new() };
            guard.Sweep(allow);
            Assert(usb.Disks[stick] is { Disabled: false, ReadOnly: false }, "allowing undoes read-only");
            Assert(usb.Disks[other].Disabled, "a disk switched off by someone else stays off");
            Assert(guard.State(allow).State == "Uncovered", "nothing to control when everything is allowed");

            // A disk in use cannot be switched off: reported, and tried again on the next check.
            usb.InUse = stick;
            guard.Sweep(enforce);
            Assert(guard.State(enforce).State == "Error", "a refused switch is reported");
            usb.InUse = null;
            Assert(guard.Sweep(enforce).Any(x => x.Type == UsbStorage.Blocked), "blocked on the next check");
            Assert(new UsbGuard(usb, state).RemoveOwn() is null, "uninstalling undoes its own changes");
            Assert(!usb.Disks[stick].Disabled && usb.Disks[other].Disabled, "only its own");

            Assert(
                new UsbGuard(new FakeUsb { CanControl = false }, state).State(enforce).State == "Uncovered",
                "without SYSTEM rights the measure is not available"
            );
            Assert(
                WindowsUsbStorage.Serial(stick, @"USB\VID_0781&PID_5581\4C530001") == "4C530001"
                    && WindowsUsbStorage.Serial(@"USBSTOR\DISK&VEN_X\7&2A1B3C&0&01&0", @"USB\VID_1&PID_2\6&1F&0&3")
                        == "",
                "serial numbers Windows made up are dropped"
            );
        }
        finally
        {
            File.Delete(state);
        }
        await Task.CompletedTask;
    }
);
await Check(
    "an upgrade installs only a package the server's key signed and the download matches",
    async () =>
    {
        using var serverKey = System.Security.Cryptography.ECDsa.Create(
            System.Security.Cryptography.ECCurve.NamedCurves.nistP256
        );
        using var otherKey = System.Security.Cryptography.ECDsa.Create(
            System.Security.Cryptography.ECCurve.NamedCurves.nistP256
        );
        using var deviceKey = System.Security.Cryptography.ECDsa.Create(
            System.Security.Cryptography.ECCurve.NamedCurves.nistP256
        );
        var file = new byte[4096];
        Random.Shared.NextBytes(file);
        PackageCrypto.MsiSignature.CopyTo(file);
        var package = new ClientPackage(
            "99.0.0",
            Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(file)),
            file.Length,
            DateTimeOffset.UtcNow
        );
        var dir = Path.Combine(Path.GetTempPath(), "compliance-upgrade-" + Guid.NewGuid());
        try
        {
            async Task<(CommandReply Reply, string? Installer)> Prepare(
                SignedClientPackage signed,
                byte[] served,
                string version = "99.0.0"
            )
            {
                using var client = new HttpClient(new PackageHandler(signed, served));
                var api = new AgentApi(client, new Uri("https://server.test"), "device-1", deviceKey);
                return await ClientUpgrade.PrepareAsync(
                    api,
                    new DeviceCommand("c-1", ClientUpgrade.Command, DateTimeOffset.UtcNow.AddHours(1), version),
                    _ => serverKey.ExportSubjectPublicKeyInfoPem(),
                    dir,
                    CancellationToken.None
                );
            }
            var good = await Prepare(PackageCrypto.Sign(package, serverKey, "k"), file);
            Assert(good.Reply.Success && good.Installer is not null, "good package: " + good.Reply.Detail);
            Assert(File.ReadAllBytes(good.Installer!).SequenceEqual(file), "installer content");

            var forged = await Prepare(PackageCrypto.Sign(package, otherKey, "k"), file);
            Assert(!forged.Reply.Success && forged.Installer is null, "another key: " + forged.Reply.Detail);

            var tampered = (byte[])file.Clone();
            tampered[^1] ^= 1;
            var swapped = await Prepare(PackageCrypto.Sign(package, serverKey, "k"), tampered);
            Assert(!swapped.Reply.Success && swapped.Installer is null, "changed file: " + swapped.Reply.Detail);
            Assert(Directory.GetFiles(Path.Combine(dir, "updates"), "*.msi").Length == 0, "changed file kept");

            var older = await Prepare(PackageCrypto.Sign(package, serverKey, "k"), file, "0.0.1");
            Assert(older.Installer is null, "older version installed: " + older.Reply.Detail);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, true);
        }
    }
);

await Check(
    "a key rotation is trusted only when announced under the current key, and completes with the first policy",
    async () =>
    {
        using var current = System.Security.Cryptography.ECDsa.Create(
            System.Security.Cryptography.ECCurve.NamedCurves.nistP256
        );
        using var next = System.Security.Cryptography.ECDsa.Create(
            System.Security.Cryptography.ECCurve.NamedCurves.nistP256
        );
        using var other = System.Security.Cryptography.ECDsa.Create(
            System.Security.Cryptography.ECCurve.NamedCurves.nistP256
        );
        var config = new AgentConfiguration(
            "https://server.test",
            "data",
            "device-1",
            current.ExportSubjectPublicKeyInfoPem(),
            "current"
        );
        var rotation = new KeyRotation(next.ExportSubjectPublicKeyInfoPem(), "next", DateTimeOffset.UtcNow);
        Assert(
            PolicyKeys.Ids(config).SequenceEqual(["current"]) && PolicyKeys.Verified(config, "current") == config,
            "before a rotation only the current key"
        );

        var forged = false;
        try
        {
            PolicyKeys.Accept(config, KeyRotationCrypto.Sign(rotation, other, "current"));
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            forged = true;
        }
        Assert(forged, "an announcement signed by another key is refused");

        var announced = KeyRotationCrypto.Sign(rotation, current, "current");
        var rotating = PolicyKeys.Accept(config, announced);
        Assert(PolicyKeys.Ids(rotating).SequenceEqual(["current", "next"]), "both keys reported");
        Assert(PolicyKeys.Accept(rotating, announced) == rotating, "the same announcement changes nothing");
        // Completing re-signs the held release under the same serial; only the signing key id says to fetch it.
        Assert(
            PolicyKeys.Resigned(rotating, "next")
                && !PolicyKeys.Resigned(rotating, "current")
                && !PolicyKeys.Resigned(rotating, null)
                && !PolicyKeys.Resigned(config, "next"),
            "a held release is fetched again only once the server signs with the known next key"
        );
        Assert(
            PolicyKeys.PublicKeyFor(rotating, "current") == config.PolicyPublicKeyPem
                && PolicyKeys.PublicKeyFor(rotating, "next") == rotation.NewPublicKeyPem,
            "either key verifies during the rotation"
        );
        var unknown = false;
        try
        {
            PolicyKeys.PublicKeyFor(rotating, "other");
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            unknown = true;
        }
        Assert(unknown, "an unknown key id is refused");

        var done = PolicyKeys.Verified(rotating, "next");
        Assert(
            done.PolicyKeyId == "next"
                && done.PolicyPublicKeyPem == rotation.NewPublicKeyPem
                && done.NextPolicyKeyId is null
                && PolicyKeys.Ids(done).SequenceEqual(["next"]),
            "the next key becomes the current one"
        );
        var stale = false;
        try
        {
            PolicyKeys.PublicKeyFor(done, "current");
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            stale = true;
        }
        Assert(stale, "the retired key is no longer trusted");
        await Task.CompletedTask;
    }
);

await Check(
    "baseline rules judge what the device reports and say when it cannot tell",
    async () =>
    {
        NotCoveredException NotCovered(Func<IEnumerable<BaselineFinding>> f) =>
            Throws<NotCoveredException>(() => f().ToArray());
        Assert(!BaselineRules.Antivirus(SecurityHealth.Good, ["Microsoft Defender"]).Any(), "healthy antivirus");
        Assert(
            BaselineRules.Antivirus(SecurityHealth.Poor, ["Microsoft Defender"]).Single().Summary
                == "杀毒软件（Microsoft Defender）未开启实时防护或病毒库已过期",
            "poor antivirus names the product"
        );
        Assert(BaselineRules.Antivirus(SecurityHealth.Poor, []).Single().Summary == "未安装杀毒软件", "no antivirus");
        Assert(NotCovered(() => BaselineRules.Antivirus(null, [])).Message.Contains("服务器版"), "no security center");
        NotCovered(() => BaselineRules.Antivirus(SecurityHealth.NotMonitored, []));

        var on = new Dictionary<string, bool?>
        {
            ["域"] = true,
            ["专用"] = true,
            ["公用"] = true,
        };
        var publicOff = new Dictionary<string, bool?>
        {
            ["域"] = true,
            ["专用"] = true,
            ["公用"] = false,
        };
        // A third-party firewall turns Windows Firewall off; Security Center's verdict counts first.
        Assert(!BaselineRules.Firewall(SecurityHealth.Good, publicOff).Any(), "security center says good");
        Assert(
            BaselineRules.Firewall(SecurityHealth.Poor, publicOff).Single().Summary == "Windows 防火墙的公用网络已关闭",
            "closed profile named"
        );
        Assert(!BaselineRules.Firewall(null, on).Any(), "server with every profile on");
        Assert(BaselineRules.Firewall(null, publicOff).Any(), "server with a profile off");
        NotCovered(() => BaselineRules.Firewall(null, new Dictionary<string, bool?> { ["域"] = null }));

        var now = DateTimeOffset.Parse("2026-10-26T08:00:00Z");
        Assert(!BaselineRules.Updates(now.AddDays(-29), now, 30).Any(), "recent update");
        Assert(BaselineRules.Updates(now.AddDays(-45), now, 30).Single().Summary.Contains("已有 45 天"), "old update");
        NotCovered(() => BaselineRules.Updates(null, now, 30));

        Assert(!BaselineRules.BitLocker("C:", 1, 1).Any(), "protected drive");
        Assert(
            BaselineRules.BitLocker("C:", 0, 0).Single().Summary == "系统盘 C: 未开启 BitLocker 加密",
            "plain drive"
        );
        Assert(BaselineRules.BitLocker("C:", 0, 1).Single().Summary.Contains("已暂停"), "suspended protection");
        Assert(BaselineRules.BitLocker("C:", 0, 2).Single().Summary.Contains("正在加密"), "encrypting");
        NotCovered(() => BaselineRules.BitLocker("C:", 2, 1));

        var good = new ScreenSaverSettings("S-1-5-21-1-2-3-1001", true, true, 600, true);
        Assert(!BaselineRules.ScreenLock(null, [good], 15).Any(), "ten minutes is within fifteen");
        Assert(!BaselineRules.ScreenLock(300, [], 15).Any(), "machine inactivity policy covers everyone");
        var slow = good with { Sid = "S-1-5-21-1-2-3-1002", TimeoutSeconds = 1800 };
        var open = good with { Sid = "S-1-5-21-1-2-3-1003", Secure = false };
        var none = good with { Sid = "S-1-5-21-1-2-3-1004", HasScreenSaver = false };
        var found = BaselineRules.ScreenLock(1800, [good, slow, open, none], 15).ToArray();
        Assert(found.Length == 3 && found.All(f => f.UserSid == f.Key), "each failing user is named");
        Assert(found[0].Summary == "屏幕保护等待 30 分钟，超过 15 分钟", found[0].Summary);
        Assert(found[1].Summary == "屏幕保护恢复时不要求密码", found[1].Summary);
        Assert(found[2].Summary.StartsWith("未启用屏幕保护"), found[2].Summary);
        NotCovered(() => BaselineRules.ScreenLock(null, [], 15));

        Assert(BaselineRules.Guest("Guest", false).Single().Summary == "来宾账户 Guest 已启用", "guest enabled");
        Assert(!BaselineRules.Guest("Guest", true).Any() && !BaselineRules.Guest(null, null).Any(), "guest disabled");

        GroupMember[] members =
        [
            new("S-1-5-21-1-2-3-500", @"PC\Administrator", true),
            new("S-1-5-21-9-8-7-512", @"CORP\Domain Admins", false),
            new("S-1-5-21-1-2-3-1001", @"PC\kaiyu", true),
            new("S-1-5-21-1-2-3-1005", @"PC\ITAdmin", true),
        ];
        var admins = BaselineRules.Admins(members, ["itadmin"]).ToArray();
        Assert(admins.Single().Summary == @"账户 PC\kaiyu 是本地管理员组成员", "only the ordinary user is reported");
        Assert(BaselineRules.Admins(members, [@"PC\kaiyu", "ITAdmin"]).Count() == 0, "full names allowed too");

        Assert(BaselineRules.Rdp(null, 0).Single().Summary == "远程桌面已开启", "rdp on");
        Assert(BaselineRules.Rdp(0, 1).Single().Summary.Contains("组策略"), "rdp opened by policy");
        Assert(!BaselineRules.Rdp(1, 0).Any() && !BaselineRules.Rdp(null, null).Any(), "rdp off");

        Assert(!BaselineRules.Smb1(new(null, null, null)).Any(), "SMBv1 not installed");
        Assert(!BaselineRules.Smb1(new(3, 0, 4)).Any(), "SMBv1 turned off");
        Assert(BaselineRules.Smb1(new(3, null, 3)).Single().Summary == "SMBv1 服务端和客户端未关闭", "SMBv1 on");
        await Task.CompletedTask;
    }
);
await Check(
    "baseline checks run only while enabled, each as its own module, and every one reads this Windows",
    async () =>
    {
        if (!OperatingSystem.IsWindows())
            return;
        var policy = PolicySeed.Create() with
        {
            RequiredModules = ["users"],
            Baseline = new() { Enabled = true, Rules = [.. Baseline.Checks.Select(c => new BaselineRule(c.Id))] },
        };
        var snapshot = await new WindowsCollector().CollectAsync("device", policy, CancellationToken.None);
        foreach (var m in snapshot.Modules.Where(m => Baseline.IsModule(m.Module)))
            Console.WriteLine($"  {m.Module}: {m.Status} {m.Error}");
        foreach (var e in snapshot.Evidence.Where(e => e.Kind == EvidenceKind.Baseline))
            Console.WriteLine($"  {e.ObjectKey}: {e.Summary}");
        var results = snapshot.Modules.Where(m => Baseline.IsModule(m.Module)).ToArray();
        Assert(results.Length == Baseline.Checks.Length, "one result per check: " + results.Length);
        // A read that fails outright is a bug on a stock Windows; a check the edition cannot answer says so.
        Assert(
            results.All(m => m.Status is "Complete" or "Unknown"),
            string.Join("; ", results.Where(m => m.Status == "Error").Select(m => m.Module + " " + m.Error))
        );
        var off = await new WindowsCollector().CollectAsync(
            "device",
            policy with
            {
                Baseline = policy.Baseline with { Enabled = false },
            },
            CancellationToken.None
        );
        Assert(!off.Modules.Any(m => Baseline.IsModule(m.Module)), "disabled checks do not run");
    }
);
if (OperatingSystem.IsWindows())
{
    // Only an administrator can use a directory limited to SYSTEM and Administrators; CI runners are elevated.
    if (
        new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(
            System.Security.Principal.WindowsBuiltInRole.Administrator
        )
    )
        await Check(
            "data directory and its files are handed to Administrators, and a user's grant is removed and reported",
            async () =>
            {
                var administrators = new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid,
                    null
                );
                var me = System.Security.Principal.WindowsIdentity.GetCurrent().User!;
                var users = new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.BuiltinUsersSid,
                    null
                );
                System.Security.Principal.IdentityReference? Owner(FileSystemInfo item) =>
                    item switch
                    {
                        DirectoryInfo d => d.GetAccessControl()
                            .GetOwner(typeof(System.Security.Principal.SecurityIdentifier)),
                        FileInfo f => f.GetAccessControl()
                            .GetOwner(typeof(System.Security.Principal.SecurityIdentifier)),
                        _ => null,
                    };
                void OwnBy(FileSystemInfo item, System.Security.Principal.SecurityIdentifier owner)
                {
                    if (item is DirectoryInfo d)
                    {
                        var s = new System.Security.AccessControl.DirectorySecurity();
                        s.SetOwner(owner);
                        d.SetAccessControl(s);
                    }
                    else if (item is FileInfo f)
                    {
                        var s = new System.Security.AccessControl.FileSecurity();
                        s.SetOwner(owner);
                        f.SetAccessControl(s);
                    }
                }
                var path = Path.Combine(Path.GetTempPath(), "compliance-data-" + Guid.NewGuid());
                try
                {
                    // Protected permissions, but the directory and a file belong to an ordinary account, as when a
                    // user created the folder before installation or an administrator's account wrote the file.
                    Assert(!NativeDataDirectory.EnsureSecure(path), "a new directory reported a repair");
                    var directory = new DirectoryInfo(path);
                    var file = new FileInfo(Path.Combine(path, "agent.json"));
                    File.WriteAllText(file.FullName, "{}");
                    OwnBy(directory, me);
                    OwnBy(file, me);
                    Assert(Equals(Owner(directory), me) && Equals(Owner(file), me), "test could not take ownership");
                    Assert(!NativeDataDirectory.EnsureSecure(path), "a new owner alone was reported");
                    Assert(Equals(Owner(directory), administrators), "directory owner: " + Owner(directory));
                    Assert(Equals(Owner(file), administrators), "file owner: " + Owner(file));

                    var granted = directory.GetAccessControl();
                    granted.AddAccessRule(
                        new System.Security.AccessControl.FileSystemAccessRule(
                            users,
                            System.Security.AccessControl.FileSystemRights.Read,
                            System.Security.AccessControl.InheritanceFlags.ContainerInherit
                                | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                            System.Security.AccessControl.PropagationFlags.None,
                            System.Security.AccessControl.AccessControlType.Allow
                        )
                    );
                    directory.SetAccessControl(granted);
                    Assert(NativeDataDirectory.EnsureSecure(path), "a user's grant was not reported");
                    Assert(!NativeDataDirectory.EnsureSecure(path), "the repair did not hold");
                }
                finally
                {
                    if (Directory.Exists(path))
                        Directory.Delete(path, true);
                }
                await Task.CompletedTask;
            }
        );
    await Check(
        "process measure ends a real confirmed process and names its owner",
        async () =>
        {
            var ping = Path.Combine(Environment.SystemDirectory, "PING.EXE");
            var product = System.Diagnostics.FileVersionInfo.GetVersionInfo(ping).ProductName!;
            using var child = System.Diagnostics.Process.Start(
                new System.Diagnostics.ProcessStartInfo(ping, "-n 60 127.0.0.1") { CreateNoWindow = true }
            )!;
            try
            {
                var policy = PolicySeed.Create() with
                {
                    Mode = "Enforce",
                    RequiredControls = ["process", "browser"],
                    TargetDeviceIds = ["d"],
                    Products = [new ProductRule("ping", product, "test", [], ["PING.EXE"], [], [])],
                };
                var blocked = new ProcessEnforcer(new WindowsProcessTable()).Sweep(policy, DateTimeOffset.UtcNow);
                Assert(
                    blocked.Any(b => b.Pid == child.Id),
                    "ping was not ended: " + string.Join(",", blocked.Select(b => b.Pid))
                );
                Assert(child.WaitForExit(5000), "ping still running");
                Assert(
                    blocked.First(b => b.Pid == child.Id).UserSid
                        == System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value,
                    "owner SID not read"
                );
            }
            finally
            {
                if (!child.HasExited)
                    child.Kill();
            }
            await Task.CompletedTask;
        }
    );
    // Writes the machine's real browser policy, so only on a disposable CI runner.
    if (Environment.GetEnvironmentVariable("CI") == "true")
        await Check(
            "browser measure writes Edge and Chrome URLBlocklist in the registry and removes it again",
            async () =>
            {
                var state = Path.Combine(Path.GetTempPath(), "compliance-blocklist-" + Guid.NewGuid() + ".json");
                var store = new WindowsBlocklistStore();
                Assert(store.CanWrite, "runner cannot write HKLM\\SOFTWARE\\Policies");
                var saved = store.Browsers.ToDictionary(b => b, store.Read);
                try
                {
                    var blocklist = new BrowserBlocklist(store, state);
                    var policy = PolicySeed.Create() with
                    {
                        Mode = "Enforce",
                        RequiredControls = ["process", "browser"],
                        TargetDeviceIds = ["d"],
                        BlockDomains = ["chatgpt.com", "claude.ai"],
                    };
                    blocklist.Apply(policy);
                    Assert(
                        blocklist.State(policy) is { State: "Applied", Verified: true },
                        "not read back as in effect"
                    );
                    using (
                        var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                            @"SOFTWARE\Policies\Google\Chrome\URLBlocklist"
                        )
                    )
                        Assert(key?.GetValue("1") is "chatgpt.com", "Chrome value 1 missing");
                    blocklist.Apply(policy with { Mode = "Audit" });
                    Assert(store.Browsers.All(b => store.Read(b).SequenceEqual(saved[b])), "entries not removed");
                    // Another admin's numbering may have gaps; nothing past the gap may be lost.
                    using (
                        var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                            @"SOFTWARE\Policies\Google\Chrome\URLBlocklist",
                            writable: true
                        )
                    )
                    {
                        foreach (var name in key.GetValueNames())
                            key.DeleteValue(name, false);
                        key.SetValue("1", "a.example");
                        key.SetValue("2", "b.example");
                        key.SetValue("4", "d.example");
                        key.SetValue("10", "j.example");
                    }
                    Assert(
                        store.Read("Chrome").SequenceEqual(["a.example", "b.example", "d.example", "j.example"]),
                        "entries after a numbering gap not read"
                    );
                    blocklist.Apply(policy);
                    var chrome = store.Read("Chrome");
                    Assert(
                        new[] { "a.example", "b.example", "d.example", "j.example" }.All(chrome.Contains),
                        "others' entries after a gap lost on apply"
                    );
                    blocklist.Apply(policy with { Mode = "Audit" });
                    Assert(
                        store.Read("Chrome").SequenceEqual(["a.example", "b.example", "d.example", "j.example"]),
                        "others' entries changed on removal"
                    );
                }
                finally
                {
                    foreach (var (browser, values) in saved)
                        store.Write(browser, values);
                    File.Delete(state);
                }
                await Task.CompletedTask;
            }
        );
    await Check(
        "native TCP table lists our own listener with this process as owner",
        () =>
        {
            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
                var found = TcpListeners.Read().FirstOrDefault(l => l.Port == port);
                Assert(found is not null, $"listener on {port} not found");
                Assert(found!.Pid == Environment.ProcessId, $"owner pid {found.Pid}, expected {Environment.ProcessId}");
                Assert(found.ProcessName is not null, "owner process name missing");
            }
            finally
            {
                listener.Stop();
            }
            return Task.CompletedTask;
        }
    );
    await Check(
        "NTFS file table lists names with their folders and the change journal records new ones",
        () =>
        {
            var dir = Path.Combine(Path.GetTempPath(), "compliance-ntfs-" + Guid.NewGuid());
            Directory.CreateDirectory(dir);
            try
            {
                File.WriteAllText(Path.Combine(dir, "机密-ntfs.txt"), "");
                using var volume = NtfsVolume.TryOpen(Path.GetPathRoot(Path.GetFullPath(dir))!);
                Assert(volume is not null, "NTFS volume could not be opened");
                var cursor = volume!.Cursor();
                Assert(cursor is not null, "change journal unavailable");
                var found = volume.Entries(CancellationToken.None).Where(e => e.Name == "机密-ntfs.txt").ToList();
                Assert(found.Count == 1, $"file table lists the file {found.Count} times");
                var folder = volume.PathOf(found[0].ParentId);
                Assert(
                    folder is not null && folder.Equals(volume.Canonical(dir), StringComparison.OrdinalIgnoreCase),
                    $"parent resolved to {folder}, expected {volume.Canonical(dir)}"
                );
                File.WriteAllText(Path.Combine(dir, "机密-新.txt"), "");
                var (changes, next) = volume.ChangesSince(cursor!, CancellationToken.None);
                Assert(
                    changes.Any(c => c.Name == "机密-新.txt" && (c.Reason & JournalReasons.Create) != 0),
                    "journal did not record the new file"
                );
                Assert(next.NextUsn > cursor!.NextUsn, "journal cursor did not advance");
            }
            finally
            {
                Directory.Delete(dir, true);
            }
            return Task.CompletedTask;
        }
    );
    await Check(
        "notification pipe answers the tray's list and acknowledge requests",
        async () =>
        {
            var path = Path.Combine(Path.GetTempPath(), "compliance-notices-" + Guid.NewGuid() + ".sqlite");
            using var stop = new CancellationTokenSource();
            try
            {
                await using var store = new NotificationStore(path);
                var sid = System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value;
                await store.AddAsync("n-1", sid, "Violation: Cursor：已安装", CancellationToken.None);
                await store.AddAsync("n-2", null, "本机的检查未能完全覆盖", CancellationToken.None);
                var server = new NotificationPipe(store).RunAsync(stop.Token);
                await Task.Delay(500);
                if (server.IsCompleted)
                    await server; // surfaces why the pipe was not created
                async Task<string> Ask(string request)
                {
                    // Exactly as the tray connects.
                    using var pipe = new System.IO.Pipes.NamedPipeClientStream(
                        ".",
                        TrayPipe.Name,
                        System.IO.Pipes.PipeDirection.InOut,
                        System.IO.Pipes.PipeOptions.Asynchronous,
                        System.Security.Principal.TokenImpersonationLevel.Identification
                    );
                    await pipe.ConnectAsync(5000);
                    using var writer = new StreamWriter(pipe, leaveOpen: true) { AutoFlush = true };
                    using var reader = new StreamReader(pipe, leaveOpen: true);
                    await writer.WriteLineAsync(request);
                    return await reader.ReadLineAsync() ?? throw new IOException("Empty service response");
                }
                var list = await Ask("{\"action\":\"list\"}");
                Assert(list.Contains("n-1") && list.Contains("n-2") && list.Contains("\"at\""), "list reply: " + list);
                var ack = await Ask("{\"action\":\"ack\",\"eventId\":\"n-1\"}");
                Assert(ack.Contains("true"), "ack reply: " + ack);
                var after = await Ask("{\"action\":\"list\"}");
                using var json = System.Text.Json.JsonDocument.Parse(after);
                Assert(
                    json.RootElement.EnumerateArray()
                        .Single(n => n.GetProperty("eventId").GetString() == "n-1")
                        .GetProperty("acknowledged")
                        .GetBoolean(),
                    "acknowledgment not kept: " + after
                );
                // The tray's own client reads the same replies.
                var notices = await TrayPipe.ListAsync();
                Assert(
                    notices is { Length: 2 } && notices.Single(n => n.EventId == "n-1").Acknowledged,
                    "tray client: " + after
                );
                Assert(await TrayPipe.AcknowledgeAsync("n-2"), "tray client acknowledgment");
                stop.Cancel();
                try
                {
                    await server;
                }
                catch (OperationCanceledException) { }
            }
            finally
            {
                stop.Cancel();
                DeleteDatabase(path);
            }
        }
    );
    await Check(
        "Store packages read through PackageManager's binary interface match Get-AppxPackage",
        async () =>
        {
            var sid = System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value;
            var ours = StorePackages.ForUser(sid).Order(StringComparer.Ordinal).ToArray();
            var shell = System.Diagnostics.Process.Start(
                new System.Diagnostics.ProcessStartInfo(
                    "powershell.exe",
                    "-NoProfile -Command \"[Console]::OutputEncoding=[Text.Encoding]::UTF8; (Get-AppxPackage).PackageFullName\""
                )
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                }
            )!;
            var output = await shell.StandardOutput.ReadToEndAsync();
            await shell.WaitForExitAsync();
            var theirs = output
                .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Order(StringComparer.Ordinal)
                .ToArray();
            if (ours.Length == 0 || !ours.SequenceEqual(theirs))
                throw new Exception(
                    $"PackageManager listed {ours.Length}, Get-AppxPackage {theirs.Length}; only ours: "
                        + string.Join(", ", ours.Except(theirs).Take(5))
                        + "; only theirs: "
                        + string.Join(", ", theirs.Except(ours).Take(5))
                );
        }
    );
}
else
    Console.WriteLine("SKIP native Windows checks (not running on Windows)");

await Check(
    "the outbox reports what waits, since when, and what the server refused in the last day",
    async () =>
    {
        var path = Path.Combine(Path.GetTempPath(), "compliance-outbox-" + Guid.NewGuid() + ".sqlite");
        try
        {
            await using var q = new EventOutbox(path);
            var empty = await q.StatsAsync();
            Assert(empty == (0, null, 0), "an empty queue reports nothing waiting");
            var first = await q.EnqueueAsync("Health", "test:one", null, "first");
            await q.EnqueueAsync("Health", "test:two", null, "second");
            var refused = await q.EnqueueAsync("Health", "test:three", null, "third");
            await q.RetryAsync([refused.EventId], TimeSpan.Zero, "400", true);
            var (queued, oldest, refusedCount) = await q.StatsAsync();
            Assert(queued == 2, $"two events wait, not {queued}");
            Assert(oldest == first.SourceTime, "the oldest waiting event is the first queued");
            Assert(refusedCount == 1, "the refused event is counted");
        }
        finally
        {
            DeleteDatabase(path);
        }
    }
);

await Check(
    "an upgrade reports success by version and failure from the installer's log",
    () =>
    {
        var dir = Path.Combine(Path.GetTempPath(), "upgrade-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var log = Path.Combine(dir, "x.log");
            var started = DateTimeOffset.UtcNow;
            var pending = new PendingUpgrade("c-1", "0.2.30", log, started);
            pending.Save(dir);
            Assert(PendingUpgrade.Read(dir) == pending, "the record is read back");

            Assert(pending.Outcome("0.2.29", started) is null, "no log yet: the installer may still be running");
            var done = pending.Outcome("0.2.30", started);
            Assert(done is { Succeeded: true, CommandId: "c-1" }, "running the new version is success");
            Assert(pending.Outcome("0.2.31-dev", started) is { Succeeded: true }, "a newer build is success too");

            // Verbose installer logs are UTF-16 with a byte order mark.
            File.WriteAllText(
                log,
                "MSI (s) (A0:B4) [10:00:01:000]: Product: x -- Installation operation failed.\r\n"
                    + "MSI (s) (A0:B4) [10:00:01:000]: Windows Installer installed the product. Product Name: x. "
                    + "Product Version: 0.2.30. Installation success or error status: 1603.\r\n"
                    + "MSI (s) (A0:B4) [10:00:01:000]: MainEngineThread is returning 1603\r\n",
                System.Text.Encoding.Unicode
            );
            var failed = pending.Outcome("0.2.29", started);
            Assert(
                failed is { Succeeded: false } && failed.Detail.Contains("1603"),
                "the installer's status is reported"
            );

            File.WriteAllText(log, "MSI (s): MainEngineThread is returning 0\r\n", System.Text.Encoding.Unicode);
            Assert(pending.Outcome("0.2.29", started.AddMinutes(5)) is null, "status 0 waits for the new version");
            var late = pending.Outcome("0.2.29", started + PendingUpgrade.Timeout);
            Assert(
                late is { Succeeded: false } && late.Detail.Contains("一小时"),
                "an installer that never ends times out"
            );

            File.WriteAllText(Path.Combine(dir, PendingUpgrade.FileName), "{");
            Assert(PendingUpgrade.Read(dir) is null, "a damaged record is dropped");
            Assert(!File.Exists(Path.Combine(dir, PendingUpgrade.FileName)), "and removed");
        }
        finally
        {
            Directory.Delete(dir, true);
        }
        return Task.CompletedTask;
    }
);

await Check(
    "the tamper guard restores the service start type and the tray's start at sign-in, and says what it did",
    () =>
    {
        var system = new FakeTamperSystem();
        Assert(TamperGuard.Check(system).Count == 0, "nothing to report on an untouched install");
        system.Start = 4;
        system.Tray = null;
        system.TrayDisabled = true;
        var found = TamperGuard.Check(system);
        Assert(
            found
                .Select(f => f.ObjectKey)
                .SequenceEqual(["tamper:service-start", "tamper:tray-autostart", "tamper:tray-autostart-disabled"]),
            string.Join(",", found.Select(f => f.ObjectKey))
        );
        Assert(found[0].Detail == "客户端服务的启动类型被改为“禁用”，已恢复为自动启动", found[0].Detail);
        Assert(system.Start == 2 && system.Tray == system.Expected && !system.TrayDisabled, "all repaired");
        Assert(TamperGuard.Check(system).Count == 0, "repaired stays quiet");
        // A repair that fails is still reported, saying so.
        system.Start = 3;
        system.RefuseRepair = true;
        Assert(
            TamperGuard.Check(system).Single().Detail.EndsWith("未能恢复（UnauthorizedAccessException）"),
            "refused"
        );
        // An install the earlier scripts made has no Run value to keep.
        system = new FakeTamperSystem { Expected = null, Tray = null };
        Assert(TamperGuard.Check(system).Count == 0, "script installs are left alone");
        return Task.CompletedTask;
    }
);

await Check(
    "a service run that did not stop in the same boot is reported once; one from an earlier boot is not",
    () =>
    {
        var dir = Directory.CreateTempSubdirectory("tamper-").FullName;
        try
        {
            var boot = new DateTimeOffset(2026, 10, 26, 8, 0, 0, TimeSpan.Zero);
            Assert(TamperGuard.MarkRunning(dir, boot) is null, "first start");
            var killed = TamperGuard.MarkRunning(dir, boot.AddSeconds(1));
            Assert(killed?.ObjectKey == "tamper:service-killed", "ended without stopping");
            TamperGuard.ClearRunning(dir);
            Assert(TamperGuard.MarkRunning(dir, boot) is null, "stopped normally");
            Assert(TamperGuard.MarkRunning(dir, boot.AddHours(9)) is null, "the power went off");

            // Notes the uninstall check leaves are reported once and removed; anything else is dropped.
            TamperGuard.LeaveNote(dir, new("tamper:uninstall-refused", "有人尝试卸载客户端，因未提供卸载密码已阻止"));
            File.WriteAllText(Path.Combine(dir, TamperGuard.NotesDirectory, "other.txt"), "agent:x\nnot ours");
            var taken = new List<TamperFinding>();
            TamperGuard
                .TakeNotesAsync(
                    dir,
                    f =>
                    {
                        taken.Add(f);
                        return Task.CompletedTask;
                    }
                )
                .GetAwaiter()
                .GetResult();
            Assert(taken.Single().ObjectKey == "tamper:uninstall-refused", "the note");
            Assert(Directory.GetFiles(Path.Combine(dir, TamperGuard.NotesDirectory)).Length == 0, "notes removed");
            Assert(!UninstallCheck.Authorized(dir), "no password check passed");
        }
        finally
        {
            Directory.Delete(dir, true);
        }
        return Task.CompletedTask;
    }
);

foreach (var error in failures)
    Console.Error.WriteLine(error);
return failures.Count == 0 ? 0 : 1;

/// <summary>Serves one client package: its signed description, then its file.</summary>
sealed class PackageHandler(SignedClientPackage signed, byte[] file) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken
    ) =>
        Task.FromResult(
            new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = request.RequestUri!.AbsolutePath.EndsWith("/file", StringComparison.Ordinal)
                    ? new ByteArrayContent(file)
                    : new StringContent(Wire.Serialize(signed)),
            }
        );
}

sealed class DelayedHandler : HttpMessageHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken
    )
    {
        await Task.Delay(TimeSpan.FromMinutes(1), cancellationToken);
        return new HttpResponseMessage(System.Net.HttpStatusCode.OK);
    }
}

/// <summary>
/// A folder tree read as if it were an indexed volume: ids are stable per path, changes are journaled by the test.
/// Like a real journal, reading it consumes nothing: each reader asks from its own position.
/// </summary>
sealed class FakeVolume(string root) : IVolumeIndex
{
    private readonly Dictionary<string, ulong> ids = new() { [root] = 1 };
    private readonly List<VolumeEntry> journal = [];
    public readonly List<VolumeEntry> Extra = [];
    public ulong Journal = 7;
    public int Scans;

    public string Root => root;
    public ulong RootId => 1;

    public ulong Id(string path)
    {
        if (!ids.TryGetValue(path, out var id))
            ids[path] = id = (ulong)ids.Count + 1;
        return id;
    }

    /// <summary>Records a change; <paramref name="renamedFrom"/> keeps the file id of the old path, as a rename does.</summary>
    public void Change(string path, uint reason, bool folder = false, string? renamedFrom = null)
    {
        if (!folder && (reason & JournalReasons.Delete) == 0 && !File.Exists(path))
            File.WriteAllText(path, "");
        journal.Add(
            new(
                Id(renamedFrom ?? path),
                Id(Path.GetDirectoryName(path)!),
                Path.GetFileName(path),
                folder ? FileAttributes.Directory : FileAttributes.Normal,
                reason
            )
        );
    }

    public VolumeCursor? Cursor() => new(root, Journal, journal.Count);

    public IEnumerable<VolumeEntry> Entries(CancellationToken ct)
    {
        Scans++;
        var folders = new Stack<string>([root]);
        while (folders.Count > 0)
        {
            var folder = folders.Pop();
            foreach (var entry in new DirectoryInfo(folder).EnumerateFileSystemInfos())
            {
                yield return new(Id(entry.FullName), Id(folder), entry.Name, entry.Attributes);
                if (
                    (entry.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint))
                    == FileAttributes.Directory
                )
                    folders.Push(entry.FullName);
            }
        }
        foreach (var extra in Extra)
            yield return extra;
    }

    public (List<VolumeEntry> Changes, VolumeCursor Next) ChangesSince(VolumeCursor since, CancellationToken ct)
    {
        if (since.JournalId != Journal)
            throw new JournalGoneException("journal recreated");
        return (journal.Skip((int)since.NextUsn).ToList(), since with { NextUsn = journal.Count });
    }

    public string? PathOf(ulong id) => ids.FirstOrDefault(p => p.Value == id && Directory.Exists(p.Key)).Key;

    public string? Canonical(string path) => Directory.Exists(path) ? SensitiveScopeRules.Full(path) : null;

    public void Dispose() { }
}

sealed class ManualClock(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now = now;

    public override DateTimeOffset GetUtcNow() => Now;
}

sealed class FakeProcesses(RunningProcess[] running) : IProcessTable
{
    public List<int> Killed { get; } = [];
    public bool Refuse { get; set; }
    public bool System { get; init; } = true;
    public bool CanTerminate => System;

    public IEnumerable<RunningProcess> Running() => running.Where(p => !Killed.Contains(p.Pid));

    public bool Kill(int pid)
    {
        if (Refuse)
            return false;
        Killed.Add(pid);
        return true;
    }
}

sealed class FakeBlocklist : IBlocklistStore
{
    public Dictionary<string, List<string>> Values { get; } = new() { ["Edge"] = [], ["Chrome"] = [] };
    public int Writes { get; private set; }
    public IReadOnlyList<string> Browsers => ["Edge", "Chrome"];
    public bool CanWrite => true;

    public List<string> Read(string browser) => [.. Values[browser]];

    public string? Failing { get; set; }

    public void Write(string browser, IReadOnlyList<string> values)
    {
        if (browser == Failing)
            throw new UnauthorizedAccessException(browser + " refused");
        Writes++;
        Values[browser] = [.. values];
    }
}

sealed class FakeTamperSystem : ITamperSystem
{
    public int? Start = 2;
    public string? Expected = "\"C:\\Program Files\\ComplianceAgent\\Compliance.Tray.exe\"";
    public string? Tray = "\"C:\\Program Files\\ComplianceAgent\\Compliance.Tray.exe\"";
    public bool TrayDisabled;
    public bool RefuseRepair;

    void Repair()
    {
        if (RefuseRepair)
            throw new UnauthorizedAccessException();
    }

    public int? ServiceStartType() => Start;

    public void SetServiceAutoStart()
    {
        Repair();
        Start = 2;
    }

    public string? ExpectedTrayCommand() => Expected;

    public string? TrayCommand() => Tray;

    public void SetTrayCommand(string command)
    {
        Repair();
        Tray = command;
    }

    public bool TrayStartupDisabled() => TrayDisabled;

    public void EnableTrayStartup()
    {
        Repair();
        TrayDisabled = false;
    }
}

sealed class FakeUsb : IUsbStorage
{
    public Dictionary<string, UsbDisk> Disks { get; } = new(StringComparer.OrdinalIgnoreCase);
    public bool CanControl { get; set; } = true;
    public string? InUse { get; set; }

    public void Plug(string id, string name, string serial) => Disks[id] = new(id, name, serial, 32_000_000_000);

    public IReadOnlyList<UsbDisk> Attached() => [.. Disks.Values];

    public void Disable(string instanceId)
    {
        if (instanceId == InUse)
            throw new InvalidOperationException("设备正在使用中");
        Disks[instanceId] = Disks[instanceId] with { Disabled = true, ReadOnly = false };
    }

    public void Enable(string instanceId) => Disks[instanceId] = Disks[instanceId] with { Disabled = false };

    public void SetReadOnly(string instanceId, bool readOnly) =>
        Disks[instanceId] = Disks[instanceId] with { ReadOnly = readOnly };
}
