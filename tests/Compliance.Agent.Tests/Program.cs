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

// Native checks run on Windows only (CI runs them on windows-latest); elsewhere they are skipped.
if (OperatingSystem.IsWindows())
{
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
}
else
    Console.WriteLine("SKIP native Windows checks (not running on Windows)");

foreach (var error in failures)
    Console.Error.WriteLine(error);
return failures.Count == 0 ? 0 : 1;

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
