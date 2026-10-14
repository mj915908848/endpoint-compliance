using Compliance.Agent;
using Compliance.Core;

var failures = new List<string>();
async Task Check(string name, Func<Task> test)
{
    try { await test(); Console.WriteLine($"PASS {name}"); }
    catch (Exception e) { failures.Add(name + ": " + e.Message); Console.Error.WriteLine($"FAIL {name}: {e}"); }
}
void Assert(bool value, string message) { if (!value) throw new Exception(message); }
await Check("outbox persists sequence and only deletes acknowledged ids", async () =>
{
    var path = Path.Combine(Path.GetTempPath(), "compliance-outbox-" + Guid.NewGuid() + ".sqlite");
    try
    {
        await using(var q = new EventOutbox(path, 3))
        {
            var first = await q.EnqueueAsync("Health", "test:one", null, "first");
            var second = await q.EnqueueAsync("Violation", "test:two", null, "second");
            Assert(first.Sequence == 1 && second.Sequence == 2, "sequence order");
            await q.AcknowledgeAsync([first.EventId]);
        }
        await using(var q = new EventOutbox(path, 3))
        {
            var pending = await q.PendingAsync(10);
            Assert(pending.Length == 1 && pending[0].Sequence == 2, "ack removed wrong row or persistence failed");
            Assert((await q.EnqueueAsync("Recovered", "test:two", null, "recovered")).Sequence == 3, "sequence reset after restart");
            bool full = false;
            await q.EnqueueAsync("Health", "test:three", null, "third");
            try { await q.EnqueueAsync("Health", "test:four", null, "fourth"); } catch (OutboxCapacityException) { full = true; }
            Assert(full, "capacity did not fail closed");
        }
    }
    finally { File.Delete(path); }
});
await Check("fixture is always simulated", async () =>
{
    var path = Path.GetTempFileName();
    try
    {
        await File.WriteAllTextAsync(path, Wire.Serialize(new ScanSnapshot { DeviceId="device", Simulated=false }));
        var snapshot = await FixtureCollector.LoadAsync(path);
        Assert(snapshot.Simulated && snapshot.Platform == "Windows", "fixture claimed native coverage");
    }
    finally { File.Delete(path); }
});
await Check("native collector rejects non-Windows", async () =>
{
    if (OperatingSystem.IsWindows()) return;
    bool blocked = false;
    try { await new WindowsCollector().CollectAsync("device", PolicySeed.Create(), CancellationToken.None); }
    catch (PlatformNotSupportedException) { blocked = true; }
    Assert(blocked, "non-Windows native collection was accepted");
});
await Check("domain compiler refuses overflow and preserves host boundary", async () =>
{
    Assert(EdgePolicyCompiler.Compile(["example.com"]).Single() == "example.com", "Edge URLBlocklist domain pattern");
    Assert(DomainRules.Matches("sub.example.com","example.com") && !DomainRules.Matches("example.com.evil.test","example.com"),"hostname boundary");
    bool overflow = false;
    try { EdgePolicyCompiler.Compile(Enumerable.Range(0,1001).Select(i=>$"d{i}.example.com").ToArray()); }
    catch (InvalidOperationException) { overflow = true; }
    Assert(overflow, "truncated domains");
    await Task.CompletedTask;
});
await Check("notification read and ack stay scoped to user SID", async () =>
{
    var path=Path.Combine(Path.GetTempPath(),"compliance-notice-"+Guid.NewGuid()+".sqlite");
    try
    {
        await using var store=new NotificationStore(path);
        await store.AddAsync("event-1","S-1-5-21-1","Restricted notice");
        var mine=await store.ListAsync("S-1-5-21-1");
        var others=await store.ListAsync("S-1-5-21-2");
        Assert(mine.Length==1 && others.Length==0,"other user could read notice");
        Assert(!await store.AckAsync("S-1-5-21-2","event-1"),"other user could ack notice");
        Assert(await store.AckAsync("S-1-5-21-1","event-1"),"own ack failed");
        Assert((await store.ListAsync("S-1-5-21-1"))[0].Acknowledged,"ack not persisted");
    }
    finally { File.Delete(path); }
});
await Check("HTTP is limited to explicit loopback fixture", async () =>
{
    Assert(AgentRuntime.ValidateServer("http://127.0.0.1:5050",true).Host=="127.0.0.1","loopback fixture rejected");
    foreach(var (url,fixture) in new[]{("http://192.168.1.10:5050",true),("http://localhost:5050",false)})
    {
        bool rejected=false; try { AgentRuntime.ValidateServer(url,fixture); } catch(InvalidOperationException) { rejected=true; }
        Assert(rejected,"unsafe HTTP accepted: "+url);
    }
    await Task.CompletedTask;
});
await Check("incident state survives restart and recovery waits for complete scan", async () =>
{
    var path=Path.Combine(Path.GetTempPath(),"compliance-incidents-"+Guid.NewGuid()+".sqlite");
    try
    {
        await using(var q=new EventOutbox(path))
        {
            var opened=await q.SyncFindingsAsync(new Dictionary<string,string>{{"product:cursor:machine","Cursor installed"}},false);
            Assert(opened.Length==1 && opened[0].Type=="Violation","missing violation");
        }
        await using(var q=new EventOutbox(path))
        {
            Assert((await q.SyncFindingsAsync(new Dictionary<string,string>{{"product:cursor:machine","Cursor installed"}},false)).Length==0,"duplicate violation after restart");
            Assert((await q.SyncFindingsAsync(new Dictionary<string,string>(),false)).Length==0,"incomplete scan recovered violation");
            var recovered=await q.SyncFindingsAsync(new Dictionary<string,string>(),true);
            Assert(recovered.Length==1 && recovered[0].Type=="Recovered","complete scan failed to recover");
        }
    }
    finally { File.Delete(path); }
});
await Check("agent API timeout remains retryable network failure", async () =>
{
    using var key=System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
    using var client=new HttpClient(new DelayedHandler()) { Timeout=TimeSpan.FromMilliseconds(80) };
    var api=new AgentApi(client,new Uri("https://localhost"),"device",key);
    bool networkFailure=false;
    try { await api.SendAsync<System.Text.Json.JsonElement>(HttpMethod.Get,"/api/agent/commands",null,CancellationToken.None); }
    catch(HttpRequestException) { networkFailure=true; }
    Assert(networkFailure,"timeout escaped as service-cancelling exception");
});
await Check("large offline backlog is split below server request limit", async () =>
{
    var path=Path.Combine(Path.GetTempPath(),"compliance-batch-"+Guid.NewGuid()+".sqlite");
    try
    {
        await using var queue=new EventOutbox(path);
        for(var i=0;i<6;i++) await queue.EnqueueAsync("Health","batch:"+i,null,new string('x',120_000));
        var first=await queue.PendingBatchAsync(100,300_000);
        Assert(first.Length is >0 and <6,"oversized batch was not split");
        Assert(System.Text.Encoding.UTF8.GetByteCount(Wire.Serialize(new EventBatch(first)))<=300_000,"wire request exceeds declared limit");
        await queue.AcknowledgeAsync(first.Select(e=>e.EventId));
        var second=await queue.PendingBatchAsync(100,300_000);
        Assert(second.Length>0 && second.All(e=>!first.Any(a=>a.EventId==e.EventId)),"remaining events cannot drain");
    }
    finally { File.Delete(path); }
});
await Check("one oversized event is quarantined without blocking smaller queued events", async () =>
{
    var path=Path.Combine(Path.GetTempPath(),"compliance-oversize-"+Guid.NewGuid()+".sqlite");
    try
    {
        await using var queue=new EventOutbox(path);
        var huge=await queue.EnqueueAsync("Health","huge",null,new string('x',700_000));
        var small=await queue.EnqueueAsync("Health","small",null,"deliver");
        var batch=await queue.PendingBatchAsync(100,300_000);
        Assert(batch.Length==1 && batch[0].EventId==small.EventId,"one huge event blocked all valid events");
        using var db=new Microsoft.Data.Sqlite.SqliteConnection("Data Source="+path);db.Open();
        using var cmd=db.CreateCommand();cmd.CommandText="SELECT COUNT(*) FROM quarantine WHERE id=$id";cmd.Parameters.AddWithValue("$id",huge.EventId);
        Assert(Convert.ToInt32(cmd.ExecuteScalar())==1,"oversized event not retained in quarantine");
    }
    finally { File.Delete(path); }
});
await Check("Store package evidence remains scoped to the owning user", async () =>
{
    var policy=PolicySeed.Create();
    var evidence=WindowsCollector.ParseAppxEvidence("{\"Name\":\"Microsoft.Copilot\",\"PackageFullName\":\"Microsoft.Copilot_1.0\"}","S-1-5-21-1-2-3-1001",policy);
    Assert(evidence.Length==1 && evidence[0].UserSid=="S-1-5-21-1-2-3-1001","Appx violation was broadcast as machine scope");
    await Task.CompletedTask;
});
await Check("advanced WinHTTP proxy and PAC are interpreted without retaining addresses", async () =>
{
    var configured=WindowsCollector.ParseAdvancedWinHttp("Advanced proxy settings: {\"Proxy\":\"127.0.0.1:7890\",\"AutoconfigUrl\":\"\",\"AutoDetect\":false,\"ProxyIsEnabled\":true}");
    Assert(configured.Proxy && !configured.Pac && !configured.AutoDetect,"advanced proxy missed");
    var pac=WindowsCollector.ParseAdvancedWinHttp("{\"Proxy\":\"\",\"AutoconfigUrl\":\"https://example.test/pac\",\"AutoDetect\":false}");
    Assert(!pac.Proxy && pac.Pac,"advanced PAC missed");
    bool bad=false;try { WindowsCollector.ParseAdvancedWinHttp("unsupported output"); } catch(System.Text.Json.JsonException) { bad=true; }
    Assert(bad,"unparsed advanced output was accepted");
    await Task.CompletedTask;
});
foreach (var error in failures) Console.Error.WriteLine(error);
return failures.Count == 0 ? 0 : 1;
sealed class DelayedHandler : HttpMessageHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancellationToken)
    { await Task.Delay(TimeSpan.FromMinutes(1),cancellationToken); return new HttpResponseMessage(System.Net.HttpStatusCode.OK); }
}
