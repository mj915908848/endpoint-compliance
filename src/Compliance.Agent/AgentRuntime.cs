using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Compliance.Core;

namespace Compliance.Agent;

public sealed record AgentConfiguration(string ServerUrl, string DataDirectory, string? DeviceId = null, string? PolicyPublicKeyPem = null, string? PolicyKeyId = null)
{
    public static AgentConfiguration Read(string path) => Wire.Read<AgentConfiguration>(File.ReadAllText(path));
    public static void Save(string path, AgentConfiguration value)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var temp=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        File.WriteAllText(temp,Wire.Serialize(value));
        File.Move(temp,path,true);
    }
}

public sealed class DeviceIdentity
{
    private readonly string keyPath;
    private readonly bool simulation;
    public DeviceIdentity(string dataDirectory,bool simulation)
    {
        Directory.CreateDirectory(dataDirectory);
        keyPath=Path.Combine(dataDirectory,simulation?"device.simulated.pk8":"device.dpapi");
        this.simulation=simulation;
        if(!simulation && !OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("DPAPI device identity requires Windows");
    }
    public ECDsa LoadOrCreate()
    {
        if(File.Exists(keyPath))
        {
            var bytes=File.ReadAllBytes(keyPath);
            if(!simulation) { if(!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException(); bytes=UnprotectWindows(bytes); }
            var key=ECDsa.Create(); key.ImportPkcs8PrivateKey(bytes,out _); CryptographicOperations.ZeroMemory(bytes); return key;
        }
        var created=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var raw=created.ExportPkcs8PrivateKey();
        if(!simulation && !OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var stored=simulation?raw:ProtectWindows(raw);
        using(var file=new FileStream(keyPath,FileMode.CreateNew,FileAccess.Write,FileShare.None)) file.Write(stored);
        if(simulation && !OperatingSystem.IsWindows()) File.SetUnixFileMode(keyPath,UnixFileMode.UserRead|UnixFileMode.UserWrite);
        CryptographicOperations.ZeroMemory(raw);
        return created;
    }
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static byte[] ProtectWindows(byte[] data) => ProtectedData.Protect(data,null,DataProtectionScope.LocalMachine);
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static byte[] UnprotectWindows(byte[] data) => ProtectedData.Unprotect(data,null,DataProtectionScope.LocalMachine);
}

public sealed class AgentApiException(string message,HttpStatusCode status,TimeSpan? retryAfter) : HttpRequestException(message,null,status)
{
    public TimeSpan? RetryAfter { get; }=retryAfter;
}

public sealed class AgentApi(HttpClient client, Uri baseUri, string? deviceId, ECDsa key)
{
    public async Task<T> SendAsync<T>(HttpMethod method,string path,object? body,CancellationToken ct)
    {
        var bytes=body is null?Array.Empty<byte>():Encoding.UTF8.GetBytes(Wire.Serialize(body));
        using var request=new HttpRequestMessage(method,new Uri(baseUri,path));
        if(body is not null) request.Content=new ByteArrayContent(bytes) { Headers = { ContentType = new MediaTypeHeaderValue("application/json") } };
        if(path!="/api/agent/enroll")
        {
            if(string.IsNullOrWhiteSpace(deviceId)) throw new InvalidOperationException("Device has not enrolled");
            var timestamp=DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
            var nonce=Guid.NewGuid().ToString("D");
            request.Headers.Add("X-Device-Id",deviceId);
            request.Headers.Add("X-Timestamp",timestamp);
            request.Headers.Add("X-Nonce",nonce);
            request.Headers.Add("X-Signature",RequestAuthentication.Sign(key,method.Method,path,timestamp,nonce,bytes));
        }
        HttpResponseMessage response;
        try { response=await client.SendAsync(request,ct); }
        catch(OperationCanceledException ex) when(!ct.IsCancellationRequested) { throw new HttpRequestException("Agent API request timed out",ex,HttpStatusCode.RequestTimeout); }
        using(response)
        {
        if(!response.IsSuccessStatusCode)
        {
            var retry=response.Headers.RetryAfter?.Delta ?? (response.Headers.RetryAfter?.Date is { } date ? date-DateTimeOffset.UtcNow : null);
            throw new AgentApiException($"Agent API {path}: {(int)response.StatusCode}",response.StatusCode,retry);
        }
        return Wire.Read<T>(await response.Content.ReadAsStringAsync(ct));
        }
    }
}

public sealed class AgentRuntime(AgentConfiguration config,string configPath,bool simulated,string? fixturePath,bool localDemo=false)
{
    private readonly string statePath=Path.Combine(config.DataDirectory,"policy.signed.json");
    private PolicyDocument? policy;
    private SignedPolicy? signedPolicy;
    private DateTimeOffset lastFull=DateTimeOffset.MinValue;
    private DateTimeOffset lastLight=DateTimeOffset.MinValue;
    private ScanSnapshot? latest;
    public static Uri ValidateServer(string url,bool simulation,bool localDemo=false)
    {
        var uri=new Uri(url,UriKind.Absolute);
        if(localDemo)
        {
            if(uri.Scheme==Uri.UriSchemeHttp && IsTrialAddress(uri.Host) && uri.AbsolutePath=="/" && uri.Query.Length==0 && uri.Fragment.Length==0 && uri.UserInfo.Length==0)
                return uri;
            throw new InvalidOperationException("HTTP trial requires an explicit loopback or private IPv4 server address without a path");
        }
        if(uri.Scheme==Uri.UriSchemeHttps) return uri;
        if(simulation && uri.Scheme==Uri.UriSchemeHttp && IPAddress.TryParse(uri.Host,out var ip) && IPAddress.IsLoopback(ip)) return uri;
        if(simulation && uri.Scheme==Uri.UriSchemeHttp && uri.Host.Equals("localhost",StringComparison.OrdinalIgnoreCase)) return uri;
        throw new InvalidOperationException("Agent server requires HTTPS; HTTP is allowed only for explicit loopback fixture simulation");
    }
    private static bool IsTrialAddress(string host)
    {
        if(!IPAddress.TryParse(host,out var ip) || ip.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetwork) return false;
        var b=ip.GetAddressBytes();
        return b[0]==127 || b[0]==10 || b[0]==172 && b[1]>=16 && b[1]<=31 || b[0]==192 && b[1]==168;
    }
    public static bool IsLoopbackDemoStatus(string json)
    {
        try
        {
            using var document=JsonDocument.Parse(json);
            return document.RootElement.TryGetProperty("mode",out var mode) && mode.ValueKind==JsonValueKind.String && mode.GetString() is "LoopbackDemo" or "LanHttpTrial";
        }
        catch(JsonException) { return false; }
    }
    private async Task VerifyLocalDemoAsync(HttpClient client,Uri uri,CancellationToken ct)
    {
        if(!localDemo) return;
        using var response=await client.GetAsync(new Uri(uri,"/api/status"),ct);
        response.EnsureSuccessStatusCode();
        if(!IsLoopbackDemoStatus(await response.Content.ReadAsStringAsync(ct)))
            throw new InvalidOperationException("The HTTP server has not enabled trial mode");
    }
    public async Task EnrollAsync(string code,CancellationToken ct)
    {
        using var key=new DeviceIdentity(config.DataDirectory,simulated).LoadOrCreate();
        using var client=CreateInternalClient();
        var uri=ValidateServer(config.ServerUrl,simulated,localDemo);
        await VerifyLocalDemoAsync(client,uri,ct);
        var api=new AgentApi(client,uri,null,key);
        var response=await api.SendAsync<EnrollmentResponse>(HttpMethod.Post,"/api/agent/enroll",new EnrollmentRequest(code,Environment.MachineName,key.ExportSubjectPublicKeyInfoPem()),ct);
        config=config with { DeviceId=response.DeviceId,PolicyPublicKeyPem=response.PolicyPublicKeyPem,PolicyKeyId=response.PolicyKeyId };
        AgentConfiguration.Save(configPath,config);
    }
    public async Task RunAsync(bool once,CancellationToken ct)
    {
        if(string.IsNullOrWhiteSpace(config.DeviceId) || string.IsNullOrWhiteSpace(config.PolicyPublicKeyPem)) throw new InvalidOperationException("Enroll first with --enroll --code");
        var uri=ValidateServer(config.ServerUrl,simulated,localDemo);
        using var key=new DeviceIdentity(config.DataDirectory,simulated).LoadOrCreate();
        using var client=CreateInternalClient();
        await VerifyLocalDemoAsync(client,uri,ct);
        var api=new AgentApi(client,uri,config.DeviceId,key);
        await using var queue=new EventOutbox(Path.Combine(config.DataDirectory,"outbox.sqlite"));
        await using var notices=new NotificationStore(Path.Combine(config.DataDirectory,"notices.sqlite"));
        var pipeTask=OperatingSystem.IsWindows() && !once ? new NotificationPipe(notices).RunAsync(ct) : Task.CompletedTask;
        await LoadCachedPolicy();
        if(once)
        {
            await Cycle(api,queue,notices,true,ct);
            if(localDemo && await queue.UnsentCountAsync(ct)>0)
                throw new InvalidOperationException("Local scan finished but upload is still queued; keep the demo server running and retry this scan");
            return;
        }
        while(!ct.IsCancellationRequested)
        {
            if(pipeTask.IsFaulted) await pipeTask;
            try { await Cycle(api,queue,notices,lastFull<DateTimeOffset.UtcNow.AddMinutes(-60),ct); }
            catch(Exception e) when(e is not OperationCanceledException)
            {
                Console.Error.WriteLine($"Agent cycle failed: {e.GetType().Name}: {EvidenceSanitizer.Clean(e.Message)}");
                try { await queue.EnqueueAsync("Health","agent:cycle",null,"Cycle failure: "+e.GetType().Name,ct); }
                catch(OutboxCapacityException ex)
                {
                    Console.Error.WriteLine(ex.Message);
                    await notices.AddAsync("health:outbox-capacity",null,"离线事件队列已满；事件无法可靠保留，请联系管理员",ct);
                    throw;
                }
            }
            await Task.Delay(TimeSpan.FromSeconds(55+Random.Shared.Next(11)),ct);
        }
    }
    private async Task LoadCachedPolicy()
    {
        if(!File.Exists(statePath)) return;
        try
        {
            var signed=Wire.Read<SignedPolicy>(await File.ReadAllTextAsync(statePath));
            if(config.PolicyKeyId is not null && signed.KeyId!=config.PolicyKeyId) throw new CryptographicException("Cached policy key ID changed");
            var doc=VerifyRetained(signed,0);
            signedPolicy=signed; policy=doc;
        }
        catch(Exception e) { Console.Error.WriteLine("Cached policy invalid: "+e.GetType().Name); }
    }
    private PolicyDocument VerifyRetained(SignedPolicy signed,long minimumVersion)
    {
        var untrusted=Wire.Read<PolicyDocument>(signed.Payload);
        var verificationTime=untrusted.ExpiresAt<DateTimeOffset.UtcNow?untrusted.ExpiresAt:DateTimeOffset.UtcNow;
        return PolicyCrypto.Verify(signed,config.PolicyPublicKeyPem!,config.DeviceId!,minimumVersion,verificationTime);
    }
    private async Task Cycle(AgentApi api,EventOutbox queue,NotificationStore notices,bool forceFull,CancellationToken ct)
    {
        string? policyIssue=null;
        // Health goes first when connectivity resumes, then historical events.
        try
        {
            var heartbeat=new HeartbeatRequest(Environment.MachineName,"0.1.0",DateTimeOffset.UtcNow,signedPolicy is null?0:policy?.Version??0,latest?.Controls??[]);
            await api.SendAsync<JsonElement>(HttpMethod.Post,"/api/agent/heartbeat",heartbeat,ct);
        }
        catch(Exception e) when(e is HttpRequestException or TaskCanceledException) { Console.Error.WriteLine("Heartbeat pending: "+e.GetType().Name); }
        try
        {
            var fetched=await api.SendAsync<SignedPolicy>(HttpMethod.Get,"/api/agent/policy",null,ct);
            if(config.PolicyKeyId is not null && fetched.KeyId!=config.PolicyKeyId) throw new CryptographicException("Policy key ID changed");
            var verified=PolicyCrypto.Verify(fetched,config.PolicyPublicKeyPem!,config.DeviceId!,policy?.Version??0,DateTimeOffset.UtcNow);
            if(policy is not null && verified.Version==policy.Version && signedPolicy is not null && fetched.Payload!=signedPolicy.Payload) throw new CryptographicException("Immutable policy version changed content");
            if(policy?.Version != verified.Version) forceFull=true;
            policy=verified; signedPolicy=fetched;
            var temp=statePath+".tmp";
            await File.WriteAllTextAsync(temp,Wire.Serialize(fetched),ct); File.Move(temp,statePath,true);
        }
        catch(Exception e) when(e is HttpRequestException or TaskCanceledException or CryptographicException or ArgumentException or JsonException)
        {
            policyIssue=(e is HttpRequestException or TaskCanceledException) && signedPolicy is not null ? null : "Policy refresh failed: "+e.GetType().Name;
            Console.Error.WriteLine("Policy refresh failed; retained last signed policy: "+e.GetType().Name);
        }
        if(policy is null) { policy=PolicySeed.Create(); policyIssue="No valid signed policy; local seed used for detection only"; }
        if(policy.ExpiresAt<DateTimeOffset.UtcNow) policyIssue="Last signed policy expired; OS controls retained";
        DeviceCommand[] commands=[];
        try { commands=await api.SendAsync<DeviceCommand[]>(HttpMethod.Get,"/api/agent/commands",null,ct); }
        catch(HttpRequestException) { }
        var scanCommands=commands.Where(x=>x.Type=="ScanNow" && x.ExpiresAt>DateTimeOffset.UtcNow).ToArray();
        foreach(var unsupported in commands.Except(scanCommands))
            await api.SendAsync<JsonElement>(HttpMethod.Post,$"/api/agent/commands/{Uri.EscapeDataString(unsupported.Id)}/ack",new CommandReply(false,"Unsupported or expired command"),ct);
        if(scanCommands.Length>0) forceFull=true;
        bool full=forceFull || latest is null || lastFull<DateTimeOffset.UtcNow.AddMinutes(-60);
        bool light=full || lastLight<DateTimeOffset.UtcNow.AddMinutes(-5);
        if(light)
        {
            ScanSnapshot scan=simulated?await FixtureCollector.LoadAsync(fixturePath!,ct):await CollectNativeAsync(config.DeviceId!,policy,full?null:latest,ct);
            var controls=WindowsControls.Inspect(policy);
            // Lightweight cadence uses fresh module results only for modules actually collected.
            var moduleResults=policyIssue is null?scan.Modules:[..scan.Modules,new ModuleResult("policy","agent","Error",DateTimeOffset.UtcNow,policyIssue)];
            latest=EvidenceSanitizer.Sanitize(scan with { DeviceId=config.DeviceId!,PolicyVersion=signedPolicy is null?0:policy.Version,Controls=controls,Modules=moduleResults });
            await queue.EnqueueAsync("Snapshot","device:"+config.DeviceId,latest,null,ct);
            var report=ReportEngine.Evaluate(policy,latest,DateTimeOffset.UtcNow);
            var findings=BuildLocalFindings(policy,latest,report);
            var scopes=latest.Evidence.Where(e=>e.UserSid is not null).GroupBy(LocalKey).ToDictionary(g=>g.Key,g=>g.First().UserSid);
            var changes=await queue.SyncFindingsAsync(findings,report.Verdict==Verdict.PASS,scopes,ct:ct);
            foreach(var change in changes)
            {
                await notices.AddAsync(Guid.NewGuid().ToString("D"),change.UserSid,$"{change.Type}: {change.Detail}",ct);
            }
            Console.WriteLine(ReportRenderer.Markdown(report));
            lastLight=DateTimeOffset.UtcNow;
            if(full) lastFull=lastLight;
            foreach(var command in scanCommands)
                await api.SendAsync<JsonElement>(HttpMethod.Post,$"/api/agent/commands/{Uri.EscapeDataString(command.Id)}/ack",new CommandReply(true,"Full scan completed and queued"),ct);
        }
        var pending=await queue.PendingBatchAsync(100,1_500_000,ct);
        if(queue.OversizedInLastBatch>0)
        {
            await notices.AddAsync(Guid.NewGuid().ToString("D"),null,"上报事件超过管理端限制，已隔离；审计记录不完整",ct);
            await queue.EnqueueAsync("Health","agent:oversized-event",null,"One or more events were quarantined due to API size limit",ct);
            if(pending.Length==0) pending=await queue.PendingBatchAsync(100,1_500_000,ct);
        }
        if(pending.Length>0)
        {
            try
            {
                var receipt=await api.SendAsync<EventReceipt>(HttpMethod.Post,"/api/agent/events",new EventBatch(pending),ct);
                await queue.AcknowledgeAsync(receipt.AcceptedEventIds.Intersect(pending.Select(x=>x.EventId)),ct);
                var refused=pending.Select(x=>x.EventId).Except(receipt.AcceptedEventIds).ToArray();
                if(refused.Length>0) await queue.RetryAsync(refused,TimeSpan.FromMinutes(1),"Server did not accept event",false,ct);
            }
            catch(HttpRequestException ex)
            {
                var permanent=ex.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.UnprocessableEntity or HttpStatusCode.Conflict;
                var retry=ex is AgentApiException apiError && apiError.RetryAfter is { } serverDelay && serverDelay>TimeSpan.Zero ? serverDelay : TimeSpan.FromSeconds(30+Random.Shared.Next(30));
                await queue.RetryAsync(pending.Select(x=>x.EventId),retry,ex.Message,permanent,ct);
            }
        }
    }
    private static string LocalKey(Evidence e) => e.Kind==EvidenceKind.Proxy ? "proxy:"+(e.UserSid??"machine")+":"+e.ObjectKey : "product:"+e.ProductId+":"+(e.UserSid??"machine");
    private static Dictionary<string,string> BuildLocalFindings(PolicyDocument policy,ScanSnapshot snapshot,ComplianceReport report)
    {
        var now=DateTimeOffset.UtcNow;
        var known=policy.Products.Select(p=>p.Id).ToHashSet(StringComparer.Ordinal);
        var findings=new Dictionary<string,string>();
        foreach(var e in snapshot.Evidence)
        {
            if(!e.Confirmed || e.Kind is not (EvidenceKind.Installation or EvidenceKind.Process or EvidenceKind.Extension or EvidenceKind.Proxy) || e.Kind!=EvidenceKind.Proxy && !known.Contains(e.ProductId)) continue;
            var module=e.Kind switch { EvidenceKind.Installation=>"installed",EvidenceKind.Extension=>"extensions",EvidenceKind.Proxy=>"proxy",_=>"processes" };
            var times=snapshot.Modules.Where(m=>m.Module==module && (m.Scope==e.UserSid || m.Scope=="machine")).Select(m=>m.CollectedAt).ToArray();
            var sourceTime=e.CollectedAt??(times.Length>0?times.Min():snapshot.CollectedAt);
            var minutes=e.Kind is EvidenceKind.Installation or EvidenceKind.Extension?policy.InventoryFreshMinutes:policy.LightweightFreshMinutes;
            if(sourceTime<now.AddMinutes(-minutes) || sourceTime>now.AddMinutes(2)) continue;
            findings[LocalKey(e)]=e.ProductName+"："+e.Summary;
        }
        if(report.CoverageGaps.Length>0) findings["health:coverage"]="采集或防护覆盖不完整；请联系管理员查看设备报告";
        return findings;
    }
    private static Task<ScanSnapshot> CollectNativeAsync(string deviceId,PolicyDocument policy,ScanSnapshot? previous,CancellationToken ct)
    {
        if(!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        return new WindowsCollector().CollectAsync(deviceId,policy,ct,previous);
    }
    private static HttpClient CreateInternalClient() => new(new HttpClientHandler { UseProxy=false }) { Timeout=TimeSpan.FromSeconds(30) };
}
