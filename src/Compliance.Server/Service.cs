using System.Security.Cryptography;
using Compliance.Core;
namespace Compliance.Server;
public sealed class ComplianceService(Store store,Settings settings,TimeProvider clock) : IDisposable
{
    readonly ECDsa signer=ECDsa.Create();
    public string PublicKey=>signer.ExportSubjectPublicKeyInfoPem();
    public string KeyId=>Secrets.Hash(PublicKey)[..16];
    public DateTimeOffset Now=>clock.GetUtcNow();
    public async Task Initialize()
    {
        await store.Initialize();
        if(string.IsNullOrWhiteSpace(settings.SigningKeyPath))throw new InvalidOperationException("Configure a durable Compliance:SigningKeyPath");
        var keyPath=Path.GetFullPath(settings.SigningKeyPath);Directory.CreateDirectory(Path.GetDirectoryName(keyPath)!);
        if(!File.Exists(keyPath)){
            using var created=ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var options=new FileStreamOptions {Mode=FileMode.CreateNew,Access=FileAccess.Write};
            if(!OperatingSystem.IsWindows())options.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;
            using var stream=new FileStream(keyPath,options);using var writer=new StreamWriter(stream);writer.Write(created.ExportECPrivateKeyPem());
        }
        signer.ImportFromPem(await File.ReadAllTextAsync(keyPath));
        await store.Transaction(async tx=>{
            foreach(var user in Wire.Read<BootstrapUser[]>(settings.BootstrapUsers)){
                if(string.IsNullOrWhiteSpace(user.Username) || user.Username.Length>100 || user.Password.Length<16 || user.Roles.Length==0 || user.Roles.Any(r=>r is not ("Reader" or "Operator" or "Publisher" or "Reviewer")))throw new InvalidOperationException("Bootstrap users need names, >=16 character passwords and defined roles");
                if(await tx.Get<UserRecord>("user",user.Username)==null){await tx.Put("user",user.Username,new UserRecord(user.Username,Secrets.Password(user.Password),user.Roles));await tx.Audit("bootstrap","CreateUser",user.Username,Now);}
            }
            if(await tx.Get<SignedPolicy>("policy","current") is { } persisted && persisted.KeyId!=KeyId)throw new InvalidOperationException("Configured signing key does not match persisted policy; restore original key");
            if(await tx.Get<SignedPolicy>("policy","current")==null){var doc=PolicySeed.Create() with {Mode="Audit",Version=1,IssuedAt=Now,ExpiresAt=Now.AddDays(30)};var signed=PolicyCrypto.Sign(doc,signer,KeyId);await tx.Put("policy","current",signed);await tx.Put("release","1",signed);await tx.Audit("bootstrap","SeedAuditPolicy","1",Now);}
            return true;
        });
    }
    public Task<T> Tx<T>(Func<Transaction,Task<T>> action)=>store.Transaction(action);
    public Task<DeviceRecord> Device(Transaction tx,string id)=>RequireDevice(tx,id);
    static async Task<DeviceRecord> RequireDevice(Transaction tx,string id)=>await tx.Get<DeviceRecord>("device",id)??throw new ApiError(404,"Device not found");
    public string Online(DeviceRecord device)=>device.LastHeartbeat is null || Now-device.LastHeartbeat>=TimeSpan.FromMinutes(5)?"Offline":Now-device.LastHeartbeat>=TimeSpan.FromMinutes(3)?"SuspectedOffline":"Online";
    public async Task<PolicyDocument> Current(Transaction tx)=>Wire.Read<PolicyDocument>((await tx.Get<SignedPolicy>("policy","current"))!.Payload);
    public async Task<SignedPolicy> AssignedPolicy(Transaction tx,DeviceRecord device)=>await tx.Get<SignedPolicy>("release",device.TargetPolicyVersion.ToString())??throw new ApiError(409,"Assigned policy unavailable");
    public async Task<ComplianceReport> Report(Transaction tx,DeviceRecord device)
    {
        if(device.Snapshot==null)throw new ApiError(404,"No scan available");
        var report=ReportEngine.Evaluate(Wire.Read<PolicyDocument>((await AssignedPolicy(tx,device)).Payload),device.Snapshot,Now);
        return Online(device)=="Online"?report:report with {Verdict=Verdict.UNKNOWN,Summary="设备失联或疑似失联，当前合规无法判断；保留历史检查结果",CoverageGaps=report.CoverageGaps.Append("缺少新鲜心跳").ToArray()};
    }
    public async Task<DeviceSummary> Summary(Transaction tx,DeviceRecord d)
    {
        var policy=Wire.Read<PolicyDocument>((await AssignedPolicy(tx,d)).Payload);var report=d.Snapshot==null?null:ReportEngine.Evaluate(policy,d.Snapshot,Now);
        var historicalPolicy=d.Snapshot==null?null:await tx.Get<SignedPolicy>("release",d.Snapshot.PolicyVersion.ToString());
        var last=d.Snapshot==null||historicalPolicy==null?null:ReportEngine.Evaluate(Wire.Read<PolicyDocument>(historicalPolicy.Payload),d.Snapshot,d.Snapshot.CollectedAt);
        var online=Online(d);
        return new(d.Id,d.HostName,d.LastHeartbeat,online,online=="Online"?report?.Verdict??Verdict.UNKNOWN:Verdict.UNKNOWN,last?.Verdict,d.Snapshot?.CollectedAt,policy.Version,d.AppliedPolicyVersion,report?.ProtectionStatus??"未取得检查结果",report?.ViolationCount??0,d.Snapshot?.Simulated??false);
    }
    public async Task UpdateOffline(Transaction tx)
    {
        foreach(var d in await tx.All<DeviceRecord>("device")){
            string id="offline:"+d.Id;var alert=await tx.Get<AlertSummary>("alert",id);
            if(Online(d)=="Offline" && d.LastHeartbeat!=null && alert?.State!="Active"){
                await tx.Put("alert",id,new AlertSummary(id,d.Id,d.HostName,"Offline","heartbeat","设备心跳缺失，原因未确认","Active",0,Now,Now,false));
                await tx.Audit("system","Offline",d.Id,Now);
            }else if(Online(d)=="Online" && alert?.State=="Active"){
                await tx.Put("alert",id,alert with {State="Resolved",LastSeen=Now});await tx.Audit("system","OnlineRecovered",d.Id,Now);
            }
        }
    }
    public async Task<EventReceipt> Events(Transaction tx,string deviceId,EventBatch batch)
    {
        if(batch.Events is null || batch.Events.Length is 0 or >500 || batch.Events.Any(e=>e is null))throw new ApiError(400,"Batch requires 1..500 events");
        var d=await Device(tx,deviceId);var accepted=new HashSet<string>();
        foreach(var e in batch.Events){
            if(string.IsNullOrWhiteSpace(e.EventId)||e.EventId.Length>128||string.IsNullOrWhiteSpace(e.ObjectKey)||e.ObjectKey.Length>256||e.Sequence<=0||e.SourceTime>Now.AddMinutes(5)||(e.Detail?.Length??0)>2048||e.Type is not ("Snapshot" or "Violation" or "Recovered" or "Health" or "BlockedAttempt"))throw new ApiError(400,"Invalid event");
            if(e.Type=="Snapshot" && e.Snapshot==null)throw new ApiError(400,"Snapshot event needs snapshot");
            if(e.Snapshot is { } s && (s.SchemaVersion!=1||s.DeviceId!=deviceId||s.CollectedAt>Now.AddMinutes(5)||s.Evidence==null||s.Modules==null||s.Controls==null||s.Evidence.Length>5000||s.Modules.Length>1000||s.Controls.Length>100||s.Evidence.Any(e=>e is null)||s.Modules.Any(m=>m is null)||s.Controls.Any(c=>c is null)))throw new ApiError(400,"Invalid snapshot");
            string id=deviceId+":"+e.EventId;var existing=await tx.Get<StoredEvent>("event",id);var fingerprint=Secrets.Hash(Wire.Serialize(e));
            if(existing!=null){if(existing.Fingerprint!=fingerprint)throw new ApiError(409,"Event id already has different content");accepted.Add(e.EventId);continue;}
            var sequenceId=deviceId+":"+e.Sequence;var seq=await tx.Get<string>("sequence",sequenceId);
            if(seq!=null)throw new ApiError(409,"Sequence already belongs to a different event");
            var safe=e with {ObjectKey=EvidenceSanitizer.Clean(e.ObjectKey),Detail=e.Detail is null?null:EvidenceSanitizer.Clean(e.Detail),Snapshot=e.Snapshot is null?null:EvidenceSanitizer.Sanitize(e.Snapshot)};
            await tx.Put("event",id,new StoredEvent(fingerprint,safe,Now));await tx.Put("sequence",sequenceId,e.EventId);accepted.Add(e.EventId);
            if(e.Snapshot is { } snapshot && (d.Snapshot==null || snapshot.CollectedAt>=d.Snapshot.CollectedAt && e.Sequence>d.SnapshotSequence)){
                d=d with {Snapshot=EvidenceSanitizer.Sanitize(snapshot),SnapshotSequence=e.Sequence};
                await SnapshotAlerts(tx,d,e.Sequence);
            }
            if(e.Type!="Snapshot"){
                string incidentId=deviceId+":"+Secrets.Hash(e.ObjectKey);var alert=await tx.Get<AlertSummary>("alert",incidentId);
                if(alert==null || e.Sequence>alert.LastSequence){
                    string type=e.Type=="Recovered"?alert?.Type??"Violation":e.Type;
                    await tx.Put("alert",incidentId,new AlertSummary(incidentId,deviceId,d.HostName,type,safe.ObjectKey,safe.Detail??e.Type,e.Type=="Recovered"?"Resolved":"Active",e.Sequence,alert?.FirstSeen??e.SourceTime,e.SourceTime,false));
                }
            }
        }
        await tx.Put("device",deviceId,d);return new(accepted.ToArray());
    }
    async Task SnapshotAlerts(Transaction tx,DeviceRecord device,long sequence)
    {
        var snapshot=device.Snapshot!;var policy=Wire.Read<PolicyDocument>((await AssignedPolicy(tx,device)).Payload);
        var report=ReportEngine.Evaluate(policy,snapshot,Now);
        var confirmed=report.Verdict==Verdict.FAIL?snapshot.Evidence.Where(e=>ReportEngine.Evaluate(policy,snapshot with {Evidence=[e]},Now).Verdict==Verdict.FAIL).ToArray():[];
        string ObjectId(Evidence e)=>e.ProductId+"|"+(e.UserSid??"machine")+(e.Kind==EvidenceKind.Proxy?"|"+e.ObjectKey:"");
        string Module(Evidence e)=>e.Kind switch {EvidenceKind.Installation=>e.Source=="Appx"?"appx":"installed",EvidenceKind.Extension=>"extensions",EvidenceKind.Proxy=>"proxy",_=>"processes"};
        var present=new HashSet<string>();
        foreach(var group in confirmed.GroupBy(ObjectId)){
            var id="snapshot:"+device.Id+":"+Secrets.Hash(group.Key);present.Add(id);
            var previous=await tx.Get<AlertSummary>("alert",id);if(previous!=null&&previous.LastSequence>=sequence)continue;
            var oldMetadata=await tx.Get<SnapshotIncident>("snapshot-incident",id);
            var modules=group.Select(Module).Concat(oldMetadata?.Modules??[]).Distinct().ToArray();
            await tx.Put("snapshot-incident",id,new SnapshotIncident(id,device.Id,group.First().UserSid??"machine",modules));
            await tx.Put("alert",id,new AlertSummary(id,device.Id,device.HostName,"Violation",group.Key,string.Join("；",group.Select(e=>e.ProductName+": "+e.Summary).Distinct()),"Active",sequence,previous?.FirstSeen??snapshot.CollectedAt,snapshot.CollectedAt,previous?.State=="Active"&&previous.Acknowledged));
        }
        if(report.CoverageGaps.Length!=0)return;
        foreach(var metadata in (await tx.All<SnapshotIncident>("snapshot-incident")).Where(x=>x.DeviceId==device.Id&&!present.Contains(x.Id))){
            var previous=await tx.Get<AlertSummary>("alert",metadata.Id);
            if(previous==null||previous.LastSequence>=sequence)continue;
            bool complete=metadata.Modules.All(module=>snapshot.Modules.Any(m=>m.Module==module&&m.Scope==metadata.Scope&&m.Status=="Complete"&&m.CollectedAt>=Now.AddMinutes(-(module is "installed" or "appx" or "extensions"?policy.InventoryFreshMinutes:policy.LightweightFreshMinutes))&&m.CollectedAt<=Now.AddMinutes(2)));
            if(complete){await tx.Put("alert",metadata.Id,previous with {State="Resolved",LastSeen=snapshot.CollectedAt,LastSequence=sequence});if(previous.State=="Active")await tx.Audit(device.Id,"SnapshotRecovered",metadata.Id,Now);}
        }
    }
    public async Task ValidatePublish(Transaction tx,DraftRecord draft)
    {
        var doc=draft.Document;var current=await Current(tx);
        if(draft.Published||draft.ApprovedBy==null||draft.ApprovedBy==draft.CreatedBy||!draft.ImpactReviewed||doc.Version<=current.Version||doc.ExpiresAt<=Now||doc.IssuedAt>Now.AddMinutes(2))throw new ApiError(409,"Independent review, impact review and increasing valid version required");
        if(doc.Mode=="Enforce"){
            if(doc.TargetDeviceIds.Length==0||doc.RequiredControls.Length==0)throw new ApiError(409,"Enforcement requires explicit pilot targets and declared controls");
            foreach(var id in doc.TargetDeviceIds){var d=await Device(tx,id);if(Online(d)!="Online"||d.Snapshot==null||d.Snapshot.Simulated||d.Snapshot.CollectedAt<Now.AddMinutes(-10))throw new ApiError(409,"Pilot capabilities are stale or unverified");foreach(var control in doc.RequiredControls){var c=d.Controls?.FirstOrDefault(x=>x.Id==control);if(c==null||!c.Verified||c.RebootRequired||c.Version!=current.Version||c.State is not ("Applied" or "Verified"))throw new ApiError(409,"Required control capability not verified");}}
            if(doc.RequiredControls.Contains("network"))throw new ApiError(409,"Generic network enforcement adapter is not implemented");
            if(doc.ApplicationRules.Length==0||doc.BlockDomains.Length>1000)throw new ApiError(409,"No exact application rules or browser capacity exceeded");
        }
    }
    public SignedPolicy Sign(PolicyDocument doc)=>PolicyCrypto.Sign(doc,signer,KeyId);
    public void Dispose()=>signer.Dispose();
}
public sealed class OfflineMonitor(ComplianceService service,ILogger<OfflineMonitor> logger):BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer=new PeriodicTimer(TimeSpan.FromSeconds(15));
        while(await timer.WaitForNextTickAsync(stoppingToken))try{await service.Tx(async tx=>{await service.UpdateOffline(tx);return true;});}catch(Exception e)when(!stoppingToken.IsCancellationRequested){logger.LogError(e,"Offline status refresh failed");}
    }
}
