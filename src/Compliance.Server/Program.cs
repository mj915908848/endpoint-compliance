using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Compliance.Core;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
namespace Compliance.Server;
public partial class Program
{
    public static async Task Main(string[] args)
    {
        var b=WebApplication.CreateBuilder(new WebApplicationOptions { Args=args, WebRootPath=Path.Combine(AppContext.BaseDirectory,"wwwroot") });
        b.Services.AddSingleton(_=>b.Configuration.GetSection("Compliance").Get<Settings>()??new());
        b.Services.AddSingleton<TimeProvider>(TimeProvider.System);b.Services.AddSingleton<Store>();b.Services.AddSingleton<ComplianceService>();b.Services.AddHostedService<OfflineMonitor>();
        b.Services.ConfigureHttpJsonOptions(o=>o.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
        b.WebHost.ConfigureKestrel(o=>o.Limits.MaxRequestBodySize=2*1024*1024);
        b.Services.AddRateLimiter(o=>{o.RejectionStatusCode=429;o.AddPolicy("login",c=>RateLimitPartition.GetFixedWindowLimiter(c.Connection.RemoteIpAddress?.ToString()??"loopback",_=>new FixedWindowRateLimiterOptions{PermitLimit=20,Window=TimeSpan.FromMinutes(1),QueueLimit=0}));});
        var app=b.Build();var settings=app.Services.GetRequiredService<Settings>();var service=app.Services.GetRequiredService<ComplianceService>();
        if(settings.DemoMode){
            var urls=b.Configuration["urls"]??"http://127.0.0.1:5080";
            foreach(var url in urls.Split(';')){if(!Uri.TryCreate(url,UriKind.Absolute,out var uri)||!(uri.Host=="localhost"||IPAddress.TryParse(uri.Host,out var address)&&IPAddress.IsLoopback(address)))throw new InvalidOperationException("Demo listeners must be loopback");}
            if(b.Configuration["urls"]==null)app.Urls.Add("http://127.0.0.1:5080");
        }
        if(settings.TrustedProxies.Length>0){
            var options=new ForwardedHeadersOptions {ForwardedHeaders=ForwardedHeaders.XForwardedFor|ForwardedHeaders.XForwardedProto,ForwardLimit=1};
            options.KnownIPNetworks.Clear();options.KnownProxies.Clear();foreach(var proxy in settings.TrustedProxies)options.KnownProxies.Add(IPAddress.Parse(proxy));app.UseForwardedHeaders(options);
        }
        await service.Initialize();
        app.Use(async(c,next)=>{
            try{
                if(settings.DemoMode){if(c.Connection.RemoteIpAddress is { } remote && !IPAddress.IsLoopback(remote))throw new ApiError(403,"Demo accepts loopback only");}
                else if(!c.Request.IsHttps)throw new ApiError(400,"HTTPS is required");
                c.Response.Headers["X-Content-Type-Options"]="nosniff";c.Response.Headers["Content-Security-Policy"]="default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'";
                if(c.Request.Path.StartsWithSegments("/api"))c.Response.Headers.CacheControl="no-store";
                await next(c);
            }catch(ApiError e){c.Response.StatusCode=e.Status;await c.Response.WriteAsJsonAsync(new {error=e.Message});}
            catch(JsonException){c.Response.StatusCode=400;await c.Response.WriteAsJsonAsync(new {error="Invalid JSON"});}
            catch(BadHttpRequestException e){c.Response.StatusCode=e.StatusCode;await c.Response.WriteAsJsonAsync(new {error="Invalid request"});}
        });
        app.UseRateLimiter();
        app.Use(async(c,next)=>{
            var path=c.Request.Path.Value??"";
            if(path.StartsWith("/api/agent/",StringComparison.Ordinal) && path!="/api/agent/enroll")await AuthenticateAgent(c,service);
            else if(path.StartsWith("/api/",StringComparison.Ordinal) && path is not ("/api/auth/login" or "/api/status" or "/api/agent/enroll"))await AuthenticateAdmin(c,service);
            await next(c);
        });
        Map(app,service,settings);app.UseDefaultFiles();app.UseStaticFiles();
        app.MapFallback(async c=>{if(c.Request.Path.StartsWithSegments("/api")){c.Response.StatusCode=404;await c.Response.WriteAsJsonAsync(new {error="Endpoint not found"});}else {var index=Path.Combine(app.Environment.WebRootPath??Path.Combine(app.Environment.ContentRootPath,"wwwroot"),"index.html");if(File.Exists(index)){c.Response.ContentType="text/html";await c.Response.SendFileAsync(index);}else c.Response.StatusCode=404;}});
        await app.RunAsync();
    }
    static async Task AuthenticateAdmin(HttpContext c,ComplianceService s)
    {
        var token=c.Request.Cookies["compliance-session"];if(string.IsNullOrWhiteSpace(token))throw new ApiError(401,"Login required");
        var user=await s.Tx(async tx=>{
            var session=await tx.Get<SessionRecord>("session",Secrets.Hash(token));if(session==null||session.ExpiresAt<=s.Now)throw new ApiError(401,"Session expired");
            if(!HttpMethods.IsGet(c.Request.Method)&&!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(session.CsrfToken),Encoding.UTF8.GetBytes(c.Request.Headers["X-CSRF-Token"].ToString())))throw new ApiError(403,"CSRF token required");
            c.Items["session"]=session;return await tx.Get<UserRecord>("user",session.Username)??throw new ApiError(401,"Account unavailable");
        });c.Items["user"]=user;
    }
    static async Task AuthenticateAgent(HttpContext c,ComplianceService s)
    {
        string device=c.Request.Headers["X-Device-Id"].ToString(),timestamp=c.Request.Headers["X-Timestamp"].ToString(),nonce=c.Request.Headers["X-Nonce"].ToString(),signature=c.Request.Headers["X-Signature"].ToString();
        if(device.Length>100||!long.TryParse(timestamp,out var seconds)||Math.Abs((double)s.Now.ToUnixTimeSeconds()-seconds)>300||!Guid.TryParse(nonce,out _))throw new ApiError(401,"Invalid device authentication");
        c.Request.EnableBuffering();using var bytes=new MemoryStream();await c.Request.Body.CopyToAsync(bytes);c.Request.Body.Position=0;
        if(bytes.Length>2*1024*1024)throw new ApiError(413,"Body too large");
        var raw=bytes.ToArray();await s.Tx(async tx=>{
            var d=await tx.Get<DeviceRecord>("device",device);if(d==null||!RequestAuthentication.Verify(d.PublicKeyPem,c.Request.Method,c.Request.Path,timestamp,nonce,raw,signature))throw new ApiError(401,"Invalid device signature");
            if(!await tx.AcceptNonce(device,nonce,s.Now))throw new ApiError(401,"Nonce already used");return true;
        });c.Items["device"]=device;
    }
    static UserRecord Require(HttpContext c,string role){var u=c.Items["user"] as UserRecord??throw new ApiError(401,"Login required");if(!u.Roles.Contains(role))throw new ApiError(403,"Role required: "+role);return u;}
    static string Agent(HttpContext c)=>(string)c.Items["device"]!;
    static async Task<T> Body<T>(HttpContext c)=>await c.Request.ReadFromJsonAsync<T>(Wire.Json)??throw new ApiError(400,"Body required");
    static void Map(WebApplication app,ComplianceService s,Settings settings)
    {
        app.MapGet("/api/status",()=>new {mode=settings.DemoMode?"LoopbackDemo":"Production",storage=settings.Storage,networkCapabilities=new[]{new {id="network",implemented=false,verified=false,detail="通用 API 网络执行层未实现"}},policyPublicKeyPem=s.PublicKey,policyKeyId=s.KeyId});
        app.MapPost("/api/auth/login",async(HttpContext c)=>{
            var login=await Body<LoginRequest>(c);if(string.IsNullOrWhiteSpace(login.Username)||login.Username.Length>100||login.Password==null||login.Password.Length>1024)throw new ApiError(401,"Invalid credentials");
            var result=await s.Tx(async tx=>{
                var user=await tx.Get<UserRecord>("user",login.Username);if(user==null||!Secrets.Check(login.Password,user.PasswordHash))throw new ApiError(401,"Invalid credentials");
                var token=Secrets.Token();var session=new SessionRecord(user.Username,Secrets.Token(),s.Now.AddHours(8));await tx.Put("session",Secrets.Hash(token),session);await tx.Audit(user.Username,"Login",user.Username,s.Now);return (user,token,session);
            });
            c.Response.Cookies.Append("compliance-session",result.token,new CookieOptions{HttpOnly=true,Secure=c.Request.IsHttps,SameSite=SameSiteMode.Strict,Expires=result.session.ExpiresAt,Path="/"});return Results.Json(new {username=result.user.Username,roles=result.user.Roles,csrfToken=result.session.CsrfToken});
        }).RequireRateLimiting("login");
        app.MapGet("/api/me",(HttpContext c)=>{var u=(UserRecord)c.Items["user"]!;var session=(SessionRecord)c.Items["session"]!;return new {username=u.Username,roles=u.Roles,csrfToken=session.CsrfToken};});
        app.MapPost("/api/auth/logout",async(HttpContext c)=>{var user=(UserRecord)c.Items["user"]!;await s.Tx(async tx=>{await tx.Delete("session",Secrets.Hash(c.Request.Cookies["compliance-session"]!));await tx.Audit(user.Username,"Logout",user.Username,s.Now);return true;});c.Response.Cookies.Delete("compliance-session");return new {ok=true};});
        app.MapGet("/api/devices",async(HttpContext c)=>{Require(c,"Reader");return await s.Tx(async tx=>{await s.UpdateOffline(tx);var list=new List<DeviceSummary>();foreach(var d in await tx.All<DeviceRecord>("device"))list.Add(await s.Summary(tx,d));return list.OrderBy(d=>d.HostName).ToArray();});});
        app.MapGet("/api/devices/{id}",async(HttpContext c,string id)=>{Require(c,"Reader");return await s.Tx(async tx=>{var d=await s.Device(tx,id);return new {device=await s.Summary(tx,d),snapshot=d.Snapshot,controls=d.Controls??[],pendingCommands=(await tx.All<CommandRecord>("command")).Count(x=>x.DeviceId==id&&x.Reply==null&&x.Command.ExpiresAt>s.Now)};});});
        app.MapGet("/api/devices/{id}/report",async(HttpContext c,string id)=>{Require(c,"Reader");return await s.Tx(async tx=>await s.Report(tx,await s.Device(tx,id)));});
        app.MapGet("/api/devices/{id}/report.md",async(HttpContext c,string id)=>{Require(c,"Reader");return Results.Text(await s.Tx(async tx=>ReportRenderer.Markdown(await s.Report(tx,await s.Device(tx,id)))),"text/markdown; charset=utf-8");});
        app.MapGet("/api/alerts",async(HttpContext c)=>{Require(c,"Reader");return await s.Tx(async tx=>{await s.UpdateOffline(tx);return (await tx.All<AlertSummary>("alert")).OrderByDescending(a=>a.LastSeen).ToArray();});});
        app.MapPost("/api/alerts/{id}/ack",async(HttpContext c,string id)=>{var u=Require(c,"Operator");return await s.Tx(async tx=>{var a=await tx.Get<AlertSummary>("alert",id)??throw new ApiError(404,"Alert not found");await tx.Put("alert",id,a with {Acknowledged=true});await tx.Audit(u.Username,"AcknowledgeAlert",id,s.Now);return new {ok=true};});});
        app.MapGet("/api/audit",async(HttpContext c)=>{Require(c,"Reader");return await s.Tx(async tx=>(await tx.All<AuditRecord>("audit")).OrderByDescending(a=>a.At).Take(500).ToArray());});
        app.MapPost("/api/enrollment-codes",async(HttpContext c)=>{var u=Require(c,"Operator");var request=await Body<CodeRequest>(c);var minutes=request.ExpiresMinutes??15;if(minutes is <1 or >60)throw new ApiError(400,"Expiry must be 1..60 minutes");var code=Secrets.Token();var expiry=s.Now.AddMinutes(minutes);await s.Tx(async tx=>{await tx.Put("code",Secrets.Hash(code),new CodeRecord(expiry,false));await tx.Audit(u.Username,"CreateEnrollmentCode","[redacted]",s.Now);return true;});return new {code,expiresAt=expiry};});
        app.MapGet("/api/policies/current",async(HttpContext c)=>{Require(c,"Reader");return await s.Tx(async tx=>(await tx.Get<SignedPolicy>("policy","current"))!);});
        app.MapGet("/api/policies/drafts",async(HttpContext c)=>{Require(c,"Reader");return await s.Tx(async tx=>await tx.All<DraftRecord>("draft"));});
        app.MapPost("/api/policies/drafts",async(HttpContext c)=>{var u=Require(c,"Publisher");var r=await Body<DraftRequest>(c);var doc=r.Document??throw new ApiError(400,"Policy required");if(doc.SchemaVersion!=1||doc.Mode is not ("Audit" or "Enforce")||doc.RequiredModules==null||doc.RequiredControls==null||doc.TargetDeviceIds==null||doc.Products==null||doc.ApplicationRules==null||doc.BlockDomains==null||!doc.DenyInstalled||!doc.DenyProxy||doc.RequiredModules.Length==0||doc.Products.Length>5000||doc.BlockDomains.Length>1000||doc.ApplicationRules.Length>1000)throw new ApiError(400,"Invalid or incomplete policy");try{PolicyCrypto.Validate(doc);}catch(ArgumentException){throw new ApiError(400,"Invalid policy content");}return await s.Tx(async tx=>{var draft=new DraftRecord(Guid.NewGuid().ToString(),doc,u.Username,null,false,r.ImpactReviewed);await tx.Put("draft",draft.Id,draft);await tx.Audit(u.Username,"CreatePolicyDraft",draft.Id,s.Now);return draft;});});
        app.MapPost("/api/policies/{id}/approve",async(HttpContext c,string id)=>{var u=Require(c,"Reviewer");return await s.Tx(async tx=>{var d=await tx.Get<DraftRecord>("draft",id)??throw new ApiError(404,"Draft not found");if(d.Published||d.CreatedBy==u.Username||!d.ImpactReviewed)throw new ApiError(409,"Independent reviewer and impact review required");d=d with {ApprovedBy=u.Username};await tx.Put("draft",id,d);await tx.Audit(u.Username,"ApprovePolicy",id,s.Now);return d;});});
        app.MapPost("/api/policies/{id}/publish",async(HttpContext c,string id)=>{var u=Require(c,"Publisher");return await s.Tx(async tx=>{var d=await tx.Get<DraftRecord>("draft",id)??throw new ApiError(404,"Draft not found");if(d.ApprovedBy==u.Username)throw new ApiError(409,"Publisher must differ from reviewer");await s.ValidatePublish(tx,d);var signed=s.Sign(d.Document);await tx.Put("release",d.Document.Version.ToString(),signed);await tx.Put("policy","current",signed);foreach(var device in await tx.All<DeviceRecord>("device")){if(d.Document.TargetDeviceIds.Length==0||d.Document.TargetDeviceIds.Contains(device.Id))await tx.Put("device",device.Id,device with {TargetPolicyVersion=d.Document.Version});}await tx.Put("draft",id,d with {Published=true});await tx.Audit(u.Username,"PublishPolicy",id,s.Now);return signed;});});
        app.MapPost("/api/devices/{id}/commands",async(HttpContext c,string id)=>{var u=Require(c,"Operator");var r=await Body<CommandRequest>(c);if(r.Type!="ScanNow")throw new ApiError(400,"Only ScanNow is supported");return await s.Tx(async tx=>{await s.Device(tx,id);var command=new DeviceCommand(Guid.NewGuid().ToString(),"ScanNow",s.Now.AddMinutes(10));await tx.Put("command",command.Id,new CommandRecord(id,command));await tx.Audit(u.Username,"RequestScan",id,s.Now);return command;});});
        app.MapPost("/api/agent/enroll",async(HttpContext c)=>{
            var r=await Body<EnrollmentRequest>(c);if(string.IsNullOrWhiteSpace(r.Code)||r.Code.Length>256||string.IsNullOrWhiteSpace(r.HostName)||r.HostName.Length>256||r.PublicKeyPem==null||r.PublicKeyPem.Length>2048)throw new ApiError(400,"Invalid enrollment");
            string publicKey;try{using var key=ECDsa.Create();key.ImportFromPem(r.PublicKeyPem);if(key.KeySize<256)throw new CryptographicException();publicKey=key.ExportSubjectPublicKeyInfoPem();}catch(Exception e)when(e is ArgumentException or CryptographicException){throw new ApiError(400,"Valid ECDSA public key required");}
            return await s.Tx(async tx=>{var hash=Secrets.Hash(r.Code);var code=await tx.Get<CodeRecord>("code",hash);if(code==null||code.Used||code.ExpiresAt<=s.Now)throw new ApiError(400,"Code invalid, expired or used");if((await tx.All<DeviceRecord>("device")).Any(d=>d.PublicKeyPem==publicKey))throw new ApiError(400,"Key already enrolled");var id=Guid.NewGuid().ToString();await tx.Put("device",id,new DeviceRecord(id,EvidenceSanitizer.Clean(r.HostName),publicKey,TargetPolicyVersion:(await s.Current(tx)).TargetDeviceIds.Length==0?(await s.Current(tx)).Version:1));await tx.Put("code",hash,code with {Used=true});await tx.Audit("enrollment","EnrollDevice",id,s.Now);return new EnrollmentResponse(id,s.PublicKey,s.KeyId);});
        }).RequireRateLimiting("login");
        app.MapPost("/api/agent/heartbeat",async(HttpContext c)=>{var r=await Body<HeartbeatRequest>(c);if(string.IsNullOrWhiteSpace(r.HostName)||r.HostName.Length>256||r.Controls==null||r.Controls.Length>100||r.Controls.Any(x=>x is null)||r.SourceTime>s.Now.AddMinutes(5)||r.SourceTime<s.Now.AddMinutes(-5))throw new ApiError(400,"Invalid heartbeat");return await s.Tx(async tx=>{var d=await s.Device(tx,Agent(c));await tx.Put("device",d.Id,d with {HostName=EvidenceSanitizer.Clean(r.HostName),LastHeartbeat=s.Now,AppliedPolicyVersion=r.PolicyVersion,Controls=r.Controls.Select(x=>x with {Detail=EvidenceSanitizer.Clean(x.Detail)}).ToArray()});await s.UpdateOffline(tx);return new {ok=true};});});
        app.MapGet("/api/agent/policy",async Task<SignedPolicy> (HttpContext c)=>await s.Tx(async tx=>await s.AssignedPolicy(tx,await s.Device(tx,Agent(c)))));
        app.MapPost("/api/agent/events",async(HttpContext c)=>{var batch=await Body<EventBatch>(c);return await s.Tx(tx=>s.Events(tx,Agent(c),batch));});
        app.MapGet("/api/agent/commands",async Task<DeviceCommand[]> (HttpContext c)=>await s.Tx(async tx=>(await tx.All<CommandRecord>("command")).Where(x=>x.DeviceId==Agent(c)&&x.Reply==null&&x.Command.ExpiresAt>s.Now).Select(x=>x.Command).ToArray()));
        app.MapPost("/api/agent/commands/{id}/ack",async(HttpContext c,string id)=>{var reply=await Body<CommandReply>(c);if(reply.Detail==null||reply.Detail.Length>2048)throw new ApiError(400,"Invalid reply");reply=reply with {Detail=EvidenceSanitizer.Clean(reply.Detail)};return await s.Tx(async tx=>{var command=await tx.Get<CommandRecord>("command",id);if(command==null||command.DeviceId!=Agent(c))throw new ApiError(404,"Command not found");if(command.Reply!=null&&command.Reply!=reply)throw new ApiError(409,"Reply already recorded");if(command.Reply==null){await tx.Put("command",id,command with {Reply=reply with {Detail=EvidenceSanitizer.Clean(reply.Detail)}});await tx.Audit(Agent(c),"ScanReply",id,s.Now);}return new {ok=true};});});
    }
}
public record LoginRequest(string Username,string Password);
public record CodeRequest(int? ExpiresMinutes=null);
public record DraftRequest(PolicyDocument? Document,bool ImpactReviewed=false);
public record CommandRequest(string Type);
