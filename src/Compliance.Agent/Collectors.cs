using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using System.Runtime.InteropServices;
using System.IO.Compression;
using Compliance.Core;
using Microsoft.Win32;

namespace Compliance.Agent;

public static class FixtureCollector
{
    public static async Task<ScanSnapshot> LoadAsync(string path, CancellationToken ct = default)
    {
        var source = Wire.Read<ScanSnapshot>(await File.ReadAllTextAsync(path, ct));
        return source with { Simulated = true, Platform = "Windows", CollectedAt = DateTimeOffset.UtcNow };
    }
}

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed class WindowsCollector
{
    private sealed record Profile(string Sid, string Path, bool HiveLoaded, bool PathAvailable);
    public static (Evidence[] Evidence, int Errors) ScanVsCodeExtensions(string root, string sid, PolicyDocument policy)
    {
        if(!DirectoryPresent(root)) return ([],0);
        var found=new List<Evidence>();
        var errors=0;
        var host=Path.GetFileName(Path.GetDirectoryName(root));
        var obsolete=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var obsoleteFile=Path.Combine(root,".obsolete");
        if(FilePresent(obsoleteFile))
        {
            try
            {
                using var state=JsonDocument.Parse(File.ReadAllText(obsoleteFile));
                if(state.RootElement.ValueKind!=JsonValueKind.Object) throw new JsonException("Invalid extension removal state");
                foreach(var item in state.RootElement.EnumerateObject())
                {
                    if(item.Value.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw new JsonException("Invalid extension removal entry");
                    if(item.Value.GetBoolean()) obsolete.Add(item.Name);
                }
            }
            catch(Exception ex) when(ex is JsonException or IOException or UnauthorizedAccessException) { return ([],1); }
        }
        foreach(var dir in Directory.EnumerateDirectories(root))
        {
            if(dir.EndsWith(".obsolete",StringComparison.OrdinalIgnoreCase) || obsolete.Contains(Path.GetFileName(dir))) continue;
            var manifest=Path.Combine(dir,"package.json");
            try
            {
                if((File.GetAttributes(dir)&FileAttributes.ReparsePoint)!=0 || !FilePresent(manifest)) continue;
                using var doc=JsonDocument.Parse(File.ReadAllText(manifest));
                var publisher=doc.RootElement.TryGetProperty("publisher",out var publisherProperty)?publisherProperty.GetString():null;
                var name=doc.RootElement.TryGetProperty("name",out var nameProperty)?nameProperty.GetString():null;
                if(publisher is null || name is null) continue;
                var id=publisher+"."+name;
                foreach(var rule in policy.Products.Where(r=>r.ExtensionIds.Any(x=>string.Equals(x,id,StringComparison.OrdinalIgnoreCase))))
                    found.Add(new(rule.Id,rule.Name,EvidenceKind.Extension,"ide:"+sid+":"+host+":"+id,"IDE package.json","Exact extension ID: "+id+" in "+host,sid));
            }
            catch(JsonException) { errors++; }
            catch(InvalidOperationException) { errors++; }
            catch(IOException) { errors++; }
            catch(UnauthorizedAccessException) { errors++; }
        }
        return (found.ToArray(),errors);
    }
    public static (Evidence[] Evidence, int Errors) ScanKnownExtensionRoots(string profilePath, string sid, PolicyDocument policy)
    {
        var found=new List<Evidence>();
        var errors=0;
        foreach(var host in new[]{".vscode",".vscode-insiders",".vscode-oss",".cursor",".windsurf",".windsurf-next"})
        {
            var result=ScanVsCodeExtensions(Path.Combine(profilePath,host,"extensions"),sid,policy);
            found.AddRange(result.Evidence);
            errors+=result.Errors;
        }
        return (found.ToArray(),errors);
    }
    public static Evidence? MatchServiceRegistration(string serviceName, string? displayName, PolicyDocument policy)
    {
        var productId=serviceName.ToLowerInvariant() switch
        {
            "clash_verge_service"=>"clash",
            "codexsandboxservice.openai.codex"=>"codex",
            _=>null
        };
        if(productId is null) return null;
        var rule=policy.Products.FirstOrDefault(r=>r.Id==productId);
        return rule is null?null:new Evidence(rule.Id,rule.Name,EvidenceKind.Installation,"service:"+serviceName,"Windows service registry","Registered service name: "+serviceName);
    }
    public static Evidence[] ScanKnownInstallRoot(string root, string? sid, PolicyDocument policy)
    {
        if(!DirectoryPresent(root)) return [];
        var found=new List<Evidence>();
        foreach(var dir in Directory.EnumerateDirectories(root))
        {
            if((File.GetAttributes(dir)&FileAttributes.ReparsePoint)!=0) continue;
            var folder=Path.GetFileName(dir);
            var matching=policy.Products.Where(r=>r.DisplayNames.Any(n=>string.Equals(n,folder,StringComparison.OrdinalIgnoreCase))).ToArray();
            if(matching.Length==0) continue;
            var executables=Directory.EnumerateFiles(dir).Select(Path.GetFileName).Where(n=>n is not null).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach(var rule in matching)
            {
                var executable=rule.ExecutableNames.FirstOrDefault(executables.Contains);
                if(executable is not null)
                    found.Add(new(rule.Id,rule.Name,EvidenceKind.Installation,"install-dir:"+(sid??"machine")+":"+folder,"Known install directory","Folder "+folder+" contains "+executable,sid));
            }
        }
        return found.ToArray();
    }
    public static Evidence[] ScanKnownCliBin(string root, string sid, PolicyDocument policy)
    {
        var found=new List<Evidence>();
        foreach(var (file,id) in new[]{("claude.exe","claude"),("codex.exe","codex"),("gemini.exe","gemini")})
        {
            if(!FilePresent(Path.Combine(root,file))) continue;
            var rule=policy.Products.FirstOrDefault(r=>r.Id==id);
            if(rule is not null) found.Add(new(rule.Id,rule.Name,EvidenceKind.Installation,"cli-file:"+sid+":"+file,"Known user CLI bin","Known CLI executable: "+file,sid) { CollectedAt=DateTimeOffset.UtcNow });
        }
        return found.ToArray();
    }
    public static Evidence? ProxyEnvironmentEvidence(string name, string? value, string? sid)
    {
        if(name.ToUpperInvariant() is not ("HTTP_PROXY" or "HTTPS_PROXY" or "ALL_PROXY") || string.IsNullOrWhiteSpace(value)) return null;
        var scope=sid??"machine";
        return new("proxy","Proxy environment",EvidenceKind.Proxy,"env:"+scope+":"+name.ToUpperInvariant(),"Persistent environment",name.ToUpperInvariant()+" configured (value withheld)",sid);
    }
    public static Evidence? ProcessProxyEnvironmentClue(string name, string? value)
    {
        if(name.ToUpperInvariant() is not ("HTTP_PROXY" or "HTTPS_PROXY" or "ALL_PROXY") || string.IsNullOrWhiteSpace(value)) return null;
        return new("proxy-process-clue","Scan process proxy environment",EvidenceKind.Clue,"env:process:"+name.ToUpperInvariant(),"Agent process environment",name.ToUpperInvariant()+" present in scan process; machine ownership unverified (value withheld)",null,false);
    }
    public async Task<ScanSnapshot> CollectAsync(string deviceId, PolicyDocument policy, CancellationToken ct, ScanSnapshot? previousInventory = null)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Native collection requires Windows");
        var evidence = new List<Evidence>(); var modules = new List<ModuleResult>();
        var now = DateTimeOffset.UtcNow;
        Profile[] profiles = [];
        await Module("users", "machine", () => { profiles = Profiles(); foreach(var p in profiles) modules.Add(new("users", p.Sid, p.HiveLoaded&&p.PathAvailable?"Complete":"Unknown", now, !p.HiveLoaded?"User hive not loaded; offline hive was not mounted":!p.PathAvailable?"Profile path missing or unavailable":null)); return Task.CompletedTask; });
        var priorUsers=previousInventory?.Modules.Where(m=>m.Module=="users" && m.Scope!="machine").Select(m=>m.Scope+":"+m.Status).Order().ToArray();
        var currentUsers=profiles.Select(p=>p.Sid+":"+(p.HiveLoaded&&p.PathAvailable?"Complete":"Unknown")).Order().ToArray();
        bool full=previousInventory is null || !priorUsers!.SequenceEqual(currentUsers);
        if(full) await Module("installed", "machine", () => { InstallEntries(RegistryHive.LocalMachine, RegistryView.Registry64, null); InstallEntries(RegistryHive.LocalMachine, RegistryView.Registry32, null); return Task.CompletedTask; });
        if(full) await Module("services","machine",()=>{ Services(); return Task.CompletedTask; });
        if(full) await Module("installed-paths","machine",()=>
        {
            foreach(var root in new[]{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)}.Where(x=>!string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase))
                evidence.AddRange(ScanKnownInstallRoot(root,null,policy));
            return Task.CompletedTask;
        });
        else
        {
            modules.AddRange(previousInventory!.Modules.Where(m=>m.Module is "installed" or "installed-paths" or "services" or "extensions" or "appx" or "cli"));
            evidence.AddRange(previousInventory.Evidence.Where(e=>e.Kind is EvidenceKind.Installation or EvidenceKind.Extension));
        }
        foreach (var p in profiles)
        {
            if(full && p.PathAvailable) await Module("installed-paths",p.Sid,()=>{ evidence.AddRange(ScanKnownInstallRoot(Path.Combine(p.Path,"AppData","Local","Programs"),p.Sid,policy)); return Task.CompletedTask; });
            else if(full) modules.Add(new("installed-paths",p.Sid,"Unknown",now,"Profile path unavailable"));
            if (!p.HiveLoaded)
            {
                if(full) modules.Add(new("installed", p.Sid, "Unknown", now, "User hive not loaded"));
                modules.Add(new("proxy", p.Sid, "Unknown", now, "User hive not loaded"));
                if(full && p.PathAvailable) await Module("extensions",p.Sid,()=>{ ExtensionsForUser(p); return Task.CompletedTask; });
                else if(full) modules.Add(new("extensions", p.Sid, "Unknown", now, "Profile path unavailable"));
                if(full && p.PathAvailable) await Module("cli",p.Sid,()=>{ CliForUser(p); return Task.CompletedTask; });
                else if(full) modules.Add(new("cli", p.Sid, "Unknown", now, "Profile path unavailable"));
                continue;
            }
            if(full) await Module("installed", p.Sid, () => { InstallEntries(RegistryHive.Users, RegistryView.Registry64, p.Sid); InstallEntries(RegistryHive.Users, RegistryView.Registry32, p.Sid); return Task.CompletedTask; });
            await Module("proxy", p.Sid, () => { ProxyForUser(p.Sid); return Task.CompletedTask; });
            if(full && p.PathAvailable) await Module("extensions", p.Sid, () => { ExtensionsForUser(p); return Task.CompletedTask; });
            else if(full) modules.Add(new("extensions",p.Sid,"Unknown",now,"Profile path unavailable"));
            if(full && p.PathAvailable) await Module("cli",p.Sid,()=>{ CliForUser(p); return Task.CompletedTask; });
            else if(full) modules.Add(new("cli",p.Sid,"Unknown",now,"Profile path unavailable"));
        }
        if(profiles.Length==0) modules.Add(new("users", "machine", "Unknown", now, "No eligible user profiles identified"));
        await Module("proxy-env","machine",()=>
        {
            using var env=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Environment") ?? throw new IOException("Machine environment registry unreadable");
            foreach(var name in env.GetValueNames())
            {
                var hit=ProxyEnvironmentEvidence(name,env.GetValue(name) as string,null);
                if(hit is not null) evidence.Add(hit);
            }
            foreach(var name in new[]{"HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"})
            {
                var clue=ProcessProxyEnvironmentClue(name,Environment.GetEnvironmentVariable(name));
                if(clue is not null) evidence.Add(clue);
            }
            return Task.CompletedTask;
        });
        await Module("proxy", "machine", () =>
        {
            if(!WinHttpGetDefaultProxyConfiguration(out var info)) throw new IOException("WinHTTP proxy inspection failed: "+Marshal.GetLastWin32Error());
            try
            {
                if(info.AccessType==3 && info.Proxy!=IntPtr.Zero)
                    evidence.Add(new("proxy", "WinHTTP proxy", EvidenceKind.Proxy,"winhttp","WinHTTP", "Configured WinHTTP proxy (address withheld); exception review required"));
                else if(info.AccessType is not 1 and not 3) throw new IOException("Unsupported WinHTTP proxy mode: "+info.AccessType);
            }
            finally { if(info.Proxy!=IntPtr.Zero) GlobalFree(info.Proxy); if(info.ProxyBypass!=IntPtr.Zero) GlobalFree(info.ProxyBypass); }
            return Task.CompletedTask;
        });
        await Module("proxy-advanced", "machine", async () =>
        {
            var output=await FixedProcess("netsh.exe","winhttp show advproxy",ct);
            var state=ParseAdvancedWinHttp(output);
            if(state.Proxy || state.Pac)
                evidence.Add(new("proxy","WinHTTP advanced proxy",EvidenceKind.Proxy,"winhttp-advanced","WinHTTP advanced",state.Pac?"WinHTTP PAC configured (URL withheld)":"WinHTTP proxy configured (address withheld)"));
            if(state.AutoDetect && !state.Proxy && !state.Pac)
                evidence.Add(new("proxy-clue","WinHTTP auto-detect",EvidenceKind.Clue,"winhttp-autodetect","WinHTTP advanced","Auto-detect enabled; no configured proxy proven",null,false));
        });
        await Module("processes", "machine", () => { Processes(); return Task.CompletedTask; });
        await Module("ports", "machine", () => { Ports(); return Task.CompletedTask; });
        if(full) await Module("cli", "machine", () => { CliForMachine(); return Task.CompletedTask; });
        if(full) foreach(var profile in profiles) await Module("appx",profile.Sid,async () =>
        {
            // ProfileList supplies a validated SID; never insert a caller-controlled shell fragment.
            if(!Regex.IsMatch(profile.Sid,@"^S-1-(?:5-21|12-1)-(?:\d+-){3}\d+$")) throw new IOException("Unsupported Appx user SID");
            var command="Get-AppxPackage -User '"+profile.Sid+"' -ErrorAction Stop | Select-Object Name,PackageFullName | ConvertTo-Json -Compress";
            var json=await FixedProcess("powershell.exe","-NoProfile -NonInteractive -Command \""+command+"\"",ct);
            evidence.AddRange(ParseAppxEvidence(json,profile.Sid,policy));
        });
        if(full && profiles.Length==0) modules.Add(new("appx","machine","Unknown",now,"No user profile available for per-user package check"));
        return new ScanSnapshot { DeviceId=deviceId, HostName=Environment.MachineName, Platform="Windows", Simulated=false, CollectedAt=DateTimeOffset.UtcNow, PolicyVersion=policy.Version, Evidence=evidence.ToArray(), Modules=modules.ToArray(), Controls=[] };

        async Task Module(string name,string scope, Func<Task> action)
        {
            try { await action().WaitAsync(TimeSpan.FromSeconds(30),ct); modules.Add(new(name,scope,"Complete",DateTimeOffset.UtcNow)); }
            catch(Exception ex) when(ex is not OperationCanceledException)
            { modules.Add(new(name,scope,"Error",DateTimeOffset.UtcNow, ex.GetType().Name+"; inspection incomplete")); }
        }
        void InstallEntries(RegistryHive hive, RegistryView view, string? sid)
        {
            using var root=RegistryKey.OpenBaseKey(hive,view);
            var relative=(sid is null?"":sid+"\\")+@"Software\Microsoft\Windows\CurrentVersion\Uninstall";
            using var uninstall=root.OpenSubKey(relative);
            if(uninstall is null) return;
            foreach(var sub in uninstall.GetSubKeyNames())
            {
                using var entry=uninstall.OpenSubKey(sub);
                var name=entry?.GetValue("DisplayName") as string;
                if(string.IsNullOrWhiteSpace(name)) continue;
                foreach(var rule in policy.Products.Where(r=>r.DisplayNames.Any(d=>string.Equals(d,name,StringComparison.OrdinalIgnoreCase))))
                    evidence.Add(new(rule.Id,rule.Name,EvidenceKind.Installation,$"uninstall:{hive}:{view}:{sid}:{sub}","Uninstall registry",$"Exact display name: {name}",sid));
            }
        }
        void Services()
        {
            using var root=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services") ?? throw new IOException("Service registry unreadable");
            foreach(var name in new[]{"clash_verge_service","CodexSandboxService.OpenAI.Codex"})
            {
                using var service=root.OpenSubKey(name);
                if(service is null) continue;
                var match=MatchServiceRegistration(name,service.GetValue("DisplayName") as string,policy);
                if(match is not null) evidence.Add(match);
            }
        }
        void ProxyForUser(string sid)
        {
            using var settings=Registry.Users.OpenSubKey(sid+@"\Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            if(settings is null) throw new IOException("User proxy registry key unreadable");
            var enabled=Convert.ToInt32(settings.GetValue("ProxyEnable")??0)!=0;
            var server=settings.GetValue("ProxyServer") as string;
            var pac=settings.GetValue("AutoConfigURL") as string;
            if(enabled && !string.IsNullOrWhiteSpace(server)) evidence.Add(new("proxy","System proxy",EvidenceKind.Proxy,"proxy:"+sid,"HKU proxy","Enabled proxy (address withheld)",sid));
            if(!string.IsNullOrWhiteSpace(pac)) evidence.Add(new("proxy","PAC configuration",EvidenceKind.Proxy,"pac:"+sid,"HKU proxy","PAC configured (URL withheld)",sid));
            using var env=Registry.Users.OpenSubKey(sid+@"\Environment");
            if(env is null) return;
            foreach(var name in env.GetValueNames())
            {
                var hit=ProxyEnvironmentEvidence(name,env.GetValue(name) as string,sid);
                if(hit is not null) evidence.Add(hit);
            }
        }
        void Processes()
        {
            foreach(var p in Process.GetProcesses())
            {
                try
                {
                    var name=p.ProcessName+".exe";
                    var candidates=policy.Products.Where(r=>r.ExecutableNames.Any(x=>string.Equals(x,name,StringComparison.OrdinalIgnoreCase))).ToArray();
                    if(candidates.Length==0) continue;
                    string? product=null;
                    try { product=FileVersionInfo.GetVersionInfo(p.MainModule!.FileName).ProductName; } catch { }
                    foreach(var rule in candidates)
                    {
                        bool confirmed=string.Equals(product,rule.Name,StringComparison.OrdinalIgnoreCase) || rule.DisplayNames.Any(x=>string.Equals(product,x,StringComparison.OrdinalIgnoreCase));
                        evidence.Add(new(rule.Id,rule.Name,confirmed?EvidenceKind.Process:EvidenceKind.Clue,"pid:"+p.Id,"Process",confirmed?$"Verified product identity; PID {p.Id}":$"Executable filename clue; PID {p.Id}",null,confirmed));
                    }
                }
                finally { p.Dispose(); }
            }
        }
        void Ports()
        {
            var listeners=IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
            foreach(var ep in listeners.Where(x=>x.Port is 1080 or 7890 or 7897 or 8080))
                evidence.Add(new("port-clue","Listening port",EvidenceKind.Clue,"tcp:"+ep.Address+":"+ep.Port,"TCP","Local listening port clue; process and proxy identity unverified",null,false));
            foreach(var nic in NetworkInterface.GetAllNetworkInterfaces().Where(n=>n.NetworkInterfaceType==NetworkInterfaceType.Tunnel || Regex.IsMatch(n.Name,@"(?i)(tun|tap|wintun)")))
                evidence.Add(new("interface-clue","Tunnel interface",EvidenceKind.Clue,"nic:"+nic.Id,"Network interface","Tunnel interface clue; owner and approved use unverified",null,false));
        }
        void ExtensionsForUser(Profile p)
        {
            var extensions=ScanKnownExtensionRoots(p.Path,p.Sid,policy);
            evidence.AddRange(extensions.Evidence);
            var jetBrains=Path.Combine(p.Path,"AppData","Roaming","JetBrains");
            if(DirectoryPresent(jetBrains))
            {
                var options=new EnumerationOptions { RecurseSubdirectories=true,AttributesToSkip=FileAttributes.ReparsePoint,IgnoreInaccessible=false };
                foreach(var manifest in Directory.EnumerateFiles(jetBrains,"plugin.xml",options))
                {
                    using var stream=File.OpenRead(manifest); AddJetBrainsPlugin(stream,p.Sid);
                }
                foreach(var jar in Directory.EnumerateFiles(jetBrains,"*.jar",options))
                {
                    using var archive=ZipFile.OpenRead(jar);
                    var entry=archive.GetEntry("META-INF/plugin.xml");
                    if(entry is null) continue;
                    if(entry.Length>1024*1024) throw new InvalidDataException("JetBrains plugin manifest too large");
                    using var stream=entry.Open(); AddJetBrainsPlugin(stream,p.Sid);
                }
            }
            if(extensions.Errors>0) throw new InvalidDataException($"{extensions.Errors} IDE extension manifest(s) unreadable");
        }
        void AddJetBrainsPlugin(Stream stream,string sid)
        {
            var settings=new XmlReaderSettings { DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null,MaxCharactersInDocument=1024*1024 };
            using var reader=XmlReader.Create(stream,settings);
            var doc=XDocument.Load(reader);
            var id=doc.Root?.Element("id")?.Value;
            if(string.IsNullOrWhiteSpace(id)) return;
            foreach(var rule in policy.Products.Where(r=>r.ExtensionIds.Any(x=>string.Equals(x,id,StringComparison.OrdinalIgnoreCase))))
                evidence.Add(new(rule.Id,rule.Name,EvidenceKind.Extension,"jetbrains:"+sid+":"+id,"JetBrains plugin manifest","Exact plugin ID: "+id,sid));
        }
        void CliForUser(Profile p)
        {
            var npm=Path.Combine(p.Path,"AppData","Roaming","npm");
            NpmPackages(Path.Combine(npm,"node_modules"),p.Sid);
            foreach(var name in new[]{"claude.cmd","codex.cmd","gemini.cmd"})
                if(FilePresent(Path.Combine(npm,name))) evidence.Add(new("cli-clue","CLI shim",EvidenceKind.Clue,"cli-shim:"+p.Sid+":"+name,"npm shim","Filename clue only: "+name,p.Sid,false));
            var localBin=Path.Combine(p.Path,".local","bin");
            evidence.AddRange(ScanKnownCliBin(localBin,p.Sid,policy));
        }
        void CliForMachine()
        {
            var roots=new[]{Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"nodejs","node_modules"),Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"npm","node_modules")};
            foreach(var root in roots) NpmPackages(root,null);
        }
        void NpmPackages(string root,string? sid)
        {
            foreach(var (relative,expected,productId) in new[]{(@"@anthropic-ai\claude-code","@anthropic-ai/claude-code","claude"),(@"@openai\codex","@openai/codex","codex"),(@"@google\gemini-cli","@google/gemini-cli","gemini")})
            {
                var manifest=Path.Combine(root,relative,"package.json");
                if(!FilePresent(manifest)) continue;
                using var doc=JsonDocument.Parse(File.ReadAllText(manifest));
                if(!doc.RootElement.TryGetProperty("name",out var name) || !string.Equals(name.GetString(),expected,StringComparison.Ordinal)) continue;
                var rule=policy.Products.FirstOrDefault(r=>r.Id==productId);
                if(rule is not null) evidence.Add(new(rule.Id,rule.Name,EvidenceKind.Installation,"npm:"+(sid??"machine")+":"+expected,"npm package.json","Exact package ID: "+expected,sid,true) { CollectedAt=DateTimeOffset.UtcNow });
            }
        }
    }
    public static Evidence[] ParseAppxEvidence(string json,string userSid,PolicyDocument policy)
    {
        if(string.IsNullOrWhiteSpace(userSid)) throw new ArgumentException("Store package must have an owning user SID");
        if(string.IsNullOrWhiteSpace(json)) return [];
        using var doc=JsonDocument.Parse(json);
        if(doc.RootElement.ValueKind==JsonValueKind.Null) return [];
        if(doc.RootElement.ValueKind is not (JsonValueKind.Array or JsonValueKind.Object)) throw new JsonException("Invalid Appx package list");
        var found=new List<Evidence>();
        foreach(var item in doc.RootElement.ValueKind==JsonValueKind.Array?doc.RootElement.EnumerateArray().ToArray():[doc.RootElement])
        {
            if(item.ValueKind!=JsonValueKind.Object) throw new JsonException("Invalid Appx package entry");
            var name=item.TryGetProperty("Name",out var n)?n.GetString():null;
            var full=item.TryGetProperty("PackageFullName",out var f)?f.GetString():null;
            if(name is null) continue;
            foreach(var rule in policy.Products.Where(r=>r.PackageIds.Any(id=>string.Equals(id,name,StringComparison.OrdinalIgnoreCase))))
                found.Add(new(rule.Id,rule.Name,EvidenceKind.Installation,"appx:"+userSid+":"+name,"Appx user package",$"Package ID {name}; package {full}",userSid));
        }
        return found.ToArray();
    }
    public static (bool Proxy,bool Pac,bool AutoDetect) ParseAdvancedWinHttp(string output)
    {
        var start=output.IndexOf('{'); var end=output.LastIndexOf('}');
        if(start<0 || end<=start) throw new JsonException("WinHTTP advanced JSON missing");
        using var doc=JsonDocument.Parse(output[start..(end+1)]);
        var root=doc.RootElement;
        if(root.ValueKind!=JsonValueKind.Object) throw new JsonException("WinHTTP advanced format unknown");
        bool ReadBool(string key) => root.TryGetProperty(key,out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False ? value.GetBoolean() : throw new JsonException("WinHTTP advanced flag missing");
        string ReadString(string key) => root.TryGetProperty(key,out var value) && value.ValueKind==JsonValueKind.String ? value.GetString()! : throw new JsonException("WinHTTP advanced value missing");
        var proxy=ReadString("Proxy"); var pac=ReadString("AutoconfigUrl"); var auto=ReadBool("AutoDetect");
        var proxyEnabled=root.TryGetProperty("ProxyIsEnabled",out _)?ReadBool("ProxyIsEnabled"):!string.IsNullOrWhiteSpace(proxy);
        var pacEnabled=root.TryGetProperty("AutoConfigIsEnabled",out _)?ReadBool("AutoConfigIsEnabled"):!string.IsNullOrWhiteSpace(pac);
        return (proxyEnabled,pacEnabled,auto);
    }
    private static Profile[] Profiles()
    {
        using var root=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList") ?? throw new IOException("ProfileList unreadable");
        var profiles=new List<Profile>();
        foreach(var sid in root.GetSubKeyNames().Where(s=>Regex.IsMatch(s,@"^S-1-5-21-(\d+-){3}\d+$") || Regex.IsMatch(s,@"^S-1-12-1-(\d+-){3}\d+$")))
        {
            using var key=root.OpenSubKey(sid);
            var raw=key?.GetValue("ProfileImagePath") as string;
            var path=string.IsNullOrWhiteSpace(raw)?"":Environment.ExpandEnvironmentVariables(raw);
            using var hive=Registry.Users.OpenSubKey(sid);
            profiles.Add(new(sid,path,hive is not null,path.Length>0 && DirectoryPresent(path)));
        }
        return profiles.ToArray();
    }
    private static bool DirectoryPresent(string path)
    {
        try { return (File.GetAttributes(path)&FileAttributes.Directory)!=0; }
        catch(FileNotFoundException) { return false; }
        catch(DirectoryNotFoundException) { return false; }
    }
    private static bool FilePresent(string path)
    {
        try { return (File.GetAttributes(path)&FileAttributes.Directory)==0; }
        catch(FileNotFoundException) { return false; }
        catch(DirectoryNotFoundException) { return false; }
    }
    [StructLayout(LayoutKind.Sequential)] private struct WinHttpProxyInfo { public int AccessType; public IntPtr Proxy; public IntPtr ProxyBypass; }
    [DllImport("winhttp.dll",SetLastError=true)] private static extern bool WinHttpGetDefaultProxyConfiguration(out WinHttpProxyInfo info);
    [DllImport("kernel32.dll")] private static extern IntPtr GlobalFree(IntPtr memory);
    private static async Task<string> FixedProcess(string fileName,string args,CancellationToken ct)
    {
        using var process=new Process { StartInfo = new ProcessStartInfo(fileName,args) { RedirectStandardOutput=true, RedirectStandardError=true, UseShellExecute=false, CreateNoWindow=true } };
        process.Start(); using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(30));
        try
        {
            var output=process.StandardOutput.ReadToEndAsync(timeout.Token);
            var error=process.StandardError.ReadToEndAsync(timeout.Token);
            await process.WaitForExitAsync(timeout.Token);
            if(process.ExitCode!=0) throw new IOException($"{fileName} failed: {(await error)[..Math.Min((await error).Length,160)]}");
            return await output;
        }
        catch(OperationCanceledException) { process.Kill(entireProcessTree:true); throw new TimeoutException(fileName+" timed out"); }
    }
}
