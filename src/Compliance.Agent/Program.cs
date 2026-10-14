using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Compliance.Agent;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            string? Arg(string flag) { var i=Array.IndexOf(args,flag); return i>=0 && i+1<args.Length?args[i+1]:null; }
            bool Has(string flag)=>args.Contains(flag,StringComparer.Ordinal);
            var simulated=Arg("--fixture") is not null;
            if(!simulated && !OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Native service requires Windows; use --fixture for simulation");
            var data=Arg("--data-dir")??(simulated?Path.Combine(Environment.CurrentDirectory,".agent-demo"):Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"ComplianceAgent"));
            if(!simulated) NativeDataDirectory.EnsureSecure(data);
            var configPath=Arg("--config")??Path.Combine(data,"agent.json");
            AgentConfiguration config;
            if(File.Exists(configPath)) config=AgentConfiguration.Read(configPath);
            else
            {
                var server=Arg("--server")??throw new ArgumentException("First run needs --server URL");
                config=new(server,data); AgentRuntime.ValidateServer(server,simulated);
                AgentConfiguration.Save(configPath,config);
            }
            // A CLI server override is intentionally not persisted over enrollment identity.
            if(Arg("--server") is { } overrideUrl && config.ServerUrl!=overrideUrl) throw new ArgumentException("Configured server differs from --server");
            var runtime=new AgentRuntime(config,configPath,simulated,Arg("--fixture"));
            if(Has("--enroll"))
            {
                var code=Arg("--code")??throw new ArgumentException("--enroll requires --code");
                await runtime.EnrollAsync(code,CancellationToken.None);
                if(!Has("--once")) return 0;
                config=AgentConfiguration.Read(configPath);
                runtime=new AgentRuntime(config,configPath,simulated,Arg("--fixture"));
            }
            if(Has("--once")) { await runtime.RunAsync(true,CancellationToken.None); return 0; }
            using var host=Host.CreateDefaultBuilder(args).UseWindowsService(options=>options.ServiceName="ComplianceAgent")
                .ConfigureServices(services=>services.AddSingleton(runtime).AddHostedService<AgentWorker>()).Build();
            await host.RunAsync(); return Environment.ExitCode;
        }
        catch(Exception ex) { Console.Error.WriteLine($"Fatal agent failure: {ex.GetType().Name}: {ex.Message}"); return 1; }
    }
}

public sealed class AgentWorker(AgentRuntime runtime) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try { await runtime.RunAsync(false,stoppingToken); }
        catch(OperationCanceledException) when(stoppingToken.IsCancellationRequested) { }
        catch(Exception ex)
        {
            Console.Error.WriteLine("Service fault: "+ex.GetType().Name+": "+ex.Message);
            Environment.Exit(1); // SCM recovery must see a process failure.
        }
    }
}
