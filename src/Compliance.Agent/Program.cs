using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Compliance.Agent;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            string? Arg(string flag)
            {
                var i = Array.IndexOf(args, flag);
                return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
            }
            bool Has(string flag) => args.Contains(flag, StringComparer.Ordinal);
            var simulated = Arg("--fixture") is not null;
            var localDemo = Has("--local-demo");
            ValidateLocalDemoArguments(localDemo, Has("--once"), simulated);
            if (!simulated && !OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException(
                    "Native service requires Windows; use --fixture for simulation"
                );
            var data =
                Arg("--data-dir")
                ?? (
                    simulated
                        ? Path.Combine(Environment.CurrentDirectory, ".agent-demo")
                        : Path.Combine(
                            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                            "ComplianceAgent"
                        )
                );
            var aclRepaired = !simulated && NativeDataDirectory.EnsureSecure(data);
            var configPath = Arg("--config") ?? Path.Combine(data, "agent.json");
            AgentConfiguration config;
            if (File.Exists(configPath))
                config = AgentConfiguration.Read(configPath);
            else
            {
                var server = Arg("--server") ?? throw new ArgumentException("First run needs --server URL");
                config = new(server, data);
                AgentRuntime.ValidateServer(server, simulated, localDemo);
                AgentConfiguration.Save(configPath, config);
            }
            // A CLI server override is intentionally not persisted over enrollment identity.
            if (Arg("--server") is { } overrideUrl && config.ServerUrl != overrideUrl)
                throw new ArgumentException("Configured server differs from --server");
            // A trial install persists its HTTP trial mode so the resident service keeps the same checks.
            localDemo |= config.HttpTrial && !simulated;
            var runtime = new AgentRuntime(config, configPath, simulated, Arg("--fixture"), localDemo)
            {
                DataAclRepaired = aclRepaired,
            };
            if (Has("--enroll"))
            {
                var code = Arg("--code") ?? throw new ArgumentException("--enroll requires --code");
                await runtime.EnrollAsync(code, CancellationToken.None);
                // The identity key and configuration were just written by the enrolling administrator's account.
                if (!simulated)
                    NativeDataDirectory.EnsureSecure(data);
                if (!Has("--once"))
                    return 0;
                config = AgentConfiguration.Read(configPath);
                runtime = new AgentRuntime(config, configPath, simulated, Arg("--fixture"), localDemo);
            }
            if (Has("--once"))
            {
                await runtime.RunAsync(true, CancellationToken.None);
                return 0;
            }
            if (Microsoft.Extensions.Hosting.WindowsServices.WindowsServiceHelpers.IsWindowsService())
            {
                AgentLog.Attach(data);
                Console.WriteLine($"客户端服务启动，服务器 {config.ServerUrl}");
            }
            if (aclRepaired)
                Console.WriteLine(AgentRuntime.DataAclRepairedMessage);
            using var host = Host.CreateDefaultBuilder(args)
                .UseWindowsService(options => options.ServiceName = "ComplianceAgent")
                .ConfigureServices(services => services.AddSingleton(runtime).AddHostedService<AgentWorker>())
                .Build();
            await host.RunAsync();
            return Environment.ExitCode;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Fatal agent failure: {ex.GetType().Name}: {ex.Message}");
            return 1;
        }
    }

    public static void ValidateLocalDemoArguments(bool localDemo, bool once, bool simulated)
    {
        if (localDemo && (!once || simulated))
            throw new InvalidOperationException("Local native demo requires --once and cannot use a fixture");
    }
}

public sealed class AgentWorker(AgentRuntime runtime) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await runtime.RunAsync(false, stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Service fault: " + ex.GetType().Name + ": " + ex.Message);
            Environment.Exit(1); // SCM recovery must see a process failure.
        }
    }
}
