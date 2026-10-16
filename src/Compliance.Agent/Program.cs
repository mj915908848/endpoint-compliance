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
            var configPath = Arg("--config") ?? Path.Combine(data, "agent.json");
            if (Has("--prepare-install"))
            {
                // Run by the MSI as SYSTEM before the service first starts; see NativeDataDirectory.RemoveIfForeign.
                if (!simulated && NativeDataDirectory.RemoveIfForeign(data))
                    Console.WriteLine($"已删除非管理员创建的数据目录 {data}");
                return 0;
            }
            var aclRepaired = !simulated && NativeDataDirectory.EnsureSecure(data);
            var server = Arg("--server");
            AgentConfiguration? config = File.Exists(configPath) ? AgentConfiguration.Read(configPath) : null;
            if (Has("--enroll"))
                return await EnrollAsync(
                    config,
                    configPath,
                    data,
                    server,
                    Arg("--code"),
                    Arg("--result"),
                    simulated,
                    Arg("--fixture"),
                    localDemo,
                    Has("--once"),
                    aclRepaired
                );
            if (config is null)
            {
                if (server is null)
                {
                    // An MSI installs the service before anyone enrolls; it waits for the enrollment.
                    if (!simulated && !Has("--once"))
                        return await RunServiceAsync(args, configPath, data, null, false, aclRepaired);
                    throw new ArgumentException("First run needs --server URL");
                }
                config = new(server, data);
                AgentRuntime.ValidateServer(server, simulated, localDemo);
                AgentConfiguration.Save(configPath, config);
            }
            // A CLI server override is intentionally not persisted over enrollment identity.
            if (server is not null && config.ServerUrl != server)
                throw new ArgumentException("Configured server differs from --server");
            // A trial install persists its HTTP trial mode so the resident service keeps the same checks.
            localDemo |= config.HttpTrial && !simulated;
            if (Has("--once"))
            {
                await new AgentRuntime(config, configPath, simulated, Arg("--fixture"), localDemo)
                {
                    DataAclRepaired = aclRepaired,
                }.RunAsync(true, CancellationToken.None);
                return 0;
            }
            return await RunServiceAsync(args, configPath, data, Arg("--fixture"), simulated, aclRepaired);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Fatal agent failure: {ex.GetType().Name}: {ex.Message}");
            return 1;
        }
    }

    /// <summary>
    /// Enrolls with a one-time code. With <c>--server</c> the configuration is written for that server, unless the
    /// device is already enrolled: then the same server is a success with nothing to do (an MSI may be run again with
    /// the same settings) and another server is refused. HTTP addresses enroll in trial mode, which the server must
    /// report. <c>--result</c> names a file for the outcome in words, for the tray, which runs this elevated and
    /// cannot read its output.
    /// </summary>
    static async Task<int> EnrollAsync(
        AgentConfiguration? config,
        string configPath,
        string data,
        string? server,
        string? code,
        string? resultPath,
        bool simulated,
        string? fixture,
        bool localDemo,
        bool once,
        bool aclRepaired
    )
    {
        void Result(string text)
        {
            Console.WriteLine(text);
            if (resultPath is not null)
                File.WriteAllText(resultPath, text);
        }
        try
        {
            if (string.IsNullOrWhiteSpace(code))
                throw new ArgumentException("--enroll requires --code");
            if (server is not null)
            {
                server = server.Trim().TrimEnd('/');
                if (config is { DeviceId.Length: > 0 })
                {
                    if (!SameServer(config.ServerUrl, server))
                        throw new EnrollmentRefusedException(
                            $"本机已登记到管理端 {config.ServerUrl}。如需改登记到其他管理端，请先卸载客户端再重新安装。"
                        );
                    Result("本机已登记到该管理端，无需再次登记。");
                    return 0;
                }
                var trial = !simulated && server.StartsWith("http://", StringComparison.OrdinalIgnoreCase);
                config = new(server, data, HttpTrial: trial);
                AgentRuntime.ValidateServer(server, simulated, localDemo || trial);
                AgentConfiguration.Save(configPath, config);
            }
            else if (config is null)
                throw new ArgumentException("First run needs --server URL");
            localDemo |= config.HttpTrial && !simulated;
            await new AgentRuntime(config, configPath, simulated, fixture, localDemo).EnrollAsync(
                code.Trim(),
                CancellationToken.None
            );
            // The identity key and configuration were just written by the enrolling administrator's account.
            if (!simulated)
                NativeDataDirectory.EnsureSecure(data);
            Result("登记成功。");
        }
        catch (Exception e) when (resultPath is not null)
        {
            Result(EnrollmentFailure.Describe(e));
            return 1;
        }
        if (!once)
            return 0;
        await new AgentRuntime(AgentConfiguration.Read(configPath), configPath, simulated, fixture, localDemo)
        {
            DataAclRepaired = aclRepaired,
        }.RunAsync(true, CancellationToken.None);
        return 0;
    }

    static bool SameServer(string a, string b) =>
        Uri.TryCreate(a.TrimEnd('/'), UriKind.Absolute, out var x)
        && Uri.TryCreate(b.TrimEnd('/'), UriKind.Absolute, out var y)
        && Uri.Compare(x, y, UriComponents.SchemeAndServer, UriFormat.Unescaped, StringComparison.OrdinalIgnoreCase)
            == 0;

    /// <summary>
    /// The resident service. Until the device is enrolled it answers the tray that it is waiting and checks the
    /// configuration every few seconds, then runs as usual.
    /// </summary>
    static async Task<int> RunServiceAsync(
        string[] args,
        string configPath,
        string data,
        string? fixture,
        bool simulated,
        bool aclRepaired
    )
    {
        if (Microsoft.Extensions.Hosting.WindowsServices.WindowsServiceHelpers.IsWindowsService())
            AgentLog.Attach(NativeDataDirectory.EnsureLogs(data));
        if (aclRepaired)
            Console.WriteLine(AgentRuntime.DataAclRepairedMessage);
        AgentRuntime? Load()
        {
            if (!File.Exists(configPath))
                return null;
            var config = AgentConfiguration.Read(configPath);
            if (string.IsNullOrWhiteSpace(config.DeviceId) || string.IsNullOrWhiteSpace(config.PolicyPublicKeyPem))
                return null;
            Console.WriteLine($"客户端服务启动，服务器 {config.ServerUrl}");
            return new AgentRuntime(config, configPath, simulated, fixture, config.HttpTrial && !simulated)
            {
                DataAclRepaired = aclRepaired,
            };
        }
        using var host = Host.CreateDefaultBuilder(args)
            .UseWindowsService(options => options.ServiceName = "ComplianceAgent")
            .ConfigureServices(services =>
                services.AddSingleton<Func<AgentRuntime?>>(Load).AddHostedService<AgentWorker>()
            )
            .Build();
        await host.RunAsync();
        return Environment.ExitCode;
    }

    public static void ValidateLocalDemoArguments(bool localDemo, bool once, bool simulated)
    {
        if (localDemo && (!once || simulated))
            throw new InvalidOperationException("Local native demo requires --once and cannot use a fixture");
    }
}

public sealed class AgentWorker(Func<AgentRuntime?> load) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            var runtime = load();
            if (runtime is null)
            {
                Console.WriteLine("客户端尚未登记，等待登记。");
                using var waiting = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                // Tells the tray the service waits for an enrollment, so it can offer one.
                var pipe = OperatingSystem.IsWindows()
                    ? new NotificationPipe(null).RunAsync(waiting.Token)
                    : Task.CompletedTask;
                while ((runtime = load()) is null)
                    await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
                waiting.Cancel();
                try
                {
                    await pipe;
                }
                catch (OperationCanceledException) { }
            }
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
