using System.Diagnostics;

namespace Compliance.Server;

/// <summary>
/// The container's health check, run as <c>dotnet Compliance.Server.dll --healthcheck</c>: the image has no curl.
/// It asks <c>/healthz</c> on this machine. A server that answers is alive even when its database is not (503), and
/// restarting it would not help. One that does not answer three checks in a row is stuck: the check ends it, and the
/// restart policy starts it again, which Docker does not do for an unhealthy container on its own.
/// </summary>
public static class HealthCheck
{
    public const string Argument = "--healthcheck";
    const int MissesBeforeRestart = 3;
    static readonly string MissFile = Path.Combine(Path.GetTempPath(), "compliance-health-misses");

    public static async Task<int> RunAsync()
    {
        var url = LocalUrl(Environment.GetEnvironmentVariable("ASPNETCORE_URLS")) + "/healthz";
        using var handler = new HttpClientHandler
        {
            // Only this machine is asked, by the name localhost, which the certificate does not cover.
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        try
        {
            using var response = await client.GetAsync(url);
            File.Delete(MissFile);
            Console.WriteLine($"{(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
            return response.IsSuccessStatusCode ? 0 : 1;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
        {
            var misses = (int.TryParse(File.Exists(MissFile) ? File.ReadAllText(MissFile) : "", out var n) ? n : 0) + 1;
            File.WriteAllText(MissFile, misses.ToString());
            Console.WriteLine($"No answer from {url} ({misses} in a row): {e.Message}");
            if (
                misses >= MissesBeforeRestart
                && Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER") == "true"
            )
            {
                File.Delete(MissFile);
                Console.WriteLine("Ending the stuck server so it is restarted");
                using var server = Process.GetProcessById(1);
                server.Kill();
            }
            return 1;
        }
    }

    /// <summary>The first address the server listens on, with a wildcard host made localhost.</summary>
    public static string LocalUrl(string? urls)
    {
        var first =
            (urls ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "http://localhost:5080";
        var uri = new UriBuilder(
            first
                .Replace("://+", "://localhost")
                .Replace("://*", "://localhost")
                .Replace("://[::]", "://localhost")
                .Replace("://0.0.0.0", "://localhost")
        )
        {
            Path = "",
        };
        return uri.Uri.GetLeftPart(UriPartial.Authority);
    }
}
