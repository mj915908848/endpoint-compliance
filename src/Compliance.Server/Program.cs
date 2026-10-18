using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.HttpOverrides;

namespace Compliance.Server;

public partial class Program
{
    /// <summary>Device requests handled at once; the database pool holds 100 connections by default.</summary>
    public const int AgentConcurrency = 32;

    public static async Task Main(string[] args)
    {
        if (args is [HealthCheck.Argument])
        {
            Environment.ExitCode = await HealthCheck.RunAsync();
            return;
        }
        var b = WebApplication.CreateBuilder(
            new WebApplicationOptions { Args = args, WebRootPath = Path.Combine(AppContext.BaseDirectory, "wwwroot") }
        );
        b.Services.AddSingleton(_ => b.Configuration.GetSection("Compliance").Get<Settings>() ?? new());
        b.Services.AddSingleton<TimeProvider>(TimeProvider.System);
        b.Services.AddSingleton<Store>();
        b.Services.AddSingleton<ComplianceService>();
        b.Services.AddHostedService<StatusMonitor>();
        b.Services.AddHostedService<MaintenanceService>();
        b.Services.AddHttpClient(AlertNotifier.HttpClientName, c => c.Timeout = TimeSpan.FromSeconds(10));
        b.Services.AddSingleton<AlertNotifier>();
        b.Services.AddHostedService<NotificationService>();
        b.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
        b.Services.AddOpenApi(ApiDocument.Configure);
        b.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 2 * 1024 * 1024);
        b.Services.AddRateLimiter(o =>
        {
            o.RejectionStatusCode = 429;
            // Separate buckets per source address, so devices enrolling together behind one NAT do not lock
            // administrators out of signing in, and the other way round.
            void PerAddress(string policy, int perMinute) =>
                o.AddPolicy(
                    policy,
                    c =>
                        RateLimitPartition.GetFixedWindowLimiter(
                            c.Connection.RemoteIpAddress?.ToString() ?? "loopback",
                            _ => new FixedWindowRateLimiterOptions
                            {
                                PermitLimit = perMinute,
                                Window = TimeSpan.FromMinutes(1),
                                QueueLimit = 0,
                            }
                        )
                );
            PerAddress("login", 20);
            // Enrollment codes are random and long, so this only stops floods; a whole office may enroll at once.
            PerAddress("enroll", 300);
            PerAddress("notify-test", 5);
            // Device requests are checked against the database before anything else, signed or not; a flood of
            // forged ones could take every database connection. They take turns instead, leaving connections for
            // the pages. Not per address: a whole office reports through one NAT.
            o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(c =>
                (c.Request.Path.Value ?? "").StartsWith("/api/agent/", StringComparison.OrdinalIgnoreCase)
                    ? RateLimitPartition.GetConcurrencyLimiter(
                        "agent",
                        _ => new ConcurrencyLimiterOptions
                        {
                            PermitLimit = AgentConcurrency,
                            QueueLimit = 2000,
                            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                        }
                    )
                    : RateLimitPartition.GetNoLimiter("other")
            );
        });

        var app = b.Build();
        var settings = app.Services.GetRequiredService<Settings>();
        var service = app.Services.GetRequiredService<ComplianceService>();

        if (settings.DemoMode)
        {
            var urls = b.Configuration["urls"] ?? "http://127.0.0.1:5080";
            foreach (var url in urls.Split(';'))
            {
                if (!TrialNetwork.IsAllowedListener(url, settings.DemoHttpLan))
                    throw new InvalidOperationException(
                        "Demo listener requires a loopback address, or an explicit private IPv4 address with Compliance:DemoHttpLan enabled"
                    );
            }
            if (b.Configuration["urls"] == null)
                app.Urls.Add("http://127.0.0.1:5080");
        }
        else if (settings.DemoHttpLan)
        {
            throw new InvalidOperationException("DemoHttpLan requires DemoMode");
        }

        if (settings.TrustedProxies.Length > 0)
        {
            var options = new ForwardedHeadersOptions
            {
                ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
                ForwardLimit = 1,
            };
            options.KnownIPNetworks.Clear();
            options.KnownProxies.Clear();
            foreach (var proxy in settings.TrustedProxies)
                options.KnownProxies.Add(IPAddress.Parse(proxy));
            app.UseForwardedHeaders(options);
        }

        await service.Initialize();

        app.Use(
            async (c, next) =>
            {
                try
                {
                    if (settings.DemoMode)
                    {
                        if (
                            c.Connection.RemoteIpAddress is { } remote
                            && !(
                                settings.DemoHttpLan
                                    ? TrialNetwork.IsPrivateOrLoopback(remote)
                                    : IPAddress.IsLoopback(remote)
                            )
                        )
                            throw new ApiError(
                                403,
                                "Demo accepts only its configured local or private-network clients"
                            );
                    }
                    else if (!c.Request.IsHttps)
                    {
                        throw new ApiError(400, "HTTPS is required");
                    }

                    c.Response.Headers["X-Content-Type-Options"] = "nosniff";
                    // The UI's component library injects its styles at runtime, so inline styles are
                    // allowed; scripts stay limited to files served by this origin.
                    c.Response.Headers["Content-Security-Policy"] =
                        "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'";
                    if (c.Request.Path.StartsWithSegments("/api"))
                        c.Response.Headers.CacheControl = "no-store";
                    await next(c);
                }
                catch (ApiError e)
                {
                    c.Response.StatusCode = e.Status;
                    await c.Response.WriteAsJsonAsync(new { error = e.Message });
                }
                catch (JsonException)
                {
                    c.Response.StatusCode = 400;
                    await c.Response.WriteAsJsonAsync(new { error = "Invalid JSON" });
                }
                catch (BadHttpRequestException e)
                {
                    c.Response.StatusCode = e.StatusCode;
                    await c.Response.WriteAsJsonAsync(new { error = "Invalid request" });
                }
            }
        );
        app.UseRateLimiter();
        app.Use(
            async (c, next) =>
            {
                // Routes match regardless of case, so these checks must too: "/API/devices" reaches the same endpoint.
                var path = (c.Request.Path.Value ?? "").ToLowerInvariant();
                if (path.StartsWith("/api/agent/", StringComparison.Ordinal) && path != "/api/agent/enroll")
                    await Authentication.Agent(c, service);
                else if (
                    path.StartsWith("/api/", StringComparison.Ordinal)
                    && path is not ("/api/auth/login" or "/api/status" or "/api/agent/enroll")
                )
                    await Authentication.Admin(c, service);
                await next(c);
            }
        );

        // For the container's health check: answers without signing in, and says whether the database does.
        app.MapGet(
                "/healthz",
                async () =>
                {
                    try
                    {
                        await service.Tx(async tx => await tx.GetSetting("health"));
                        return Results.Text("ok");
                    }
                    catch (Exception e) when (e is not OperationCanceledException)
                    {
                        return Results.Text("database unavailable: " + e.GetType().Name, statusCode: 503);
                    }
                }
            )
            .ExcludeFromDescription();
        Endpoints.Map(app, service, settings, app.Services.GetRequiredService<AlertNotifier>());
        app.MapOpenApi(ApiDocument.Path);
        app.UseDefaultFiles();
        app.UseStaticFiles();
        app.MapFallback(async c =>
        {
            if (c.Request.Path.StartsWithSegments("/api"))
            {
                c.Response.StatusCode = 404;
                await c.Response.WriteAsJsonAsync(new { error = "Endpoint not found" });
                return;
            }
            var index = Path.Combine(
                app.Environment.WebRootPath ?? Path.Combine(app.Environment.ContentRootPath, "wwwroot"),
                "index.html"
            );
            if (File.Exists(index))
            {
                c.Response.ContentType = "text/html";
                await c.Response.SendFileAsync(index);
            }
            else
            {
                c.Response.StatusCode = 404;
            }
        });
        await app.RunAsync();
    }
}
