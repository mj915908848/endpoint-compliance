using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.HttpOverrides;

namespace Compliance.Server;

public partial class Program
{
    public static async Task Main(string[] args)
    {
        var b = WebApplication.CreateBuilder(
            new WebApplicationOptions { Args = args, WebRootPath = Path.Combine(AppContext.BaseDirectory, "wwwroot") }
        );
        b.Services.AddSingleton(_ => b.Configuration.GetSection("Compliance").Get<Settings>() ?? new());
        b.Services.AddSingleton<TimeProvider>(TimeProvider.System);
        b.Services.AddSingleton<Store>();
        b.Services.AddSingleton<ComplianceService>();
        b.Services.AddHostedService<OfflineMonitor>();
        b.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
        b.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 2 * 1024 * 1024);
        b.Services.AddRateLimiter(o =>
        {
            o.RejectionStatusCode = 429;
            o.AddPolicy(
                "login",
                c =>
                    RateLimitPartition.GetFixedWindowLimiter(
                        c.Connection.RemoteIpAddress?.ToString() ?? "loopback",
                        _ => new FixedWindowRateLimiterOptions
                        {
                            PermitLimit = 20,
                            Window = TimeSpan.FromMinutes(1),
                            QueueLimit = 0,
                        }
                    )
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
                    c.Response.Headers["Content-Security-Policy"] =
                        "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'";
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
                var path = c.Request.Path.Value ?? "";
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

        Endpoints.Map(app, service, settings);
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
