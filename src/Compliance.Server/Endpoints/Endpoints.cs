using Compliance.Core;

namespace Compliance.Server;

/// <summary>HTTP endpoints, one file per area under <c>Endpoints/</c>.</summary>
static partial class Endpoints
{
    public static void Map(WebApplication app, ComplianceService s, Settings settings, AlertNotifier notifier)
    {
        MapAuth(app, s, settings);
        MapUsers(app, s);
        MapAudit(app, s);
        MapDevices(app, s);
        MapAssets(app, s);
        MapAlerts(app, s);
        MapEnrollment(app, s);
        MapPolicies(app, s);
        MapAgent(app, s);
        MapSettings(app, s, notifier);
        MapLogForwarding(app, s, app.Services.GetRequiredService<LogForwarder>());
        MapPackages(app, s);
        MapSigningKey(app, s);
    }

    static UserRecord Require(HttpContext c, string role)
    {
        var u = c.Items["user"] as UserRecord ?? throw new ApiError(401, "Login required");
        if (!u.Roles.Contains(role))
            throw new ApiError(403, "Role required: " + role);
        return u;
    }

    static string Agent(HttpContext c) => (string)c.Items["device"]!;

    // Bodies are read with Body rather than bound, so endpoints that read one declare it for the OpenAPI document.
    const string JsonBody = "application/json";

    static async Task<T> Body<T>(HttpContext c) =>
        !c.Request.HasJsonContentType()
            ? throw new ApiError(415, "JSON body required")
            : await c.Request.ReadFromJsonAsync<T>(Wire.Json) ?? throw new ApiError(400, "Body required");
}
