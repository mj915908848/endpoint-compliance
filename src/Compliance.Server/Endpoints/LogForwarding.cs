using Compliance.Core;

namespace Compliance.Server;

static partial class Endpoints
{
    static LogForwardingSettings CheckedForwarding(LogForwardingRequest r)
    {
        var host = r.Host?.Trim() ?? "";
        if (host.Length > 253 || host.Any(c => char.IsWhiteSpace(c) || char.IsControl(c) || c is '/' or '@'))
            throw new ApiError(400, "日志服务器地址无效，请填写主机名或 IP 地址");
        if (r.Enabled && host.Length == 0)
            throw new ApiError(400, "请填写日志服务器地址");
        if (r.Port is < 1 or > 65535)
            throw new ApiError(400, "端口需在 1 到 65535 之间");
        if (!LogForwardingSettings.Protocols.Contains(r.Protocol) || !LogForwardingSettings.Formats.Contains(r.Format))
            throw new ApiError(400, "协议或格式无效");
        if (r.Facility is < 16 or > 23)
            throw new ApiError(400, "设施需为 local0 到 local7");
        var ca = r.CaCertificate?.Trim() ?? "";
        if (ca.Length > 65536 || (ca.Length > 0 && !LogForwarder.ValidCa(ca)))
            throw new ApiError(400, "CA 证书无效，请粘贴 PEM 格式（-----BEGIN CERTIFICATE-----）");
        return new LogForwardingSettings
        {
            Enabled = r.Enabled,
            Host = host,
            Port = r.Port,
            Protocol = r.Protocol,
            Format = r.Format,
            Facility = r.Facility,
            Alerts = r.Alerts,
            Audit = r.Audit,
            CaCertificate = ca,
        };
    }

    static void MapLogForwarding(IEndpointRouteBuilder routes, ComplianceService s, LogForwarder forwarder)
    {
        var group = routes.MapGroup("/api/settings/log-forwarding");

        group.MapGet(
            "",
            async (HttpContext c) =>
            {
                Require(c, UserRoles.Admin);
                return new LogForwardingView(await s.Tx(LogForwarder.Settings), forwarder.Last);
            }
        );

        // Account administrators, not operators: forwarding sends the audit log, which also holds operators to
        // account, out of reach of the people it records.
        group
            .MapPut(
                "",
                async (HttpContext c) =>
                {
                    var u = Require(c, UserRoles.Admin);
                    var settings = CheckedForwarding(await Body<LogForwardingRequest>(c));
                    return await s.Tx(async tx =>
                    {
                        await tx.PutSetting(LogForwardingSettings.Key, Wire.Serialize(settings));
                        await tx.Audit(
                            u.Username,
                            "SetLogForwarding",
                            settings.Enabled
                                ? $"{settings.Protocol.ToUpperInvariant()} {settings.Host}:{settings.Port}，{settings.Format.ToUpperInvariant()}"
                                    + (settings.Alerts ? "，告警" : "")
                                    + (settings.Audit ? "，审计记录" : "")
                                : "关闭",
                            s.Now
                        );
                        return new Done();
                    });
                }
            )
            .Accepts<LogForwardingRequest>(JsonBody);

        group
            .MapPost(
                "/test",
                async (HttpContext c) =>
                {
                    var u = Require(c, UserRoles.Admin);
                    var settings = await s.Tx(async tx =>
                    {
                        await tx.Audit(u.Username, "TestLogForwarding", "", s.Now);
                        return await LogForwarder.Settings(tx);
                    });
                    var error = await forwarder.Test(settings, c.RequestAborted);
                    return new NotificationTested(error == null, error);
                }
            )
            .RequireRateLimiting("notify-test");
    }
}
