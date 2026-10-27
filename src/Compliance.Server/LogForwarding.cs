using System.Globalization;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Compliance.Core;

namespace Compliance.Server;

/// <summary>Where alerts and audit records are sent as syslog, for a SIEM or a log server.</summary>
public sealed record LogForwardingSettings
{
    public bool Enabled { get; init; }
    public string Host { get; init; } = "";
    public int Port { get; init; } = 514;

    /// <summary>Udp (RFC 5426), Tcp (one message per line) or Tls (RFC 5425, octet counting).</summary>
    public string Protocol { get; init; } = "Udp";

    /// <summary>Json: RFC 5424 with a JSON message; Cef: RFC 5424 carrying ArcSight CEF.</summary>
    public string Format { get; init; } = "Json";

    /// <summary>Syslog facility, local0 (16) to local7 (23).</summary>
    public int Facility { get; init; } = 16;

    public bool Alerts { get; init; } = true;
    public bool Audit { get; init; } = true;

    /// <summary>PEM certificates trusted for Tls besides the system's, for a log server with an internal CA.</summary>
    public string CaCertificate { get; init; } = "";

    public const string Key = "log-forwarding";
    public const string AuditCursorKey = "log-forwarding-audit";

    public static readonly string[] Protocols = ["Udp", "Tcp", "Tls"];
    public static readonly string[] Formats = ["Json", "Cef"];
}

public sealed record LogForwardingResult(DateTimeOffset At, bool Ok, string Error, int Sent);

/// <summary>The audit record forwarding has reached, oldest first by time and then id.</summary>
public sealed record AuditCursor(DateTimeOffset At, string Id);

/// <summary>
/// Sends alerts as they are raised and resolved and every audit record to a syslog server, in order, from where it
/// left off: a failed send is retried next run, so the server sees each once a run gets through. While forwarding
/// (or one of the two kinds) is off, what happens is passed over, so turning it on does not send a backlog.
/// </summary>
public sealed class LogForwarder(ComplianceService service, ILogger<LogForwarder> logger)
{
    const int Batch = 500;
    const string AppName = "endpoint-compliance";
    const int MaxUdpBytes = 8192;

    /// <summary>
    /// Audit records younger than this wait for the next run: one written by a transaction that commits late would
    /// otherwise land behind the cursor and never be sent.
    /// </summary>
    static readonly TimeSpan AuditSettle = TimeSpan.FromSeconds(5);

    readonly SemaphoreSlim gate = new(1);

    /// <summary>The last attempt to send, shown in the settings page.</summary>
    public LogForwardingResult? Last { get; private set; }

    public static async Task<LogForwardingSettings> Settings(Transaction tx) =>
        await tx.GetSetting(LogForwardingSettings.Key) is { } json
            ? Wire.Read<LogForwardingSettings>(json)
            : new LogForwardingSettings();

    static async Task<AuditCursor?> Cursor(Transaction tx) =>
        await tx.GetSetting(LogForwardingSettings.AuditCursorKey) is { } json ? Wire.Read<AuditCursor>(json) : null;

    public async Task Run(CancellationToken ct = default)
    {
        await gate.WaitAsync(ct);
        try
        {
            var until = service.Now - AuditSettle;
            var (settings, alerts, audit) = await service.Tx(async tx =>
            {
                var settings = await Settings(tx);
                bool alertsOn = settings.Enabled && settings.Alerts,
                    auditOn = settings.Enabled && settings.Audit;
                if (!alertsOn)
                    await tx.MarkAllForwarded();
                // Without a cursor yet (forwarding just set up), the audit log so far is passed over too.
                var cursor = await Cursor(tx);
                if (!auditOn || cursor is null)
                {
                    if (cursor is null || cursor.At < until)
                        await tx.PutSetting(
                            LogForwardingSettings.AuditCursorKey,
                            Wire.Serialize(new AuditCursor(until, ""))
                        );
                    cursor = null;
                }
                return (
                    settings,
                    alertsOn ? await tx.PendingForwards(Batch) : [],
                    cursor is null ? [] : await tx.AuditAfter(cursor.At, cursor.Id, until, Batch)
                );
            });
            if (alerts.Count + audit.Count == 0)
                return;

            var host = Environment.MachineName;
            var messages = alerts
                .Select(a => Alert(settings, host, a.Alert, a.Note))
                .Concat(audit.Select(a => Audit(settings, host, a)))
                .ToList();
            var error = await Send(settings, messages, ct);
            Last = new(service.Now, error == null, error ?? "", error == null ? messages.Count : 0);
            if (error != null)
            {
                logger.LogWarning("Forwarding {Count} log messages failed: {Error}", messages.Count, error);
                return;
            }
            await service.Tx(async tx =>
            {
                await tx.MarkForwarded(alerts.Select(a => (a.Alert.Id, a.Alert.State, a.Activation)));
                if (audit.Count > 0)
                    await tx.PutSetting(
                        LogForwardingSettings.AuditCursorKey,
                        Wire.Serialize(new AuditCursor(audit[^1].At, audit[^1].Id))
                    );
                return true;
            });
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>Sends one test message with <paramref name="settings"/>; returns null or why it failed.</summary>
    public async Task<string?> Test(LogForwardingSettings settings, CancellationToken ct = default)
    {
        var record = new AuditRecord(
            "test",
            "system",
            "LogForwardingTest",
            "终端合规管控日志外发测试消息",
            service.Now
        );
        var error = await Send(settings, [Audit(settings, Environment.MachineName, record)], ct);
        Last = new(service.Now, error == null, error ?? "", error == null ? 1 : 0);
        return error;
    }

    // ---- messages --------------------------------------------------------------------------

    /// <summary>CEF severity, 0 to 10, of an alert type while active.</summary>
    static int AlertSeverity(string type) =>
        type switch
        {
            "Tamper" => 8,
            "Violation" => 7,
            "SensitiveFile" => 6,
            "Baseline" or "BlockedAttempt" => 5,
            "Health" => 4,
            _ => 3,
        };

    static int AuditSeverity(string action) => action is "LoginFailed" or "LoginLocked" or "LoginWrongCode" ? 5 : 2;

    /// <summary>Syslog severity (RFC 5424: 4 warning, 5 notice, 6 informational) for a CEF severity.</summary>
    static int SyslogSeverity(int cef) =>
        cef switch
        {
            >= 6 => 4,
            >= 4 => 5,
            _ => 6,
        };

    public static string Alert(LogForwardingSettings settings, string host, AlertSummary a, string note)
    {
        var resolved = a.State == "Resolved";
        var severity = resolved ? 1 : AlertSeverity(a.Type);
        var at = resolved ? a.LastSeen : a.FirstSeen;
        string message;
        if (settings.Format == "Cef")
            message = Cef(
                "alert:" + a.Type,
                Labels.AlertType(a.Type) + (resolved ? "（已恢复）" : ""),
                severity,
                [
                    ("rt", at.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture)),
                    ("dhost", a.HostName),
                    ("msg", a.Summary),
                    ("act", resolved ? "resolved" : "raised"),
                    ("externalId", a.Id),
                    ("cs1Label", "deviceId"),
                    ("cs1", a.DeviceId),
                    ("cs2Label", "alertType"),
                    ("cs2", a.Type),
                    ("cs3Label", note.Length > 0 ? "deviceNote" : ""),
                    ("cs3", note),
                ]
            );
        else
            message = JsonSerializer.Serialize(
                new
                {
                    kind = "alert",
                    @event = resolved ? "resolved" : "raised",
                    id = a.Id,
                    type = a.Type,
                    typeName = Labels.AlertType(a.Type),
                    severity,
                    deviceId = a.DeviceId,
                    hostName = a.HostName,
                    deviceNote = note,
                    summary = a.Summary,
                    firstSeen = a.FirstSeen,
                    lastSeen = a.LastSeen,
                    acknowledged = a.Acknowledged,
                },
                Plain
            );
        return Syslog(settings, host, SyslogSeverity(severity), at, "alert", message);
    }

    public static string Audit(LogForwardingSettings settings, string host, AuditRecord a)
    {
        var severity = AuditSeverity(a.Action);
        var message =
            settings.Format == "Cef"
                ? Cef(
                    "audit:" + a.Action,
                    a.Action,
                    severity,
                    [
                        ("rt", a.At.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture)),
                        ("suser", a.Actor),
                        ("msg", a.Target),
                        ("externalId", a.Id),
                    ]
                )
                : JsonSerializer.Serialize(
                    new
                    {
                        kind = "audit",
                        id = a.Id,
                        at = a.At,
                        actor = a.Actor,
                        action = a.Action,
                        target = a.Target,
                    },
                    Plain
                );
        return Syslog(settings, host, SyslogSeverity(severity), a.At, "audit", message);
    }

    /// <summary>Chinese and other text as is, not as \u escapes, so the log server shows it readably.</summary>
    static readonly JsonSerializerOptions Plain = new()
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>An RFC 5424 message: PRI, version, timestamp, host, app, no process id, the message id, no structured data.</summary>
    static string Syslog(
        LogForwardingSettings settings,
        string host,
        int severity,
        DateTimeOffset at,
        string id,
        string message
    ) =>
        $"<{settings.Facility * 8 + severity}>1 {at.UtcDateTime:yyyy-MM-ddTHH:mm:ss.fffZ} {Token(host)} {AppName} - {id} - {message}";

    /// <summary>A header field of RFC 5424: printable ASCII without spaces, at most 255 characters.</summary>
    static string Token(string value)
    {
        var token = new string(value.Where(c => c > ' ' && c < 127).Take(255).ToArray());
        return token.Length == 0 ? "-" : token;
    }

    static string Cef(string signature, string name, int severity, (string Key, string Value)[] extension)
    {
        static string Header(string v) => v.Replace("\\", "\\\\").Replace("|", "\\|").ReplaceLineEndings(" ");

        static string Value(string v) =>
            v.Replace("\\", "\\\\")
                .Replace("=", "\\=")
                .Replace("\r\n", "\\n")
                .Replace("\n", "\\n")
                .Replace("\r", "\\r");

        var version = Header(ComplianceService.Version);
        var ext = string.Join(" ", extension.Where(e => e.Value.Length > 0).Select(e => $"{e.Key}={Value(e.Value)}"));
        return $"CEF:0|恺域科技|终端合规管控|{version}|{Header(signature)}|{Header(name)}|{severity}|{ext}";
    }

    // ---- transport -------------------------------------------------------------------------

    async Task<string?> Send(LogForwardingSettings settings, List<string> messages, CancellationToken ct)
    {
        if (settings.Host.Length == 0)
            return "未填写日志服务器地址";
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        try
        {
            if (settings.Protocol == "Udp")
            {
                using var udp = new UdpClient();
                udp.Connect(settings.Host, settings.Port);
                foreach (var m in messages)
                {
                    var bytes = Encoding.UTF8.GetBytes(m);
                    await udp.SendAsync(bytes.Length > MaxUdpBytes ? bytes[..MaxUdpBytes] : bytes, timeout.Token);
                }
                return null;
            }
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(settings.Host, settings.Port, timeout.Token);
            Stream stream = tcp.GetStream();
            if (settings.Protocol == "Tls")
            {
                var ssl = new SslStream(stream, false);
                stream = ssl;
                await ssl.AuthenticateAsClientAsync(
                    new SslClientAuthenticationOptions
                    {
                        TargetHost = settings.Host,
                        RemoteCertificateValidationCallback = (_, certificate, chain, errors) =>
                            Trusted(settings.CaCertificate, certificate, errors),
                    },
                    timeout.Token
                );
            }
            await using (stream)
            {
                foreach (var m in messages)
                {
                    var bytes = Encoding.UTF8.GetBytes(m);
                    // TLS uses octet counting (RFC 5425); plain TCP ends each message with a line feed, which
                    // most log servers and SIEM inputs take, and the messages themselves hold none.
                    var frame =
                        settings.Protocol == "Tls"
                            ? [.. Encoding.ASCII.GetBytes(bytes.Length + " "), .. bytes]
                            : (byte[])[.. bytes, (byte)'\n'];
                    await stream.WriteAsync(frame, timeout.Token);
                }
                await stream.FlushAsync(timeout.Token);
            }
            return null;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return "连接日志服务器超时";
        }
        catch (Exception e)
            when (e is SocketException or IOException or System.Security.Authentication.AuthenticationException)
        {
            return e is System.Security.Authentication.AuthenticationException
                ? "日志服务器的证书不受信任：" + e.Message
                : "无法连接日志服务器：" + e.Message;
        }
    }

    /// <summary>The system's trust, or a chain ending at one of the configured CA certificates; the name must match.</summary>
    static bool Trusted(string caPem, X509Certificate? certificate, SslPolicyErrors errors)
    {
        if (errors == SslPolicyErrors.None)
            return true;
        if (caPem.Length == 0 || certificate is null || errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
            return false;
        var roots = new X509Certificate2Collection();
        roots.ImportFromPem(caPem);
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(roots);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(new X509Certificate2(certificate));
    }

    /// <summary>Whether <paramref name="pem"/> holds at least one certificate.</summary>
    public static bool ValidCa(string pem)
    {
        try
        {
            var roots = new X509Certificate2Collection();
            roots.ImportFromPem(pem);
            return roots.Count > 0;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}

public sealed class LogForwardingService(LogForwarder forwarder, ILogger<LogForwardingService> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(10));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await forwarder.Run(stoppingToken);
            }
            catch (Exception e) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogError(e, "Log forwarding failed");
            }
        }
    }
}
