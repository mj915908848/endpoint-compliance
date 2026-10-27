using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Compliance.Core;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Compliance.Server.Tests;

/// <summary>Alerts and audit records sent to a syslog server or SIEM.</summary>
public class LogForwardingTests
{
    static readonly AlertSummary Violation = new(
        "a1",
        "dev-1",
        "PC|01",
        "Violation",
        "clash",
        "Clash 已安装 path=C:\\Clash",
        "Active",
        1,
        DateTimeOffset.FromUnixTimeSeconds(1_800_000_000),
        DateTimeOffset.FromUnixTimeSeconds(1_800_000_060),
        false
    );

    static Task<HttpResponseMessage> Save(Fixture f, object settings) =>
        f.Client.PutAsJsonAsync("/api/settings/log-forwarding", settings);

    static async Task RaiseAlert(Fixture f)
    {
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        var violation = new AgentEvent("v1", 1, f.Clock.Now, "Violation", "clash", Detail: "installed");
        Assert.Equal(
            HttpStatusCode.OK,
            (await f.Agent("POST", "/api/agent/events", new EventBatch([violation]))).StatusCode
        );
    }

    /// <summary>Runs the forwarder once, with audit records old enough to be sent.</summary>
    static async Task<LogForwardingResult?> Forward(Fixture f)
    {
        f.Clock.Now += TimeSpan.FromSeconds(10);
        var forwarder = f.Services.GetRequiredService<LogForwarder>();
        await forwarder.Run();
        return forwarder.Last;
    }

    static async Task<List<string>> Received(UdpClient udp)
    {
        var messages = new List<string>();
        using var quiet = new CancellationTokenSource(TimeSpan.FromSeconds(1));
        try
        {
            while (true)
                messages.Add(Encoding.UTF8.GetString((await udp.ReceiveAsync(quiet.Token)).Buffer));
        }
        catch (OperationCanceledException) { }
        return messages;
    }

    [Fact]
    public void Messages_are_rfc_5424_with_json_or_escaped_cef()
    {
        var json = new LogForwardingSettings { Facility = 17 };
        var raised = LogForwarder.Alert(json, "server 1", Violation, "财务部");
        // local1 (17) * 8 + warning (4); host without spaces; message id names the kind.
        Assert.StartsWith("<140>1 2027-01-15T08:00:00.000Z server1 endpoint-compliance - alert - {", raised);
        Assert.Contains("\"event\":\"raised\"", raised);
        Assert.Contains("\"typeName\":\"违规\"", raised);
        Assert.Contains("\"deviceNote\":\"财务部\"", raised);

        var cef = new LogForwardingSettings { Format = "Cef" };
        var resolved = LogForwarder.Alert(cef, "srv", Violation with { State = "Resolved" }, "");
        Assert.StartsWith(
            "<134>1 2027-01-15T08:01:00.000Z srv endpoint-compliance - alert - CEF:0|恺域科技|终端合规管控|",
            resolved
        );
        Assert.Contains("|alert:Violation|违规（已恢复）|1|", resolved);
        Assert.Contains("dhost=PC|01", resolved);
        Assert.Contains("msg=Clash 已安装 path\\=C:\\\\Clash", resolved);
        Assert.Contains("cs2Label=alertType cs2=Violation", resolved);
        Assert.DoesNotContain("cs3Label", resolved);

        var login = LogForwarder.Audit(
            cef,
            "srv",
            new AuditRecord("x", "anonymous", "LoginFailed", "admin（10.0.0.8）", Violation.FirstSeen)
        );
        Assert.StartsWith("<133>1 ", login);
        Assert.Contains("|audit:LoginFailed|LoginFailed|5|", login);
        Assert.Contains("suser=anonymous", login);
    }

    [Fact]
    public async Task Only_account_admins_set_it_and_settings_are_checked()
    {
        await using var f = new Fixture();
        await f.Login("operator");
        Assert.Equal(HttpStatusCode.Forbidden, (await f.Client.GetAsync("/api/settings/log-forwarding")).StatusCode);
        await f.Login();
        foreach (
            var bad in new object[]
            {
                new { enabled = true, host = "" },
                new
                {
                    enabled = true,
                    host = "siem.local",
                    port = 70000,
                },
                new { enabled = true, host = "a b" },
                new
                {
                    enabled = true,
                    host = "siem.local",
                    protocol = "Http",
                },
                new
                {
                    enabled = true,
                    host = "siem.local",
                    facility = 3,
                },
                new
                {
                    enabled = true,
                    host = "siem.local",
                    caCertificate = "not a certificate",
                },
            }
        )
            Assert.Equal(HttpStatusCode.BadRequest, (await Save(f, bad)).StatusCode);
        Assert.Equal(
            HttpStatusCode.OK,
            (
                await Save(
                    f,
                    new
                    {
                        enabled = true,
                        host = " siem.local ",
                        port = 6514,
                        protocol = "Tls",
                        format = "Cef",
                        audit = false,
                    }
                )
            ).StatusCode
        );
        var view = await f.Client.GetFromJsonAsync<LogForwardingView>("/api/settings/log-forwarding", Wire.Json);
        Assert.Equal(
            ("siem.local", 6514, "Tls", "Cef", true, false),
            (
                view!.Settings.Host,
                view.Settings.Port,
                view.Settings.Protocol,
                view.Settings.Format,
                view.Settings.Alerts,
                view.Settings.Audit
            )
        );
        Assert.Contains("SetLogForwarding", await f.Client.GetStringAsync("/api/audit"));
    }

    [Fact]
    public async Task Udp_sends_what_happens_from_when_it_is_set_up_once_each()
    {
        await using var f = new Fixture();
        await f.Login();
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)udp.Client.LocalEndPoint!).Port;
        // Whatever happened while it was off is not sent.
        await f.Code();
        await Forward(f);
        Assert.Equal(
            HttpStatusCode.OK,
            (
                await Save(
                    f,
                    new
                    {
                        enabled = true,
                        host = "127.0.0.1",
                        port,
                    }
                )
            ).StatusCode
        );

        await RaiseAlert(f);
        Assert.True((await Forward(f))!.Ok);
        var messages = await Received(udp);
        Assert.Single(messages, m => m.Contains("- alert - ") && m.Contains("\"event\":\"raised\""));
        Assert.Single(messages, m => m.Contains("\"action\":\"SetLogForwarding\""));
        Assert.Single(messages, m => m.Contains("\"action\":\"EnrollDevice\""));
        Assert.DoesNotContain(messages, m => m.Contains("\"action\":\"Login\""));

        // Nothing again; a resolved alert is sent as such.
        await Forward(f);
        Assert.Empty(await Received(udp));
        var recovered = new AgentEvent("r1", 2, f.Clock.Now, "Recovered", "clash", Detail: "removed");
        await f.Agent("POST", "/api/agent/events", new EventBatch([recovered]));
        await Forward(f);
        Assert.Contains(await Received(udp), m => m.Contains("\"event\":\"resolved\""));

        var test = await f.Client.PostAsync("/api/settings/log-forwarding/test", null);
        Assert.Contains("\"ok\":true", await test.Content.ReadAsStringAsync());
        Assert.Contains(await Received(udp), m => m.Contains("LogForwardingTest"));
    }

    [Fact]
    public async Task Tcp_retries_after_a_failure_and_sends_one_message_per_line()
    {
        await using var f = new Fixture();
        await f.Login();
        var closed = new TcpListener(IPAddress.Loopback, 0);
        closed.Start();
        var closedPort = ((IPEndPoint)closed.LocalEndpoint).Port;
        closed.Stop();
        await Forward(f);
        await Save(
            f,
            new
            {
                enabled = true,
                host = "127.0.0.1",
                port = closedPort,
                protocol = "Tcp",
            }
        );
        await RaiseAlert(f);
        var failed = await Forward(f);
        Assert.False(failed!.Ok);
        Assert.Contains("无法连接", failed.Error);

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        await Save(
            f,
            new
            {
                enabled = true,
                host = "127.0.0.1",
                port,
                protocol = "Tcp",
            }
        );
        var accept = listener.AcceptTcpClientAsync();
        Assert.True((await Forward(f))!.Ok);
        using var client = await accept;
        var text = await new StreamReader(client.GetStream()).ReadToEndAsync();
        listener.Stop();
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Contains(lines, l => l.Contains("\"event\":\"raised\""));
        Assert.All(lines, l => Assert.StartsWith("<", l));
    }

    [Fact]
    public async Task Tls_checks_the_certificate_against_the_system_or_the_given_ca()
    {
        await using var f = new Fixture();
        await f.Login();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName("localhost");
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1)
        );
        using var server = X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pkcs12), null);
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        async Task<string> Serve()
        {
            using var client = await listener.AcceptTcpClientAsync();
            await using var ssl = new SslStream(client.GetStream());
            try
            {
                await ssl.AuthenticateAsServerAsync(server);
                return await new StreamReader(ssl).ReadToEndAsync();
            }
            catch (Exception e) when (e is IOException or System.Security.Authentication.AuthenticationException)
            {
                return "";
            }
        }

        var settings = new
        {
            enabled = true,
            host = "localhost",
            port,
            protocol = "Tls",
        };
        await Save(f, settings);
        var refused = Serve();
        var test = await f.Client.PostAsync("/api/settings/log-forwarding/test", null);
        Assert.Contains("证书", await test.Content.ReadAsStringAsync());
        await refused;

        await Save(
            f,
            new
            {
                enabled = true,
                host = "localhost",
                port,
                protocol = "Tls",
                caCertificate = certificate.ExportCertificatePem(),
            }
        );
        var served = Serve();
        test = await f.Client.PostAsync("/api/settings/log-forwarding/test", null);
        Assert.Contains("\"ok\":true", await test.Content.ReadAsStringAsync());
        var text = await served;
        listener.Stop();
        // Octet counting: the length, a space, then the message.
        var space = text.IndexOf(' ');
        Assert.Equal(Encoding.UTF8.GetByteCount(text[(space + 1)..]), int.Parse(text[..space]));
        Assert.Contains("LogForwardingTest", text);
    }
}
