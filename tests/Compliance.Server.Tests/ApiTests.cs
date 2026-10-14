using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Compliance.Core;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using Xunit;

namespace Compliance.Server.Tests;

public class ApiTests
{
    [Fact]
    public async Task Device_list_requires_admin_session()
    {
        await using var f = new Fixture();
        Assert.Equal(HttpStatusCode.Unauthorized, (await f.Client.GetAsync("/api/devices")).StatusCode);
    }

    [Fact]
    public async Task Policy_template_offers_the_built_in_rules_of_this_server_version()
    {
        await using var f = new Fixture();
        Assert.Equal(HttpStatusCode.Unauthorized, (await f.Client.GetAsync("/api/policies/template")).StatusCode);
        await f.Login("reader");
        var template = (await f.Client.GetFromJsonAsync<PolicyDocument>("/api/policies/template", Wire.Json))!;
        Assert.Contains("aTrust", template.ApprovedNetworkAdapters);
        Assert.Contains(template.Products, p => p.Id == "clash" && p.ExecutableNames.Contains("verge-mihomo.exe"));
    }

    [Fact]
    public async Task Content_security_policy_allows_inline_styles_but_only_same_origin_scripts()
    {
        await using var f = new Fixture();
        var csp = (await f.Client.GetAsync("/api/status")).Headers.GetValues("Content-Security-Policy").Single();
        Assert.Contains("default-src 'self'", csp);
        Assert.Contains("style-src 'self' 'unsafe-inline'", csp);
        Assert.DoesNotContain("script-src", csp);
        Assert.Contains("frame-ancestors 'none'", csp);
    }

    [Fact]
    public async Task Enrollment_is_expiring_single_use_and_persists_across_restart()
    {
        await using var f = new Fixture();
        await f.Login();
        var code = await f.Code();
        var enrolled = await f.Enroll(code);
        Assert.False(string.IsNullOrWhiteSpace(enrolled.DeviceId));
        Assert.Equal(
            HttpStatusCode.BadRequest,
            (
                await f.Client.PostAsJsonAsync(
                    "/api/agent/enroll",
                    new EnrollmentRequest(code, "other", f.Key.ExportSubjectPublicKeyInfoPem()),
                    Wire.Json
                )
            ).StatusCode
        );
        var expired = await f.Code();
        f.Clock.Now = f.Clock.Now.AddMinutes(16);
        Assert.Equal(
            HttpStatusCode.BadRequest,
            (
                await f.Client.PostAsJsonAsync(
                    "/api/agent/enroll",
                    new EnrollmentRequest(expired, "other", f.Key.ExportSubjectPublicKeyInfoPem()),
                    Wire.Json
                )
            ).StatusCode
        );
        await using var restart = new Fixture(f.Directory, f.Clock);
        await restart.Login();
        Assert.Single((await restart.Client.GetFromJsonAsync<DeviceSummary[]>("/api/devices", Wire.Json))!);
        Assert.Equal(
            HttpStatusCode.BadRequest,
            (
                await restart.Client.PostAsJsonAsync(
                    "/api/agent/enroll",
                    new EnrollmentRequest(code, "other", restart.Key.ExportSubjectPublicKeyInfoPem()),
                    Wire.Json
                )
            ).StatusCode
        );
    }

    [Fact]
    public async Task Invalid_device_signatures_and_replayed_nonce_are_rejected()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        var body = new HeartbeatRequest("host", "1", f.Clock.Now, 1, []);
        var nonce = Guid.NewGuid().ToString();
        Assert.Equal(HttpStatusCode.OK, (await f.Agent("POST", "/api/agent/heartbeat", body, nonce)).StatusCode);
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            (await f.Agent("POST", "/api/agent/heartbeat", body, nonce)).StatusCode
        );
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            (await f.Agent("POST", "/api/agent/heartbeat", body, Guid.NewGuid().ToString(), bad: true)).StatusCode
        );
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            (await f.Client.PostAsJsonAsync("/api/agent/heartbeat", body)).StatusCode
        );
    }

    [Fact]
    public async Task Durable_event_deduplication_and_out_of_order_recovery_do_not_reopen_alert()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        var recovered = new AgentEvent("recovery", 2, f.Clock.Now, "Recovered", "cursor", Detail: "removed");
        var violation = new AgentEvent(
            "violation",
            1,
            f.Clock.Now.AddMinutes(-1),
            "Violation",
            "cursor",
            Detail: "installed"
        );
        var r = await f.Agent("POST", "/api/agent/events", new EventBatch([recovered, violation, violation]));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var receipt = await r.Content.ReadFromJsonAsync<EventReceipt>(Wire.Json);
        Assert.Equal(2, receipt!.AcceptedEventIds.Length);
        var alerts = (await f.Client.GetFromJsonAsync<AlertSummary[]>("/api/alerts", Wire.Json))!;
        Assert.Equal("Resolved", Assert.Single(alerts).State);
        Assert.Equal(2, alerts[0].LastSequence);
        await using var restart = new Fixture(f.Directory, f.Clock);
        await restart.Login();
        restart.Device = f.Device;
        restart.Key.ImportFromPem(f.Key.ExportECPrivateKeyPem());
        Assert.Equal(
            HttpStatusCode.OK,
            (await restart.Agent("POST", "/api/agent/events", new EventBatch([violation]))).StatusCode
        );
        Assert.Equal(
            "Resolved",
            Assert.Single((await restart.Client.GetFromJsonAsync<AlertSummary[]>("/api/alerts", Wire.Json))!).State
        );
        var conflict = violation with { Detail = "changed" };
        Assert.Equal(
            HttpStatusCode.Conflict,
            (await restart.Agent("POST", "/api/agent/events", new EventBatch([conflict]))).StatusCode
        );
    }

    [Fact]
    public async Task New_received_time_does_not_refresh_old_scan_or_offline_verdict()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        await f.Agent("POST", "/api/agent/heartbeat", new HeartbeatRequest("host", "1", f.Clock.Now, 1, []));
        var recent = new ScanSnapshot
        {
            DeviceId = f.Device,
            HostName = "host",
            CollectedAt = f.Clock.Now.AddMinutes(-1),
            PolicyVersion = 1,
        };
        var old = recent with { CollectedAt = f.Clock.Now.AddHours(-4) };
        Assert.Equal(
            HttpStatusCode.OK,
            (
                await f.Agent(
                    "POST",
                    "/api/agent/events",
                    new EventBatch([
                        new("recent", 1, recent.CollectedAt, "Snapshot", "scan", recent),
                        new("old", 2, old.CollectedAt, "Snapshot", "scan", old),
                    ])
                )
            ).StatusCode
        );
        var detail = await f.Client.GetFromJsonAsync<JsonElement>($"/api/devices/{f.Device}", Wire.Json);
        Assert.Equal(recent.CollectedAt, detail.GetProperty("snapshot").GetProperty("collectedAt").GetDateTimeOffset());
        f.Clock.Now = f.Clock.Now.AddMinutes(6);
        var devices = (await f.Client.GetFromJsonAsync<DeviceSummary[]>("/api/devices", Wire.Json))!;
        Assert.Equal("Offline", devices[0].OnlineState);
        Assert.Equal(Verdict.UNKNOWN, devices[0].CurrentVerdict);
        Assert.Contains(
            (await f.Client.GetFromJsonAsync<AlertSummary[]>("/api/alerts", Wire.Json))!,
            x => x.Type == "Offline" && x.State == "Active"
        );
    }

    [Fact]
    public async Task Acknowledgment_does_not_resolve_violation_and_only_scan_command_is_allowed()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        await f.Agent(
            "POST",
            "/api/agent/events",
            new EventBatch([new("v", 1, f.Clock.Now, "Violation", "x", Detail: "confirmed")])
        );
        var alert = Assert.Single((await f.Client.GetFromJsonAsync<AlertSummary[]>("/api/alerts", Wire.Json))!);
        Assert.Equal(
            HttpStatusCode.OK,
            (await f.Client.PostAsJsonAsync($"/api/alerts/{alert.Id}/ack", new { })).StatusCode
        );
        alert = Assert.Single((await f.Client.GetFromJsonAsync<AlertSummary[]>("/api/alerts", Wire.Json))!);
        Assert.True(alert.Acknowledged);
        Assert.Equal("Active", alert.State);
        Assert.Equal(
            HttpStatusCode.BadRequest,
            (
                await f.Client.PostAsJsonAsync($"/api/devices/{f.Device}/commands", new { type = "PowerShell" })
            ).StatusCode
        );
        Assert.Equal(
            HttpStatusCode.OK,
            (await f.Client.PostAsJsonAsync($"/api/devices/{f.Device}/commands", new { type = "ScanNow" })).StatusCode
        );
    }

    [Fact]
    public async Task Deleted_device_disappears_with_its_alerts_and_can_enroll_again()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        await f.Agent(
            "POST",
            "/api/agent/events",
            new EventBatch([new("v", 1, f.Clock.Now, "Violation", "x", Detail: "confirmed")])
        );
        Assert.Single((await f.Client.GetFromJsonAsync<AlertSummary[]>("/api/alerts", Wire.Json))!);

        await f.Login("reader");
        Assert.Equal(HttpStatusCode.Forbidden, (await f.Client.DeleteAsync($"/api/devices/{f.Device}")).StatusCode);
        await f.Login();
        Assert.Equal(HttpStatusCode.OK, (await f.Client.DeleteAsync($"/api/devices/{f.Device}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await f.Client.DeleteAsync($"/api/devices/{f.Device}")).StatusCode);

        Assert.Empty((await f.Client.GetFromJsonAsync<DeviceSummary[]>("/api/devices", Wire.Json))!);
        Assert.Empty((await f.Client.GetFromJsonAsync<AlertSummary[]>("/api/alerts", Wire.Json))!);
        Assert.Contains("DeleteDevice", await f.Client.GetStringAsync("/api/audit"));
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            (
                await f.Agent("POST", "/api/agent/events", new EventBatch([new("w", 2, f.Clock.Now, "Violation", "y")]))
            ).StatusCode
        );

        var again = (await f.Enroll(await f.Code())).DeviceId;
        Assert.NotEqual(f.Device, again);
    }

    [Fact]
    public async Task Operator_labels_a_device_with_a_note()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        var url = $"/api/devices/{f.Device}/note";

        var saved = await f.Client.PutAsJsonAsync(url, new { note = "  张三 · 研发部  " });
        Assert.Equal(HttpStatusCode.OK, saved.StatusCode);
        Assert.Equal("张三 · 研发部", (await saved.Content.ReadFromJsonAsync<DeviceSummary>(Wire.Json))!.Note);
        var list = (await f.Client.GetFromJsonAsync<DeviceSummary[]>("/api/devices", Wire.Json))!;
        Assert.Equal("张三 · 研发部", Assert.Single(list).Note);
        Assert.Contains("SetDeviceNote", await f.Client.GetStringAsync("/api/audit"));

        Assert.Equal(
            HttpStatusCode.BadRequest,
            (await f.Client.PutAsJsonAsync(url, new { note = new string('x', 101) })).StatusCode
        );
        Assert.Equal(
            HttpStatusCode.NotFound,
            (await f.Client.PutAsJsonAsync("/api/devices/missing/note", new { note = "x" })).StatusCode
        );
        await f.Login("reader");
        Assert.Equal(HttpStatusCode.Forbidden, (await f.Client.PutAsJsonAsync(url, new { note = "" })).StatusCode);
    }

    [Fact]
    public async Task Reader_cannot_write_and_missing_csrf_is_rejected()
    {
        await using var f = new Fixture();
        await f.Login("reader");
        Assert.Equal(
            HttpStatusCode.Forbidden,
            (await f.Client.PostAsJsonAsync("/api/enrollment-codes", new { })).StatusCode
        );
        await f.Login();
        f.Client.DefaultRequestHeaders.Remove("X-CSRF-Token");
        Assert.Equal(
            HttpStatusCode.Forbidden,
            (await f.Client.PostAsJsonAsync("/api/enrollment-codes", new { })).StatusCode
        );
    }

    [Fact]
    public async Task Publisher_publishes_directly_and_server_assigns_version_and_validity()
    {
        await using var f = new Fixture();
        await f.Login("reader");
        Assert.Equal(HttpStatusCode.Forbidden, (await f.Publish(new PolicyDocument())).StatusCode);

        await f.Login();
        var r = await f.Publish(
            new PolicyDocument
            {
                PolicyId = "office-pcs",
                Version = 99,
                IssuedAt = f.Clock.Now.AddYears(-3),
                ExpiresAt = f.Clock.Now.AddYears(-2),
                RequiredControls = [],
            }
        );
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var current = await f.Client.GetFromJsonAsync<SignedPolicy>("/api/policies/current", Wire.Json);
        var doc = Wire.Read<PolicyDocument>(current!.Payload);
        Assert.Equal(("office-pcs", 2L), (doc.PolicyId, doc.Version));
        Assert.Equal(f.Clock.Now, doc.IssuedAt);
        Assert.Equal(f.Clock.Now + ComplianceService.PolicyValidity, doc.ExpiresAt);
        Assert.Contains("PublishPolicy", await f.Client.GetStringAsync("/api/audit"));

        r = await f.Publish(new PolicyDocument { PolicyId = " ", RequiredControls = [] });
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.Contains("策略名称不能为空", await r.Content.ReadAsStringAsync());
        r = await f.Publish(new PolicyDocument { BlockDomains = ["https://x.com/a"], RequiredControls = [] });
        Assert.Contains("只能填写域名", await r.Content.ReadAsStringAsync());
        r = await f.Publish(new PolicyDocument { Mode = "Enforce" });
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
        Assert.Contains("试点终端", await r.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Historical_scan_stays_unknown_and_offline_report_cannot_claim_current_pass()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        await f.Agent("POST", "/api/agent/heartbeat", new HeartbeatRequest("host", "1", f.Clock.Now, 1, []));
        var snapshot = new ScanSnapshot
        {
            DeviceId = f.Device,
            HostName = "host",
            CollectedAt = f.Clock.Now.AddHours(-4),
            PolicyVersion = 1,
            Modules = new[] { "installed", "processes", "proxy", "extensions", "appx", "ports", "users", "cli" }
                .Select(m => new ModuleResult(m, "machine", "Complete", f.Clock.Now.AddHours(-4)))
                .ToArray(),
        };
        await f.Agent(
            "POST",
            "/api/agent/events",
            new EventBatch([new("old", 1, snapshot.CollectedAt, "Snapshot", "scan", snapshot)])
        );
        var report = await f.Client.GetFromJsonAsync<ComplianceReport>($"/api/devices/{f.Device}/report", Wire.Json);
        Assert.Equal(Verdict.UNKNOWN, report!.Verdict);
        snapshot = snapshot with
        {
            CollectedAt = f.Clock.Now,
            Modules = snapshot.Modules.Select(m => m with { CollectedAt = f.Clock.Now }).ToArray(),
        };
        await f.Agent(
            "POST",
            "/api/agent/events",
            new EventBatch([new("fresh", 2, snapshot.CollectedAt, "Snapshot", "scan", snapshot)])
        );
        report = await f.Client.GetFromJsonAsync<ComplianceReport>($"/api/devices/{f.Device}/report", Wire.Json);
        Assert.Equal(Verdict.PASS, report!.Verdict);
        f.Clock.Now = f.Clock.Now.AddMinutes(6);
        report = await f.Client.GetFromJsonAsync<ComplianceReport>($"/api/devices/{f.Device}/report", Wire.Json);
        Assert.Equal(Verdict.UNKNOWN, report!.Verdict);
    }

    [Fact]
    public async Task Targeted_policy_does_not_assign_to_other_devices()
    {
        await using var f = new Fixture();
        await f.Login();
        var first = (await f.Enroll(await f.Code())).DeviceId;
        f.Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var second = (await f.Enroll(await f.Code())).DeviceId;
        f.Device = second;
        Assert.Equal(HttpStatusCode.OK, (await f.Publish(new PolicyDocument { TargetDeviceIds = [first] })).StatusCode);
        var signed = await (await f.Agent("GET", "/api/agent/policy")).Content.ReadFromJsonAsync<SignedPolicy>(
            Wire.Json
        );
        Assert.Equal(1, Wire.Read<PolicyDocument>(signed!.Payload).Version);
    }

    [Fact]
    public async Task Conflicting_sequence_rolls_back_entire_batch()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        await f.Agent(
            "POST",
            "/api/agent/events",
            new EventBatch([new("one", 1, f.Clock.Now, "Violation", "one", Detail: "one")])
        );
        var r = await f.Agent(
            "POST",
            "/api/agent/events",
            new EventBatch([
                new("two", 2, f.Clock.Now, "Violation", "two", Detail: "two"),
                new("conflict", 1, f.Clock.Now, "Violation", "other", Detail: "other"),
            ])
        );
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
        Assert.Equal(
            "one",
            Assert.Single((await f.Client.GetFromJsonAsync<AlertSummary[]>("/api/alerts", Wire.Json))!).ObjectKey
        );
    }

    [Fact]
    public async Task Credential_summaries_are_sanitized_before_storage_without_breaking_idempotency()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        var snapshot = new ScanSnapshot
        {
            DeviceId = f.Device,
            HostName = "host",
            Evidence =
            [
                new(
                    "proxy",
                    "proxy",
                    EvidenceKind.Proxy,
                    "proxy",
                    "source",
                    "password=hunter2 https://user:pass@host.test/api?token=abc"
                ),
            ],
        };
        var e = new AgentEvent("secret", 1, f.Clock.Now, "Violation", "proxy", snapshot, "token=secret-value");
        Assert.Equal(HttpStatusCode.OK, (await f.Agent("POST", "/api/agent/events", new EventBatch([e]))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await f.Agent("POST", "/api/agent/events", new EventBatch([e]))).StatusCode);
        var detail = await (await f.Client.GetAsync($"/api/devices/{f.Device}")).Content.ReadAsStringAsync();
        Assert.DoesNotContain("hunter2", detail);
        Assert.DoesNotContain("user:pass", detail);
        var alerts = await (await f.Client.GetAsync("/api/alerts")).Content.ReadAsStringAsync();
        Assert.DoesNotContain("secret-value", alerts);
        Assert.DoesNotContain("hunter2", await f.StoredDocuments());
        Assert.DoesNotContain("secret-value", await f.StoredDocuments());
    }

    [Fact]
    public async Task Snapshot_violation_opens_alert_incomplete_clean_does_not_resolve_and_fresh_complete_recovers()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        var snap = new ScanSnapshot
        {
            DeviceId = f.Device,
            HostName = "host",
            PolicyVersion = 1,
            CollectedAt = f.Clock.Now,
            Modules = new[] { "installed", "processes", "proxy", "extensions", "appx", "ports", "users", "cli" }
                .Select(m => new ModuleResult(m, "machine", "Complete", f.Clock.Now))
                .ToArray(),
            Evidence =
            [
                new(
                    "cursor",
                    "Cursor",
                    EvidenceKind.Installation,
                    "installed-cursor",
                    "registry",
                    "Confirmed installation"
                ),
            ],
        };
        Assert.Equal(
            HttpStatusCode.OK,
            (
                await f.Agent(
                    "POST",
                    "/api/agent/events",
                    new EventBatch([new("v", 1, f.Clock.Now, "Snapshot", "scan", snap)])
                )
            ).StatusCode
        );
        var alert = Assert.Single((await f.Client.GetFromJsonAsync<AlertSummary[]>("/api/alerts", Wire.Json))!);
        Assert.Equal("Active", alert.State);
        Assert.Equal("Violation", alert.Type);
        await f.Client.PostAsJsonAsync($"/api/alerts/{alert.Id}/ack", new { });
        snap = snap with { Evidence = [], Modules = snap.Modules.Where(m => m.Module != "installed").ToArray() };
        await f.Agent(
            "POST",
            "/api/agent/events",
            new EventBatch([new("incomplete", 2, f.Clock.Now, "Snapshot", "scan", snap)])
        );
        Assert.Equal(
            "Active",
            Assert.Single((await f.Client.GetFromJsonAsync<AlertSummary[]>("/api/alerts", Wire.Json))!).State
        );
        snap = snap with
        {
            Modules = snap.Modules.Append(new ModuleResult("installed", "machine", "Complete", f.Clock.Now)).ToArray(),
        };
        await f.Agent(
            "POST",
            "/api/agent/events",
            new EventBatch([new("clean", 3, f.Clock.Now, "Snapshot", "scan", snap)])
        );
        Assert.Equal(
            "Resolved",
            Assert.Single((await f.Client.GetFromJsonAsync<AlertSummary[]>("/api/alerts", Wire.Json))!).State
        );
        snap = snap with
        {
            CollectedAt = f.Clock.Now.AddHours(-4),
            Evidence =
            [
                new("cursor", "Cursor", EvidenceKind.Installation, "installed-cursor", "registry", "old installation"),
            ],
        };
        await f.Agent(
            "POST",
            "/api/agent/events",
            new EventBatch([new("stale", 4, snap.CollectedAt, "Snapshot", "scan", snap)])
        );
        Assert.Equal(
            "Resolved",
            Assert.Single((await f.Client.GetFromJsonAsync<AlertSummary[]>("/api/alerts", Wire.Json))!).State
        );
    }

    [Fact]
    public async Task Sensitive_files_alert_per_path_and_resolve_after_complete_rescan()
    {
        await using var f = new Fixture();
        await f.Login();
        var invalid = await f.Publish(
            new PolicyDocument
            {
                SensitiveFiles = new() { Enabled = true },
                RequiredControls = [],
            }
        );
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        Assert.Contains("至少一条规则", await invalid.Content.ReadAsStringAsync());
        Assert.Equal(
            HttpStatusCode.OK,
            (
                await f.Publish(
                    new PolicyDocument
                    {
                        RequiredControls = [],
                        SensitiveFiles = new()
                        {
                            Enabled = true,
                            Rules =
                            [
                                new("secret", "机密文件", ["机密"]),
                                new("salary", "薪资表", ["工资"]) { Action = "Violation" },
                            ],
                        },
                    }
                )
            ).StatusCode
        );
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        const string user = "S-1-5-21-1-2-3-1001";
        var snap = new ScanSnapshot
        {
            DeviceId = f.Device,
            HostName = "host",
            PolicyVersion = 2,
            CollectedAt = f.Clock.Now,
            Modules = new[] { "installed", "processes", "proxy", "extensions", "appx", "ports", "users", "cli" }
                .Select(m => new ModuleResult(m, "machine", "Complete", f.Clock.Now))
                .Append(new ModuleResult(SensitiveFiles.Module, user, "Complete", f.Clock.Now))
                .ToArray(),
            Evidence =
            [
                new(
                    "secret",
                    "机密文件",
                    EvidenceKind.SensitiveFile,
                    @"C:\Users\a\机密.docx",
                    user,
                    "文件名包含“机密”（规则：机密文件）",
                    user
                )
                {
                    CollectedAt = f.Clock.Now,
                },
                new(
                    "salary",
                    "薪资表",
                    EvidenceKind.SensitiveFile,
                    @"C:\Users\a\工资.xlsx",
                    user,
                    "文件名包含“工资”（规则：薪资表）",
                    user
                )
                {
                    CollectedAt = f.Clock.Now,
                },
            ],
        };
        await f.Agent(
            "POST",
            "/api/agent/events",
            new EventBatch([new("s1", 1, f.Clock.Now, "Snapshot", "scan", snap)])
        );
        var alerts = (await f.Client.GetFromJsonAsync<AlertSummary[]>("/api/alerts", Wire.Json))!;
        Assert.Equal(2, alerts.Length);
        Assert.Equal("SensitiveFile", alerts.Single(a => a.ObjectKey.EndsWith("机密.docx")).Type);
        var violation = alerts.Single(a => a.ObjectKey.EndsWith("工资.xlsx"));
        Assert.Equal("Violation", violation.Type);
        Assert.Contains("工资", violation.Summary);
        Assert.All(alerts, a => Assert.Equal("Active", a.State));

        // A truncated rescan without the files proves nothing; a complete one resolves both.
        f.Clock.Now = f.Clock.Now.AddMinutes(5);
        snap = snap with
        {
            CollectedAt = f.Clock.Now,
            Evidence = [],
            Modules = snap
                .Modules.Select(m =>
                    m with
                    {
                        CollectedAt = f.Clock.Now,
                        Status = m.Module == SensitiveFiles.Module ? "Truncated" : m.Status,
                    }
                )
                .ToArray(),
        };
        await f.Agent(
            "POST",
            "/api/agent/events",
            new EventBatch([new("s2", 2, f.Clock.Now, "Snapshot", "scan", snap)])
        );
        Assert.All(
            (await f.Client.GetFromJsonAsync<AlertSummary[]>("/api/alerts", Wire.Json))!,
            a => Assert.Equal("Active", a.State)
        );
        f.Clock.Now = f.Clock.Now.AddMinutes(5);
        snap = snap with
        {
            CollectedAt = f.Clock.Now,
            Modules = snap.Modules.Select(m => m with { CollectedAt = f.Clock.Now, Status = "Complete" }).ToArray(),
        };
        await f.Agent(
            "POST",
            "/api/agent/events",
            new EventBatch([new("s3", 3, f.Clock.Now, "Snapshot", "scan", snap)])
        );
        Assert.All(
            (await f.Client.GetFromJsonAsync<AlertSummary[]>("/api/alerts", Wire.Json))!,
            a => Assert.Equal("Resolved", a.State)
        );
    }

    [Fact]
    public async Task Signed_auth_binds_method_path_body_and_survives_restart_replay_rejection()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        var body = new HeartbeatRequest("host", "1", f.Clock.Now, 1, []);
        var nonce = Guid.NewGuid().ToString();
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            (await f.Agent("POST", "/api/agent/heartbeat", body, signedPath: "/api/agent/events")).StatusCode
        );
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            (await f.Agent("POST", "/api/agent/heartbeat", body, signedBody: "{}")).StatusCode
        );
        Assert.Equal(HttpStatusCode.OK, (await f.Agent("POST", "/api/agent/heartbeat", body, nonce)).StatusCode);
        await using var restart = new Fixture(f.Directory, f.Clock);
        restart.Key.ImportFromPem(f.Key.ExportECPrivateKeyPem());
        restart.Device = f.Device;
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            (await restart.Agent("POST", "/api/agent/heartbeat", body, nonce)).StatusCode
        );
    }

    [Fact]
    public async Task Scan_commands_are_scoped_and_reply_is_durable_idempotent()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        var r = await f.Client.PostAsJsonAsync($"/api/devices/{f.Device}/commands", new { type = "ScanNow" });
        var command = (await r.Content.ReadFromJsonAsync<DeviceCommand>(Wire.Json))!;
        var commands = await (await f.Agent("GET", "/api/agent/commands")).Content.ReadFromJsonAsync<DeviceCommand[]>(
            Wire.Json
        );
        Assert.Equal(command.Id, Assert.Single(commands!).Id);
        Assert.Equal(
            HttpStatusCode.OK,
            (
                await f.Agent("POST", $"/api/agent/commands/{command.Id}/ack", new CommandReply(true, "finished"))
            ).StatusCode
        );
        Assert.Equal(
            HttpStatusCode.OK,
            (
                await f.Agent("POST", $"/api/agent/commands/{command.Id}/ack", new CommandReply(true, "finished"))
            ).StatusCode
        );
        Assert.Empty(
            (await (await f.Agent("GET", "/api/agent/commands")).Content.ReadFromJsonAsync<DeviceCommand[]>(Wire.Json))!
        );
        f.Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        Assert.Equal(
            HttpStatusCode.NotFound,
            (
                await f.Agent("POST", $"/api/agent/commands/{command.Id}/ack", new CommandReply(true, "finished"))
            ).StatusCode
        );
    }

    [Fact]
    public async Task Malformed_nested_snapshot_is_bad_request_and_does_not_mutate_device()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        var batch = new
        {
            events = new[]
            {
                new
                {
                    eventId = "bad",
                    sequence = 1,
                    sourceTime = f.Clock.Now,
                    type = "Snapshot",
                    objectKey = "scan",
                    snapshot = new
                    {
                        deviceId = f.Device,
                        collectedAt = f.Clock.Now,
                        evidence = new object?[] { null },
                        modules = Array.Empty<object>(),
                        controls = Array.Empty<object>(),
                    },
                },
            },
        };
        Assert.Equal(HttpStatusCode.BadRequest, (await f.Agent("POST", "/api/agent/events", batch)).StatusCode);
        var device = await f.Client.GetFromJsonAsync<JsonElement>($"/api/devices/{f.Device}", Wire.Json);
        Assert.Equal(JsonValueKind.Null, device.GetProperty("snapshot").ValueKind);
    }

    [Fact]
    public async Task Policy_change_preserves_historical_verdict_under_original_immutable_release()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        await f.Agent("POST", "/api/agent/heartbeat", new HeartbeatRequest("host", "1", f.Clock.Now, 1, []));
        var snapshot = new ScanSnapshot
        {
            DeviceId = f.Device,
            HostName = "host",
            CollectedAt = f.Clock.Now,
            PolicyVersion = 1,
            Modules = new[] { "installed", "processes", "proxy", "extensions", "appx", "ports", "users", "cli" }
                .Select(m => new ModuleResult(m, "machine", "Complete", f.Clock.Now))
                .ToArray(),
        };
        await f.Agent(
            "POST",
            "/api/agent/events",
            new EventBatch([new("old-pass", 1, f.Clock.Now, "Snapshot", "scan", snapshot)])
        );
        Assert.Equal(HttpStatusCode.OK, (await f.Publish(new PolicyDocument())).StatusCode);
        var devices = (await f.Client.GetFromJsonAsync<DeviceSummary[]>("/api/devices", Wire.Json))!;
        Assert.Equal(Verdict.UNKNOWN, devices[0].CurrentVerdict);
        Assert.Equal(Verdict.PASS, devices[0].LastVerdict);
    }
}

public sealed class ManualClock : TimeProvider
{
    public DateTimeOffset Now = DateTimeOffset.UtcNow;

    public override DateTimeOffset GetUtcNow() => Now;
}

public sealed class Fixture : WebApplicationFactory<Program>
{
    readonly string? postgres;
    readonly string? schema;
    readonly bool ownsSchema;
    public string Directory { get; }
    public ManualClock Clock { get; }
    public ECDsa Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public HttpClient Client;
    public string Device = "";

    public Fixture(string? directory = null, ManualClock? clock = null)
    {
        Directory = directory ?? Path.Combine(Path.GetTempPath(), "compliance-test-" + Guid.NewGuid());
        System.IO.Directory.CreateDirectory(Directory);
        Clock = clock ?? new();
        postgres = Environment.GetEnvironmentVariable("COMPLIANCE_TEST_POSTGRES");
        if (!string.IsNullOrWhiteSpace(postgres))
        {
            var marker = Path.Combine(Directory, "pg-schema");
            if (File.Exists(marker))
                schema = File.ReadAllText(marker);
            else
            {
                schema = "ct_" + Guid.NewGuid().ToString("N");
                File.WriteAllText(marker, schema);
                ownsSchema = true;
                using var connection = new NpgsqlConnection(postgres);
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = "CREATE SCHEMA " + schema;
                command.ExecuteNonQuery();
            }
            var cs = new NpgsqlConnectionStringBuilder(postgres) { SearchPath = schema };
            postgres = cs.ToString();
        }
        Client = CreateClient(new() { BaseAddress = new("http://localhost"), AllowAutoRedirect = false });
    }

    protected override void ConfigureWebHost(IWebHostBuilder b)
    {
        b.ConfigureAppConfiguration(
            (_, c) =>
                c.AddInMemoryCollection(
                    new Dictionary<string, string?>
                    {
                        ["Compliance:DemoMode"] = "true",
                        ["Compliance:Storage"] = postgres == null ? "Sqlite" : "Postgres",
                        ["Compliance:Database"] = postgres ?? Path.Combine(Directory, "test.db"),
                        ["Compliance:SigningKeyPath"] = Path.Combine(Directory, "policy.pem"),
                        ["Compliance:BootstrapUsers"] =
                            "[{\"username\":\"admin\",\"password\":\"test-admin-password-long\",\"roles\":[\"Reader\",\"Operator\",\"Publisher\",\"Reviewer\"]},"
                            + "{\"username\":\"reader\",\"password\":\"test-admin-password-long\",\"roles\":[\"Reader\"]},"
                            + "{\"username\":\"reviewer\",\"password\":\"test-admin-password-long\",\"roles\":[\"Reader\",\"Reviewer\"]}]",
                    }
                )
        );
        b.ConfigureServices(s =>
        {
            s.RemoveAll<TimeProvider>();
            s.AddSingleton<TimeProvider>(Clock);
        });
    }

    public async Task<string> StoredDocuments()
    {
        await using System.Data.Common.DbConnection connection =
            postgres == null
                ? new SqliteConnection("Data Source=" + Path.Combine(Directory, "test.db"))
                : new NpgsqlConnection(postgres);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT body FROM events UNION ALL SELECT host_name FROM devices UNION ALL"
            + " SELECT snapshot FROM devices WHERE snapshot IS NOT NULL UNION ALL"
            + " SELECT controls FROM devices WHERE controls IS NOT NULL UNION ALL SELECT object_key FROM alerts UNION ALL"
            + " SELECT summary FROM alerts";
        await using var reader = await command.ExecuteReaderAsync();
        var text = new StringBuilder();
        while (await reader.ReadAsync())
            text.Append(reader.GetString(0));
        return text.ToString();
    }

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        Key.Dispose();
        if (ownsSchema)
        {
            await using var connection = new NpgsqlConnection(postgres);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "DROP SCHEMA " + schema + " CASCADE";
            await command.ExecuteNonQueryAsync();
        }
    }

    public async Task Login(string username = "admin")
    {
        Client.DefaultRequestHeaders.Remove("X-CSRF-Token");
        var r = await Client.PostAsJsonAsync(
            "/api/auth/login",
            new { username, password = "test-admin-password-long" }
        );
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Client.DefaultRequestHeaders.Add(
            "X-CSRF-Token",
            (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("csrfToken").GetString()
        );
    }

    public Task<HttpResponseMessage> Publish(PolicyDocument doc) =>
        Client.PostAsJsonAsync("/api/policies", doc, Wire.Json);

    public async Task<string> Code()
    {
        var r = await Client.PostAsJsonAsync("/api/enrollment-codes", new { expiresMinutes = 15 });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("code").GetString()!;
    }

    public async Task<EnrollmentResponse> Enroll(string code)
    {
        var r = await Client.PostAsJsonAsync(
            "/api/agent/enroll",
            new EnrollmentRequest(code, "host", Key.ExportSubjectPublicKeyInfoPem()),
            Wire.Json
        );
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<EnrollmentResponse>(Wire.Json))!;
    }

    public async Task<HttpResponseMessage> Agent(
        string method,
        string path,
        object? body = null,
        string? nonce = null,
        bool bad = false,
        string? signedPath = null,
        string? signedBody = null
    )
    {
        var raw = body == null ? "" : JsonSerializer.Serialize(body, Wire.Json);
        var ts = Clock.Now.ToUnixTimeSeconds().ToString();
        nonce ??= Guid.NewGuid().ToString();
        var canonical =
            $"{method}\n{signedPath ?? path}\n{ts}\n{nonce}\n{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(signedBody ?? raw)))}";
        var request = new HttpRequestMessage(new(method), path);
        if (body != null)
            request.Content = new StringContent(raw, Encoding.UTF8, "application/json");
        request.Headers.Add("X-Device-Id", Device);
        request.Headers.Add("X-Timestamp", ts);
        request.Headers.Add("X-Nonce", nonce);
        request.Headers.Add(
            "X-Signature",
            bad
                ? "bad"
                : Convert.ToBase64String(Key.SignData(Encoding.UTF8.GetBytes(canonical), HashAlgorithmName.SHA256))
        );
        return await Client.SendAsync(request);
    }
}
