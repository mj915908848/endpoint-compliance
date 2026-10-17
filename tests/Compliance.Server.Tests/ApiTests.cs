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
    public async Task Device_enrolled_while_the_default_policy_is_being_published_gets_the_new_release()
    {
        await using var f = new Fixture();
        await f.Login();
        var code = await f.Code();
        var service = f.Services.GetRequiredService<ComplianceService>();
        var published = new TaskCompletionSource<long>(TaskCreationOptions.RunContinuationsAsynchronously);
        var commit = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        // A publish that has reassigned the devices it sees but not committed yet.
        var publish = service.Tx(async tx =>
        {
            await tx.Lock(PolicyService.PolicyLock);
            var (_, signed) = await service.Policies.Publish(tx, PolicyService.DefaultPolicy, new PolicyDocument());
            published.SetResult(Wire.Read<PolicyDocument>(signed.Payload).Version);
            await commit.Task;
            return true;
        });
        var version = await published.Task;
        var enroll = f.Enroll(code);
        // Without waiting for the publish, enrollment would finish here on the old release.
        await Task.WhenAny(enroll, Task.Delay(TimeSpan.FromSeconds(1)));
        commit.SetResult();
        await publish;
        await enroll;
        var device = Assert.Single((await f.Client.GetFromJsonAsync<DeviceSummary[]>("/api/devices", Wire.Json))!);
        Assert.Equal(version, device.TargetPolicyVersion);
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
    public async Task Sequence_clashes_and_conflicting_ids_reject_the_whole_batch()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        AgentEvent Event(string id, long sequence, string detail = "found") =>
            new(id, sequence, f.Clock.Now, "Violation", "obj-" + id, Detail: detail);
        Task<HttpResponseMessage> Send(params AgentEvent[] events) =>
            f.Agent("POST", "/api/agent/events", new EventBatch(events));

        Assert.Equal(HttpStatusCode.OK, (await Send(Event("a", 1), Event("b", 2))).StatusCode);
        // A stored event's sequence, one sequence twice in a batch, and one id with two contents in a batch.
        Assert.Equal(HttpStatusCode.Conflict, (await Send(Event("c", 3), Event("d", 2))).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await Send(Event("e", 4), Event("f", 4))).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await Send(Event("g", 5), Event("g", 5, "changed"))).StatusCode);
        // Nothing from a rejected batch was kept: its events are accepted afterwards as new.
        var r = await Send(Event("c", 3), Event("e", 4), Event("g", 5), Event("a", 1));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Equal(4, (await r.Content.ReadFromJsonAsync<EventReceipt>(Wire.Json))!.AcceptedEventIds.Length);
        Assert.Equal(5, (await f.Client.GetFromJsonAsync<AlertSummary[]>("/api/alerts", Wire.Json))!.Length);
    }

    [Fact]
    public async Task Heartbeat_records_the_client_version()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        async Task<DeviceSummary> Beat(string version)
        {
            await f.Agent("POST", "/api/agent/heartbeat", new HeartbeatRequest("host", version, f.Clock.Now, 1, []));
            return Assert.Single((await f.Client.GetFromJsonAsync<DeviceSummary[]>("/api/devices", Wire.Json))!);
        }
        Assert.Equal("0.2.8", (await Beat("0.2.8")).AgentVersion);
        // The fixed value clients before 0.2.8 sent is not a release.
        Assert.Equal("", (await Beat("0.1.0")).AgentVersion);
    }

    [Fact]
    public async Task Heartbeat_records_the_network_adapters_and_where_it_came_from()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        async Task<DeviceSummary> Beat(NetworkAdapter[]? network)
        {
            var r = await f.Agent(
                "POST",
                "/api/agent/heartbeat",
                new HeartbeatRequest("host", "1", f.Clock.Now, 1, [], network)
            );
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            return Assert.Single((await f.Client.GetFromJsonAsync<DeviceSummary[]>("/api/devices", Wire.Json))!);
        }

        var d = await Beat([
            new("WLAN", "a0:b1:c2:d3:e4:f5", ["192.168.31.20", "not an address"]),
            new("以太网", "001122334455", ["10.0.0.5", "fd00::5"], Primary: true),
            new("bad", "00-00-00-00-00-00", ["10.9.9.9"]),
            new("dup", "00-11-22-33-44-55", ["10.0.0.6"]),
        ]);
        Assert.Equal(2, d.Network!.Length);
        Assert.Equal(
            ("以太网", "00-11-22-33-44-55", true),
            (d.Network[0].Name, d.Network[0].Mac, d.Network[0].Primary)
        );
        Assert.Equal(["10.0.0.5", "fd00::5"], d.Network[0].Addresses);
        Assert.Equal("A0-B1-C2-D3-E4-F5", d.Network[1].Mac);
        Assert.Equal(["192.168.31.20"], d.Network[1].Addresses);

        var csv = await (await f.Client.GetAsync("/api/devices/export.csv")).Content.ReadAsStringAsync();
        Assert.Contains("\"10.0.0.5；fd00::5；192.168.31.20\",\"00-11-22-33-44-55；A0-B1-C2-D3-E4-F5\"", csv);

        // Clients before 0.2.22 do not report their adapters.
        Assert.Null((await Beat(null)).Network);
        Assert.Equal(
            HttpStatusCode.BadRequest,
            (
                await f.Agent(
                    "POST",
                    "/api/agent/heartbeat",
                    new HeartbeatRequest(
                        "host",
                        "1",
                        f.Clock.Now,
                        1,
                        [],
                        [.. Enumerable.Range(0, 65).Select(i => new NetworkAdapter("x", "001122334455", []))]
                    )
                )
            ).StatusCode
        );
    }

    [Theory]
    [InlineData("0.2.7", "0.2.8", true)]
    [InlineData("", "0.2.8", true)]
    [InlineData("0.2.8", "0.2.8", false)]
    [InlineData("0.2.9", "0.2.8", false)]
    [InlineData("0.2.7", "0.0.0-dev", false)]
    [InlineData("0.0.0-dev", "0.2.8", false)]
    public void Client_is_outdated_only_against_a_release_server(string agent, string server, bool older) =>
        Assert.Equal(older, ReleaseVersion.Older(agent, server));

    [Fact]
    public async Task Snapshot_events_keep_no_copy_and_old_events_are_pruned()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        var service = f.Services.GetRequiredService<ComplianceService>();
        var snapshot = new ScanSnapshot
        {
            DeviceId = f.Device,
            HostName = "SNAPSHOT-HOST",
            CollectedAt = f.Clock.Now,
            PolicyVersion = 1,
        };
        var batch = new EventBatch([
            new("scan", 1, f.Clock.Now, "Snapshot", "scan", snapshot),
            new("violation", 2, f.Clock.Now, "Violation", "x", Detail: "confirmed"),
        ]);
        Assert.Equal(HttpStatusCode.OK, (await f.Agent("POST", "/api/agent/events", batch)).StatusCode);
        string? Body(string id) => service.Tx(tx => tx.GetEventBody(f.Device, id)).GetAwaiter().GetResult();
        Assert.DoesNotContain("SNAPSHOT-HOST", Body("scan"));
        Assert.Contains("confirmed", Body("violation"));
        var detail = await f.Client.GetFromJsonAsync<JsonElement>($"/api/devices/{f.Device}", Wire.Json);
        Assert.Equal("SNAPSHOT-HOST", detail.GetProperty("snapshot").GetProperty("hostName").GetString());

        f.Clock.Now = f.Clock.Now.AddDays(2);
        // The snapshot event, and the administrator's session that has expired by now.
        Assert.Equal(2, await service.Housekeeping.Maintain());
        Assert.Null(Body("scan"));
        // A retry of a kept event is still recognized.
        Assert.Equal(
            HttpStatusCode.OK,
            (await f.Agent("POST", "/api/agent/events", new EventBatch([batch.Events[1]]))).StatusCode
        );
        Assert.NotNull(Body("violation"));

        f.Clock.Now = f.Clock.Now.AddDays(90);
        Assert.True(await service.Housekeeping.Maintain() >= 1);
        Assert.Null(Body("violation"));
        Assert.Equal(0, await service.Housekeeping.Maintain());
    }

    [Fact]
    public async Task Alert_list_holds_recent_resolved_alerts_older_ones_page_and_old_ones_are_pruned()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        var service = f.Services.GetRequiredService<ComplianceService>();
        var now = f.Clock.Now;
        AlertSummary Alert(string id, string state, int daysAgo) =>
            new(id, f.Device, "HOST", "Health", id, id, state, 1, now.AddDays(-daysAgo), now.AddDays(-daysAgo), false);
        var alerts = new[]
        {
            Alert("active-old", "Active", 400),
            Alert("resolved-recent", "Resolved", 3),
            Alert("resolved-40a", "Resolved", 40),
            Alert("resolved-40b", "Resolved", 40),
            Alert("resolved-100", "Resolved", 100),
            Alert("resolved-200", "Resolved", 200),
        };
        await service.Tx(async tx =>
        {
            foreach (var a in alerts)
                await tx.UpsertAlert(a);
            await tx.PutSnapshotIncident(new SnapshotIncident("resolved-200", f.Device, "machine", ["installed"]));
            await tx.PutSnapshotIncident(new SnapshotIncident("active-old", f.Device, "machine", ["installed"]));
            return true;
        });
        async Task<string[]> Ids(string path) =>
            (await f.Client.GetFromJsonAsync<AlertSummary[]>(path, Wire.Json))!.Select(a => a.Id).ToArray();

        Assert.Equal(["resolved-recent", "active-old"], await Ids("/api/alerts"));
        // Paging back from the oldest alert listed, two at a time; alerts resolved at the same moment are not lost.
        var start = Uri.EscapeDataString(now.AddDays(-30).ToString("O"));
        var first = await Ids($"/api/alerts/resolved?before={start}&beforeId=&limit=2");
        Assert.Equal(["resolved-40b", "resolved-40a"], first);
        // The first page can leave the cursor out: it then starts where the list above ends, by the server's clock.
        Assert.Equal(first, await Ids("/api/alerts/resolved?limit=2"));
        var cursor = Uri.EscapeDataString(now.AddDays(-40).ToString("O"));
        Assert.Equal(
            ["resolved-100", "resolved-200"],
            await Ids($"/api/alerts/resolved?before={cursor}&beforeId=resolved-40a&limit=2")
        );

        // Alerts resolved more than 180 days ago go, with their recovery records; open alerts stay however old.
        await service.Housekeeping.Maintain();
        var left = await service.Tx(async tx => (await tx.ResolvedAlertsBefore(now, "", 100)).Select(a => a.Id));
        Assert.Equal(["resolved-recent", "resolved-40b", "resolved-40a", "resolved-100"], left);
        Assert.NotNull(await service.Tx(tx => tx.GetAlert("active-old")));
        Assert.Null(await service.Tx(tx => tx.GetSnapshotIncident("resolved-200")));
        Assert.NotNull(await service.Tx(tx => tx.GetSnapshotIncident("active-old")));
    }

    [Fact]
    public async Task Device_list_shows_a_new_snapshot_at_once_and_judges_expired_verdicts_without_storing_them()
    {
        await using var f = new Fixture();
        await f.Login();
        var service = f.Services.GetRequiredService<ComplianceService>();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        async Task<DeviceSummary> Listed() =>
            Assert.Single((await f.Client.GetFromJsonAsync<DeviceSummary[]>("/api/devices", Wire.Json))!);
        async Task<StoredVerdict?> Stored() => (await service.Tx(tx => tx.GetDevice(f.Device)))!.Verdict;
        async Task Heartbeat() =>
            await f.Agent("POST", "/api/agent/heartbeat", new HeartbeatRequest("host", "1", f.Clock.Now, 1, []));
        await Heartbeat();
        Assert.Null((await Listed()).LastScan);
        var scanned = f.Clock.Now;
        var snapshot = new ScanSnapshot
        {
            DeviceId = f.Device,
            HostName = "host",
            CollectedAt = scanned,
            PolicyVersion = 1,
            Evidence = [new("cursor", "Cursor", EvidenceKind.Installation, "Cursor", "registry", "Cursor 已安装")],
        };
        await f.Agent(
            "POST",
            "/api/agent/events",
            new EventBatch([new("s1", 1, f.Clock.Now, "Snapshot", "scan", snapshot)])
        );

        // Receiving the snapshot stored its verdict, which holds until the scan is too old to count.
        var stored = Assert.IsType<StoredVerdict>(await Stored());
        Assert.Equal(Verdict.FAIL, stored.Current);
        Assert.Equal(1, stored.SnapshotSequence);
        Assert.Equal(scanned.AddMinutes(new PolicyDocument().LightweightFreshMinutes).AddTicks(1), stored.ValidUntil);
        var listed = await Listed();
        Assert.Equal(scanned, listed.LastScan);
        Assert.Equal(Verdict.FAIL, listed.CurrentVerdict);
        Assert.Equal(1, listed.ViolationCount);

        // Past that, the list judges the device again but stores nothing; the background refresh does.
        f.Clock.Now = stored.ValidUntil!.Value;
        await Heartbeat();
        Assert.Equal(Verdict.UNKNOWN, (await Listed()).CurrentVerdict);
        var detail = await f.Client.GetFromJsonAsync<JsonElement>($"/api/devices/{f.Device}", Wire.Json);
        Assert.Equal("UNKNOWN", detail.GetProperty("device").GetProperty("currentVerdict").GetString());
        Assert.Equal(stored, await Stored());
        Assert.Equal(1, await service.Verdicts.RefreshVerdicts());
        Assert.Equal(Verdict.UNKNOWN, (await Stored())!.Current);
        Assert.Equal(0, await service.Verdicts.RefreshVerdicts());
        Assert.Equal(Verdict.UNKNOWN, (await Listed()).CurrentVerdict);
    }

    [Fact]
    public async Task Verdict_changes_are_recorded_once_each_and_shown_as_history_and_trend()
    {
        await using var f = new Fixture();
        await f.Login();
        var service = f.Services.GetRequiredService<ComplianceService>();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        async Task<VerdictChange[]> History() =>
            (await f.Client.GetFromJsonAsync<VerdictChange[]>($"/api/devices/{f.Device}/history", Wire.Json))!;
        async Task Snapshot(string id, long sequence) =>
            await f.Agent(
                "POST",
                "/api/agent/events",
                new EventBatch([
                    new(
                        id,
                        sequence,
                        f.Clock.Now,
                        "Snapshot",
                        "scan",
                        new ScanSnapshot
                        {
                            DeviceId = f.Device,
                            HostName = "host",
                            CollectedAt = f.Clock.Now,
                            PolicyVersion = 1,
                            Evidence =
                            [
                                new("cursor", "Cursor", EvidenceKind.Installation, "Cursor", "registry", "已安装"),
                            ],
                        }
                    ),
                ])
            );

        // Enrolled without a scan: unknown, recorded by the first refresh.
        Assert.Equal(1, await service.Verdicts.RefreshVerdicts());
        Assert.Equal([Verdict.UNKNOWN], (await History()).Select(h => h.Verdict));
        await Snapshot("s1", 1);
        f.Clock.Now += TimeSpan.FromMinutes(1);
        await Snapshot("s2", 2);
        var changes = await History();
        Assert.Equal([Verdict.UNKNOWN, Verdict.FAIL], changes.Select(h => h.Verdict));
        Assert.Equal(1, changes[1].ViolationCount);

        // The scan going stale makes the device unknown again once the refresh stores it.
        f.Clock.Now += TimeSpan.FromHours(1);
        // An hour idle signs the administrator out.
        await f.Login();
        Assert.Equal(1, await service.Verdicts.RefreshVerdicts());
        Assert.Equal([Verdict.UNKNOWN, Verdict.FAIL, Verdict.UNKNOWN], (await History()).Select(h => h.Verdict));

        var trend = (await f.Client.GetFromJsonAsync<TrendDay[]>("/api/devices/trend?days=3&offset=480", Wire.Json))!;
        Assert.Equal(3, trend.Length);
        Assert.Equal(new TrendDay(trend[2].Date, 0, 0, 1), trend[2]);

        // Pruning old history keeps each device's latest change, so its state stays known.
        f.Clock.Now += VerdictService.VerdictHistoryRetention + TimeSpan.FromDays(1);
        await service.Housekeeping.Maintain();
        await f.Login();
        Assert.Equal(
            [Verdict.UNKNOWN],
            (await service.Tx(tx => tx.DeviceVerdictChanges(f.Device, DateTimeOffset.MinValue))).Select(h => h.Verdict)
        );
        Assert.Equal(HttpStatusCode.NotFound, (await f.Client.GetAsync("/api/devices/missing/history")).StatusCode);
    }

    [Fact]
    public void Trend_counts_each_device_by_its_last_verdict_of_each_day_in_the_given_time_zone()
    {
        var zone = TimeSpan.FromHours(8);
        // 2026-10-17 09:00 in UTC+8.
        var now = new DateTimeOffset(2026, 10, 17, 1, 0, 0, TimeSpan.Zero);
        var day1 = new DateTimeOffset(2026, 10, 15, 0, 0, 0, zone);
        Assert.Equal(day1, VerdictTrend.Start(now, 3, zone));
        VerdictChange C(string device, DateTimeOffset at, Verdict v) => new(device, at, v, 0, 1);
        var trend = VerdictTrend.Daily(
            now,
            3,
            zone,
            [C("a", day1.AddDays(-3), Verdict.PASS)],
            [
                C("b", day1.AddHours(5), Verdict.FAIL),
                C("a", day1.AddHours(6), Verdict.FAIL),
                C("a", day1.AddHours(7), Verdict.UNKNOWN),
                // 23:59 on the second day still counts for it; midnight belongs to the next.
                C("b", day1.AddDays(2).AddMinutes(-1), Verdict.PASS),
                C("c", day1.AddDays(2), Verdict.PASS),
            ]
        );
        Assert.Equal(
            [
                new TrendDay(new(2026, 10, 15), 0, 1, 1),
                new TrendDay(new(2026, 10, 16), 1, 0, 1),
                new TrendDay(new(2026, 10, 17), 2, 0, 1),
            ],
            trend
        );
    }

    [Fact]
    public async Task Publishing_a_policy_leaves_stored_verdicts_to_the_background_refresh()
    {
        await using var f = new Fixture();
        await f.Login();
        var service = f.Services.GetRequiredService<ComplianceService>();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        // An enrolled device has no stored verdict until the refresh stores one; the list judges it meanwhile.
        Assert.Null((await service.Tx(tx => tx.GetDevice(f.Device)))!.Verdict);
        Assert.Single((await f.Client.GetFromJsonAsync<DeviceSummary[]>("/api/devices", Wire.Json))!);
        Assert.Equal(1, await service.Verdicts.RefreshVerdicts());
        var before = (await service.Tx(tx => tx.GetDevice(f.Device)))!;
        await service.Tx(async tx =>
        {
            await service.Policies.Publish(tx, PolicyService.DefaultPolicy, new PolicyDocument());
            return true;
        });
        var after = (await service.Tx(tx => tx.GetDevice(f.Device)))!;
        Assert.NotEqual(before.TargetPolicyVersion, after.TargetPolicyVersion);
        Assert.False(after.Verdict!.HoldsFor(after, f.Clock.Now));
        var listed = Assert.Single((await f.Client.GetFromJsonAsync<DeviceSummary[]>("/api/devices", Wire.Json))!);
        Assert.Equal(after.Verdict, (await service.Tx(tx => tx.GetDevice(f.Device)))!.Verdict);
        Assert.Equal(1, await service.Verdicts.RefreshVerdicts());
        var refreshed = (await service.Tx(tx => tx.GetDevice(f.Device)))!;
        Assert.True(refreshed.Verdict!.HoldsFor(refreshed, f.Clock.Now));
        Assert.Equal(listed.TargetPolicyVersion, refreshed.Verdict.PolicyVersion);
    }

    [Fact]
    public async Task Heartbeat_reports_the_highest_sequence_held_even_after_events_are_pruned()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        async Task<long> LastSequence() =>
            (
                await (
                    await f.Agent("POST", "/api/agent/heartbeat", new HeartbeatRequest("host", "1", f.Clock.Now, 1, []))
                ).Content.ReadFromJsonAsync<JsonElement>()
            )
                .GetProperty("lastSequence")
                .GetInt64();
        Assert.Equal(0, await LastSequence());
        var snapshot = new ScanSnapshot
        {
            DeviceId = f.Device,
            HostName = "host",
            CollectedAt = f.Clock.Now,
            PolicyVersion = 1,
        };
        var batch = new EventBatch([
            new("scan", 7, f.Clock.Now, "Snapshot", "scan", snapshot),
            new("violation", 9, f.Clock.Now, "Violation", "x", Detail: "confirmed"),
        ]);
        Assert.Equal(HttpStatusCode.OK, (await f.Agent("POST", "/api/agent/events", batch)).StatusCode);
        Assert.Equal(9, await LastSequence());

        // Once the events are pruned, the device's snapshot and alerts still hold their sequences.
        f.Clock.Now = f.Clock.Now.AddDays(200);
        await f.Services.GetRequiredService<ComplianceService>().Housekeeping.Maintain();
        Assert.Equal(9, await LastSequence());
    }

    [Fact]
    public async Task Compressed_uploads_are_verified_as_sent_and_expanded_within_limits()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        var heartbeat = await f.Agent(
            "POST",
            "/api/agent/heartbeat",
            new HeartbeatRequest("host", "1", f.Clock.Now, 1, [])
        );
        Assert.True((await heartbeat.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("gzipUploads").GetBoolean());
        var batch = new EventBatch([new("v", 1, f.Clock.Now, "Violation", "x", Detail: new string('a', 1000))]);
        var accepted = await f.Agent("POST", "/api/agent/events", batch, encoding: "gzip");
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.Equal(["v"], (await accepted.Content.ReadFromJsonAsync<EventReceipt>(Wire.Json))!.AcceptedEventIds);
        // Uncompressed bodies from earlier clients still work.
        Assert.Equal(
            HttpStatusCode.OK,
            (
                await f.Agent("POST", "/api/agent/events", new EventBatch([new("w", 2, f.Clock.Now, "Violation", "y")]))
            ).StatusCode
        );
        Assert.Equal(
            HttpStatusCode.UnsupportedMediaType,
            (await f.Agent("POST", "/api/agent/events", batch, encoding: "br")).StatusCode
        );
        // A small compressed body that expands past the limit.
        var bomb = new EventBatch([
            new("b", 3, f.Clock.Now, "Violation", "z", Detail: new string('a', 8 * 1024 * 1024)),
        ]);
        Assert.Equal(
            HttpStatusCode.RequestEntityTooLarge,
            (await f.Agent("POST", "/api/agent/events", bomb, encoding: "gzip")).StatusCode
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
        // Reading pages opens no alert; the background status refresh does.
        Assert.DoesNotContain(
            (await f.Client.GetFromJsonAsync<AlertSummary[]>("/api/alerts", Wire.Json))!,
            x => x.Type == "Offline"
        );
        var service = f.Services.GetRequiredService<ComplianceService>();
        await service.Tx(async tx =>
        {
            await service.Housekeeping.UpdateOffline(tx);
            return true;
        });
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
        Assert.Equal(f.Clock.Now + PolicyService.PolicyValidity, doc.ExpiresAt);
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
    public async Task Publishing_from_an_older_release_is_refused_so_nothing_is_overwritten_unseen()
    {
        await using var f = new Fixture();
        await f.Login();
        var doc = new PolicyDocument { PolicyId = "office-pcs", RequiredControls = [] };
        Task<HttpResponseMessage> Publish(string query) =>
            f.Client.PostAsJsonAsync("/api/policies/default" + query, doc, Wire.Json);

        Assert.Equal(HttpStatusCode.OK, (await Publish("?baseVersion=1")).StatusCode);
        var stale = await Publish("?baseVersion=1");
        Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);
        Assert.Contains("已被他人更新为 v2", await stale.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.OK, (await Publish("?baseVersion=2")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Publish("?baseVersion=x")).StatusCode);
        // Callers that do not say which release they started from publish as before.
        Assert.Equal(HttpStatusCode.OK, (await Publish("")).StatusCode);
    }

    [Fact]
    public async Task Session_ends_after_idle_minutes_and_polling_alone_does_not_keep_it()
    {
        await using var f = new Fixture();
        await f.Login();
        Assert.Contains("\"idleMinutes\":30", await f.Client.GetStringAsync("/api/me"));
        Task<HttpResponseMessage> Poll(int idleSeconds)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "/api/devices");
            request.Headers.Add("X-Idle-Seconds", idleSeconds.ToString());
            return f.Client.SendAsync(request);
        }

        // The page keeps polling but nobody touches it.
        f.Clock.Now = f.Clock.Now.AddMinutes(20);
        Assert.Equal(HttpStatusCode.OK, (await Poll(20 * 60)).StatusCode);
        f.Clock.Now = f.Clock.Now.AddMinutes(11);
        var idle = await Poll(31 * 60);
        Assert.Equal(HttpStatusCode.Unauthorized, idle.StatusCode);
        Assert.Contains("Session idle", await idle.Content.ReadAsStringAsync());

        // Use reported by the page, or a request that does not report (a download), keeps it.
        await f.Login();
        f.Clock.Now = f.Clock.Now.AddMinutes(20);
        Assert.Equal(HttpStatusCode.OK, (await Poll(5)).StatusCode);
        f.Clock.Now = f.Clock.Now.AddMinutes(20);
        Assert.Equal(HttpStatusCode.OK, (await f.Client.GetAsync("/api/devices")).StatusCode);
        f.Clock.Now = f.Clock.Now.AddMinutes(25);
        Assert.Equal(HttpStatusCode.OK, (await Poll(25 * 60)).StatusCode);
    }

    [Fact]
    public async Task Devices_enrolling_together_do_not_use_up_the_sign_in_limit()
    {
        await using var f = new Fixture();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        for (var i = 0; i < 30; i++)
        {
            var r = await f.Client.PostAsJsonAsync(
                "/api/agent/enroll",
                new EnrollmentRequest("not-a-code", "pc-" + i, key.ExportSubjectPublicKeyInfoPem()),
                Wire.Json
            );
            Assert.NotEqual(HttpStatusCode.TooManyRequests, r.StatusCode);
        }
        await f.Login();
    }

    [Fact]
    public async Task Repeated_wrong_passwords_lock_the_account_for_a_while()
    {
        await using var f = new Fixture();
        Task<HttpResponseMessage> SignIn(string username, string password) =>
            f.Client.PostAsJsonAsync("/api/auth/login", new { username, password });

        for (var i = 0; i < LoginThrottle.MaxFailures; i++)
            Assert.Equal(HttpStatusCode.Unauthorized, (await SignIn("ADMIN", "wrong-password")).StatusCode);
        var locked = await SignIn("admin", "test-admin-password-long");
        Assert.Equal(HttpStatusCode.TooManyRequests, locked.StatusCode);
        Assert.Contains("15 分钟后再试", await locked.Content.ReadAsStringAsync());
        // Other accounts are not affected.
        Assert.Equal(HttpStatusCode.OK, (await SignIn("reader", "test-admin-password-long")).StatusCode);

        f.Clock.Now += LoginThrottle.Window;
        await f.Login();
    }

    [Fact]
    public async Task Authentication_applies_whatever_the_case_of_the_path()
    {
        await using var f = new Fixture();
        Assert.Equal(HttpStatusCode.Unauthorized, (await f.Client.GetAsync("/API/devices")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await f.Client.GetAsync("/Api/Me")).StatusCode);
        var unsigned = await f.Client.PostAsJsonAsync(
            "/API/Agent/heartbeat",
            new HeartbeatRequest("host", "1", f.Clock.Now, 1, []),
            Wire.Json
        );
        Assert.Equal(HttpStatusCode.Unauthorized, unsigned.StatusCode);
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
            Modules = PolicyDocument
                .AllModules.Select(m => new ModuleResult(m, "machine", "Complete", f.Clock.Now.AddHours(-4)))
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
    public async Task Named_policies_apply_to_their_devices_and_others_keep_the_default()
    {
        await using var f = new Fixture();
        await f.Login();
        var first = (await f.Enroll(await f.Code())).DeviceId;
        f.Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var second = (await f.Enroll(await f.Code())).DeviceId;
        f.Device = second;
        async Task<Dictionary<string, DeviceSummary>> Devices() =>
            (await f.Client.GetFromJsonAsync<DeviceSummary[]>("/api/devices", Wire.Json))!.ToDictionary(d => d.Id);

        var created = await f.Client.PostAsJsonAsync(
            "/api/policies/new",
            new PolicyDocument { PolicyId = "研发部", TargetDeviceIds = [first] },
            Wire.Json
        );
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        var pilot = await created.Content.ReadFromJsonAsync<PolicyListItem>(Wire.Json);
        Assert.Equal(1, pilot!.Devices);
        var devices = await Devices();
        // Each policy counts its own versions.
        Assert.Equal(("研发部", 1L), (devices[first].PolicyName, devices[first].TargetPolicyVersion));
        Assert.Equal(2L, Wire.Read<PolicyDocument>(pilot.Release.Payload).Serial);
        Assert.Equal(("Default", 1L), (devices[second].PolicyName, devices[second].TargetPolicyVersion));
        // The device that was not named still receives the default release it already had.
        var signed = await (await f.Agent("GET", "/api/agent/policy")).Content.ReadFromJsonAsync<SignedPolicy>(
            Wire.Json
        );
        Assert.Equal(1, Wire.Read<PolicyDocument>(signed!.Payload).Version);

        Assert.Equal(
            HttpStatusCode.Conflict,
            (
                await f.Client.PostAsJsonAsync(
                    "/api/policies/new",
                    new PolicyDocument { PolicyId = "测试组", TargetDeviceIds = [first] },
                    Wire.Json
                )
            ).StatusCode
        );
        Assert.Equal(
            HttpStatusCode.Conflict,
            (
                await f.Client.PostAsJsonAsync(
                    "/api/policies/new",
                    new PolicyDocument { PolicyId = "default", TargetDeviceIds = [second] },
                    Wire.Json
                )
            ).StatusCode
        );
        Assert.Equal(
            HttpStatusCode.BadRequest,
            (
                await f.Client.PostAsJsonAsync("/api/policies/new", new PolicyDocument { PolicyId = "空" }, Wire.Json)
            ).StatusCode
        );
        Assert.Equal(
            HttpStatusCode.Conflict,
            (await f.Publish(new PolicyDocument { Mode = "Enforce", TargetDeviceIds = [second] })).StatusCode
        );

        var list = await f.Client.GetFromJsonAsync<PolicyListItem[]>("/api/policies", Wire.Json);
        Assert.Equal([(true, 1), (false, 1)], list!.Select(p => (p.IsDefault, p.Devices)));

        // Deleting the named policy moves its device back to the default policy under a newer serial, because
        // agents refuse a lower one than they hold; the default policy's own version stays the same.
        Assert.Equal(HttpStatusCode.OK, (await f.Client.DeleteAsync("/api/policies/" + pilot.Key)).StatusCode);
        devices = await Devices();
        Assert.Equal(("Default", 1L), (devices[first].PolicyName, devices[first].TargetPolicyVersion));
        Assert.Equal(devices[first].TargetPolicyVersion, devices[second].TargetPolicyVersion);
        signed = await (await f.Agent("GET", "/api/agent/policy")).Content.ReadFromJsonAsync<SignedPolicy>(Wire.Json);
        Assert.True(Wire.Read<PolicyDocument>(signed!.Payload).Serial > 2);
        Assert.Single((await f.Client.GetFromJsonAsync<PolicyListItem[]>("/api/policies", Wire.Json))!);
        Assert.Equal(HttpStatusCode.Conflict, (await f.Client.DeleteAsync("/api/policies/default")).StatusCode);
    }

    [Fact]
    public async Task A_batch_code_enrolls_up_to_its_limit_until_revoked()
    {
        await using var f = new Fixture();
        await f.Login();
        var created = await f.Client.PostAsJsonAsync(
            "/api/enrollment-codes",
            new
            {
                expiresMinutes = 7 * 24 * 60,
                maxUses = 2,
                label = "研发部",
            }
        );
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        var body = await created.Content.ReadFromJsonAsync<JsonElement>();
        var code = body.GetProperty("code").GetString()!;
        var id = body.GetProperty("id").GetString()!;

        async Task<HttpStatusCode> EnrollNew(string with)
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            return (
                await f.Client.PostAsJsonAsync(
                    "/api/agent/enroll",
                    new EnrollmentRequest(with, "pc", key.ExportSubjectPublicKeyInfoPem()),
                    Wire.Json
                )
            ).StatusCode;
        }
        Assert.Equal(HttpStatusCode.OK, await EnrollNew(code));
        Assert.Equal(HttpStatusCode.OK, await EnrollNew(code));
        Assert.Equal(HttpStatusCode.BadRequest, await EnrollNew(code));

        var listed = (await f.Client.GetFromJsonAsync<JsonElement>("/api/enrollment-codes")).EnumerateArray().Single();
        Assert.Equal(
            ("研发部", 2, 2, false),
            (
                listed.GetProperty("label").GetString(),
                listed.GetProperty("maxUses").GetInt32(),
                listed.GetProperty("uses").GetInt32(),
                listed.GetProperty("revoked").GetBoolean()
            )
        );

        var another = await f.Client.PostAsJsonAsync("/api/enrollment-codes", new { maxUses = 50 });
        var second = await another.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(
            HttpStatusCode.OK,
            (await f.Client.DeleteAsync("/api/enrollment-codes/" + second.GetProperty("id").GetString())).StatusCode
        );
        Assert.Equal(HttpStatusCode.BadRequest, await EnrollNew(second.GetProperty("code").GetString()!));
        Assert.Equal(HttpStatusCode.NotFound, (await f.Client.DeleteAsync("/api/enrollment-codes/nope")).StatusCode);

        var tooMany = await f.Client.PostAsJsonAsync("/api/enrollment-codes", new { maxUses = 501 });
        Assert.Equal(HttpStatusCode.BadRequest, tooMany.StatusCode);
        var tooLong = await f.Client.PostAsJsonAsync("/api/enrollment-codes", new { expiresMinutes = 7 * 24 * 60 + 1 });
        Assert.Equal(HttpStatusCode.BadRequest, tooLong.StatusCode);
        Assert.NotEqual("", id);
    }

    [Fact]
    public async Task Check_intervals_set_how_long_results_stay_current()
    {
        await using var f = new Fixture();
        await f.Login();
        var slower = PolicySeed.Create() with { QuickCheckMinutes = 15, FullCheckMinutes = 240 };
        var published = await f.Client.PostAsJsonAsync("/api/policies", slower, Wire.Json);
        Assert.Equal(HttpStatusCode.OK, published.StatusCode);
        var doc = Wire.Read<PolicyDocument>(
            (await published.Content.ReadFromJsonAsync<SignedPolicy>(Wire.Json))!.Payload
        );
        Assert.Equal(
            (15, 240, 30, 480),
            (doc.QuickCheckMinutes, doc.FullCheckMinutes, doc.LightweightFreshMinutes, doc.InventoryFreshMinutes)
        );

        var backwards = await f.Client.PostAsJsonAsync(
            "/api/policies",
            slower with
            {
                QuickCheckMinutes = 30,
                FullCheckMinutes = 20,
            },
            Wire.Json
        );
        Assert.Equal(HttpStatusCode.BadRequest, backwards.StatusCode);
        Assert.Contains("完整检查的间隔不能短于快速检查", await backwards.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Enforcement_starts_once_the_pilot_device_reports_its_measures_ready()
    {
        await using var f = new Fixture();
        await f.Login();
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        var snap = new ScanSnapshot
        {
            DeviceId = f.Device,
            HostName = "pilot",
            PolicyVersion = 1,
            CollectedAt = f.Clock.Now,
        };
        await f.Agent(
            "POST",
            "/api/agent/events",
            new EventBatch([new("s", 1, f.Clock.Now, "Snapshot", "scan", snap)])
        );
        async Task Heartbeat(params ControlState[] controls) =>
            Assert.Equal(
                HttpStatusCode.OK,
                (
                    await f.Agent(
                        "POST",
                        "/api/agent/heartbeat",
                        new HeartbeatRequest("pilot", "1", f.Clock.Now, 1, controls),
                        Guid.NewGuid().ToString()
                    )
                ).StatusCode
            );
        var pilot = PolicySeed.Create() with
        {
            PolicyId = "试点",
            Mode = "Enforce",
            TargetDeviceIds = [f.Device],
            RequiredControls = ["application", "edge", "network"],
        };

        await Heartbeat(
            new ControlState("process", 1, "Ready", "可启用", true),
            new ControlState("browser", 1, "Uncovered", "客户端没有写入浏览器策略的权限")
        );
        var refused = await f.Client.PostAsJsonAsync("/api/policies/new", pilot, Wire.Json);
        Assert.Equal(HttpStatusCode.Conflict, refused.StatusCode);
        Assert.Contains("浏览器网址拦截", await refused.Content.ReadAsStringAsync());

        await Heartbeat(
            new ControlState("process", 1, "Ready", "可启用", true),
            new ControlState("browser", 1, "Ready", "可启用", true)
        );
        var created = await f.Client.PostAsJsonAsync("/api/policies/new", pilot, Wire.Json);
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        var doc = Wire.Read<PolicyDocument>(
            (await created.Content.ReadFromJsonAsync<PolicyListItem>(Wire.Json))!.Release.Payload
        );
        // Legacy names map onto the measures that exist; the never-implemented network measure is dropped.
        Assert.Equal(["process", "browser"], doc.RequiredControls);

        await f.Agent(
            "POST",
            "/api/agent/events",
            new EventBatch([
                new("b", 2, f.Clock.Now, "BlockedAttempt", "blocked:cursor", null, "Cursor（Cursor.exe）已被结束"),
            ])
        );
        var blocked = Assert.Single(
            (await f.Client.GetFromJsonAsync<AlertSummary[]>("/api/alerts", Wire.Json))!,
            a => a.Type == "BlockedAttempt"
        );
        Assert.Equal("Cursor（Cursor.exe）已被结束", blocked.Summary);
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
            Modules = PolicyDocument
                .AllModules.Select(m => new ModuleResult(m, "machine", "Complete", f.Clock.Now))
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
            Modules = PolicyDocument
                .AllModules.Select(m => new ModuleResult(m, "machine", "Complete", f.Clock.Now))
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
            Modules = PolicyDocument
                .AllModules.Select(m => new ModuleResult(m, "machine", "Complete", f.Clock.Now))
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

    /// <summary>Answers the alert notifier instead of a real group robot.</summary>
    public WebhookStub Webhook { get; } = new();

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
            // Tests run the status refresh themselves, at the times they choose.
            foreach (var monitor in s.Where(d => d.ImplementationType == typeof(StatusMonitor)).ToList())
                s.Remove(monitor);
            s.AddHttpClient(AlertNotifier.HttpClientName)
                .ConfigurePrimaryHttpMessageHandler(() => Webhook)
                .SetHandlerLifetime(Timeout.InfiniteTimeSpan);
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
        string? signedBody = null,
        string? encoding = null
    )
    {
        var raw = body == null ? "" : JsonSerializer.Serialize(body, Wire.Json);
        var wire = Encoding.UTF8.GetBytes(raw);
        if (encoding == "gzip")
            wire = Gzip(wire);
        var ts = Clock.Now.ToUnixTimeSeconds().ToString();
        nonce ??= Guid.NewGuid().ToString();
        var canonical =
            $"{method}\n{signedPath ?? path}\n{ts}\n{nonce}\n{Convert.ToHexString(SHA256.HashData(signedBody is null ? wire : Encoding.UTF8.GetBytes(signedBody)))}";
        var request = new HttpRequestMessage(new(method), path);
        if (body != null)
        {
            request.Content = new ByteArrayContent(wire);
            request.Content.Headers.ContentType = new("application/json") { CharSet = "utf-8" };
            if (encoding != null)
                request.Content.Headers.ContentEncoding.Add(encoding);
        }
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

    public static byte[] Gzip(byte[] plain)
    {
        using var output = new MemoryStream();
        using (var gzip = new System.IO.Compression.GZipStream(output, System.IO.Compression.CompressionLevel.Fastest))
            gzip.Write(plain);
        return output.ToArray();
    }
}

public sealed class WebhookStub : HttpMessageHandler
{
    public readonly List<(Uri Url, string Body)> Requests = [];
    public string Reply = """{"errcode":0,"errmsg":"ok"}""";

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        Requests.Add((request.RequestUri!, await request.Content!.ReadAsStringAsync(ct)));
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Reply) };
    }

    protected override void Dispose(bool disposing) { }
}
