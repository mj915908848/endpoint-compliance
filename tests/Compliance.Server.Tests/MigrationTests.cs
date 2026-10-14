using System.Net.Http.Json;
using System.Security.Cryptography;
using Compliance.Core;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Compliance.Server.Tests;

public class MigrationTests
{
    static bool UsingPostgres => !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("COMPLIANCE_TEST_POSTGRES"));

    [Fact]
    public async Task Restart_does_not_reapply_migrations_or_duplicate_seed_data()
    {
        await using var f = new Fixture();
        await f.Login();
        var policy = await f.Client.GetFromJsonAsync<SignedPolicy>("/api/policies/current", Wire.Json);

        await using var restart = new Fixture(f.Directory, f.Clock);
        await restart.Login();
        Assert.Equal(policy, await restart.Client.GetFromJsonAsync<SignedPolicy>("/api/policies/current", Wire.Json));
        var audit = (await restart.Client.GetFromJsonAsync<AuditRecord[]>("/api/audit", Wire.Json))!;
        Assert.Single(audit, a => a.Action == "SeedAuditPolicy");
    }

    [Fact]
    public async Task Legacy_records_table_is_imported_once_and_kept_for_rollback()
    {
        if (UsingPostgres) return; // the legacy fixture below is written with SQLite

        var directory = Path.Combine(Path.GetTempPath(), "compliance-legacy-" + Guid.NewGuid());
        Directory.CreateDirectory(directory);
        var clock = new ManualClock();

        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await File.WriteAllTextAsync(Path.Combine(directory, "policy.pem"), signer.ExportECPrivateKeyPem());
        var keyId = Secrets.Hash(signer.ExportSubjectPublicKeyInfoPem())[..16];
        var release = PolicyCrypto.Sign(PolicySeed.Create() with { Mode = "Audit", Version = 1, IssuedAt = clock.Now, ExpiresAt = clock.Now.AddDays(30) }, signer, keyId);

        using var deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var deviceId = Guid.NewGuid().ToString();
        var alert = new AlertSummary("offline:" + deviceId, deviceId, "legacy-host", "Offline", "heartbeat", "legacy alert", "Resolved", 0, clock.Now, clock.Now, true);

        await using (var connection = new SqliteConnection("Data Source=" + Path.Combine(directory, "test.db")))
        {
            await connection.OpenAsync();
            await using var create = connection.CreateCommand();
            create.CommandText =
                "CREATE TABLE records(kind TEXT NOT NULL,id TEXT NOT NULL,json TEXT NOT NULL,PRIMARY KEY(kind,id));" +
                "CREATE TABLE nonces(device TEXT NOT NULL,nonce TEXT NOT NULL,expires BIGINT NOT NULL,PRIMARY KEY(device,nonce));";
            await create.ExecuteNonQueryAsync();

            async Task Put(string kind, string id, object value)
            {
                await using var insert = connection.CreateCommand();
                insert.CommandText = "INSERT INTO records(kind,id,json) VALUES($kind,$id,$json)";
                insert.Parameters.AddWithValue("$kind", kind);
                insert.Parameters.AddWithValue("$id", id);
                insert.Parameters.AddWithValue("$json", Wire.Serialize(value));
                await insert.ExecuteNonQueryAsync();
            }

            await Put("user", "admin", new UserRecord("admin", Secrets.Password("test-admin-password-long"), ["Reader", "Operator", "Publisher", "Reviewer"]));
            await Put("policy", "current", release);
            await Put("release", "1", release);
            await Put("device", deviceId, new DeviceRecord(deviceId, "legacy-host", deviceKey.ExportSubjectPublicKeyInfoPem(), LastHeartbeat: clock.Now, TargetPolicyVersion: 1));
            await Put("alert", alert.Id, alert);
            await Put("sequence", deviceId + ":1", "event-1");
            await Put("audit", "a1", new AuditRecord("a1", "legacy", "LegacyAction", "x", clock.Now.AddMinutes(-1)));
        }

        await using var f = new Fixture(directory, clock);
        await f.Login();

        var device = Assert.Single((await f.Client.GetFromJsonAsync<DeviceSummary[]>("/api/devices", Wire.Json))!);
        Assert.Equal("legacy-host", device.HostName);
        Assert.Equal("Online", device.OnlineState);
        var importedAlert = Assert.Single((await f.Client.GetFromJsonAsync<AlertSummary[]>("/api/alerts", Wire.Json))!);
        Assert.Equal(alert, importedAlert);
        Assert.Equal(release, await f.Client.GetFromJsonAsync<SignedPolicy>("/api/policies/current", Wire.Json));
        var audit = (await f.Client.GetFromJsonAsync<AuditRecord[]>("/api/audit", Wire.Json))!;
        Assert.Contains(audit, a => a.Action == "LegacyAction");
        Assert.DoesNotContain(audit, a => a.Action == "SeedAuditPolicy");

        await using var check = new SqliteConnection("Data Source=" + Path.Combine(directory, "test.db"));
        await check.OpenAsync();
        await using var tables = check.CreateCommand();
        tables.CommandText = "SELECT group_concat(name) FROM sqlite_master WHERE type='table' AND name IN ('records','records_legacy_v0')";
        Assert.Equal("records_legacy_v0", (string?)await tables.ExecuteScalarAsync());
    }
}
