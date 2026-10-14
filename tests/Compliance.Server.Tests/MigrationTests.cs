using System.Data.Common;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Compliance.Core;
using Microsoft.Data.Sqlite;
using Npgsql;
using Xunit;

namespace Compliance.Server.Tests;

public class MigrationTests
{
    static string? Postgres => Environment.GetEnvironmentVariable("COMPLIANCE_TEST_POSTGRES");
    static bool UsingPostgres => !string.IsNullOrWhiteSpace(Postgres);

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
        var directory = Path.Combine(Path.GetTempPath(), "compliance-legacy-" + Guid.NewGuid());
        Directory.CreateDirectory(directory);
        var clock = new ManualClock();

        // On Postgres the legacy tables go into a fresh schema; Fixture picks it up from the "pg-schema" marker.
        string? schema = null;
        if (UsingPostgres)
        {
            schema = "ct_" + Guid.NewGuid().ToString("N");
            await File.WriteAllTextAsync(Path.Combine(directory, "pg-schema"), schema);
            await Execute(Postgres!, "CREATE SCHEMA " + schema);
        }

        DbConnection Open() => schema == null
            ? new SqliteConnection("Data Source=" + Path.Combine(directory, "test.db"))
            : new NpgsqlConnection(new NpgsqlConnectionStringBuilder(Postgres) { SearchPath = schema }.ToString());

        try
        {
            using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            await File.WriteAllTextAsync(Path.Combine(directory, "policy.pem"), signer.ExportECPrivateKeyPem());
            var keyId = Secrets.Hash(signer.ExportSubjectPublicKeyInfoPem())[..16];
            var release = PolicyCrypto.Sign(PolicySeed.Create() with { Mode = "Audit", Version = 1, IssuedAt = clock.Now, ExpiresAt = clock.Now.AddDays(30) }, signer, keyId);

            using var deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var deviceId = Guid.NewGuid().ToString();
            var alert = new AlertSummary("offline:" + deviceId, deviceId, "legacy-host", "Offline", "heartbeat", "legacy alert", "Resolved", 0, clock.Now, clock.Now, true);

            await using (var connection = Open())
            {
                await connection.OpenAsync();
                // 0.1.0 used the same DDL for SQLite and Postgres.
                await using var create = connection.CreateCommand();
                create.CommandText =
                    "CREATE TABLE records(kind TEXT NOT NULL,id TEXT NOT NULL,json TEXT NOT NULL,PRIMARY KEY(kind,id));" +
                    "CREATE TABLE nonces(device TEXT NOT NULL,nonce TEXT NOT NULL,expires BIGINT NOT NULL,PRIMARY KEY(device,nonce));";
                await create.ExecuteNonQueryAsync();

                async Task Put(string kind, string id, object value)
                {
                    await using var insert = connection.CreateCommand();
                    insert.CommandText = "INSERT INTO records(kind,id,json) VALUES(@kind,@id,@json)";
                    foreach (var (name, text) in new[] { ("kind", kind), ("id", id), ("json", Wire.Serialize(value)) })
                    {
                        var parameter = insert.CreateParameter();
                        parameter.ParameterName = name;
                        parameter.Value = text;
                        insert.Parameters.Add(parameter);
                    }
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

            await using (var f = new Fixture(directory, clock))
            {
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
            }

            // A restart must not import the legacy rows a second time.
            await using (var restart = new Fixture(directory, clock))
            {
                await restart.Login();
                var audit = (await restart.Client.GetFromJsonAsync<AuditRecord[]>("/api/audit", Wire.Json))!;
                Assert.Single(audit, a => a.Action == "LegacyAction");
                Assert.Single((await restart.Client.GetFromJsonAsync<DeviceSummary[]>("/api/devices", Wire.Json))!);
            }

            await using var check = Open();
            await check.OpenAsync();
            await using var tables = check.CreateCommand();
            tables.CommandText = schema == null
                ? "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('records','records_legacy_v0')"
                : "SELECT table_name FROM information_schema.tables WHERE table_schema=current_schema() AND table_name IN ('records','records_legacy_v0')";
            var names = new List<string>();
            await using (var reader = await tables.ExecuteReaderAsync())
                while (await reader.ReadAsync()) names.Add(reader.GetString(0));
            Assert.Equal(["records_legacy_v0"], names);
        }
        finally
        {
            if (schema != null) await Execute(Postgres!, "DROP SCHEMA " + schema + " CASCADE");
        }
    }

    static async Task Execute(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
    }
}
