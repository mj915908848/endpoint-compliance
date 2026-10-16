using Compliance.Core;

namespace Compliance.Server;

/// <summary>
/// Ordered, append-only schema migrations. Applied versions are recorded in <c>schema_migrations</c>;
/// startup applies whatever is missing inside one transaction. Never edit a released migration —
/// add a new one. The SQL is restricted to what both PostgreSQL and SQLite accept.
/// </summary>
public static class Migrations
{
    sealed record Migration(long Version, string Name, Func<Transaction, Task> Apply);

    static readonly Migration[] All =
    [
        new(1, "relational schema", CreateSchema),
        new(2, "import legacy records table", ImportLegacyRecords),
        new(3, "device notes", tx => tx.Execute("ALTER TABLE devices ADD COLUMN note TEXT NOT NULL DEFAULT ''")),
        new(4, "multiple policies", MultiplePolicies),
        new(5, "multi-use enrollment codes", MultiUseCodes),
        new(
            6,
            "client versions",
            tx => tx.Execute("ALTER TABLE devices ADD COLUMN agent_version TEXT NOT NULL DEFAULT ''")
        ),
        new(7, "settings and alert notifications", SettingsAndNotifications),
        new(8, "device network addresses", DeviceNetwork),
    ];

    public static async Task<bool> Apply(Transaction tx)
    {
        await tx.Lock("schema-migrations");
        await tx.Execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations(version BIGINT PRIMARY KEY, name TEXT NOT NULL, applied_at BIGINT NOT NULL)"
        );
        foreach (var migration in All)
        {
            var applied = await tx.Execute(
                "INSERT INTO schema_migrations(version, name, applied_at) VALUES(@version, @name, @at) ON CONFLICT(version) DO NOTHING",
                ("version", migration.Version),
                ("name", migration.Name),
                ("at", DateTimeOffset.UtcNow)
            );
            if (applied == 1)
                await migration.Apply(tx);
        }
        return true;
    }

    static readonly string[] Schema =
    [
        "CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, roles TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, csrf_token TEXT NOT NULL, expires_at BIGINT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS sessions_expires ON sessions(expires_at)",
        "CREATE TABLE IF NOT EXISTS enrollment_codes(code_hash TEXT PRIMARY KEY, expires_at BIGINT NOT NULL, used BIGINT NOT NULL)",
        """
            CREATE TABLE IF NOT EXISTS devices(
                id TEXT PRIMARY KEY,
                host_name TEXT NOT NULL,
                public_key_pem TEXT NOT NULL UNIQUE,
                last_heartbeat BIGINT NULL,
                applied_policy_version BIGINT NOT NULL,
                controls TEXT NULL,
                snapshot TEXT NULL,
                snapshot_sequence BIGINT NOT NULL,
                target_policy_version BIGINT NOT NULL)
            """,
        "CREATE INDEX IF NOT EXISTS devices_last_heartbeat ON devices(last_heartbeat)",
        """
            CREATE TABLE IF NOT EXISTS events(
                device_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                sequence BIGINT NOT NULL,
                type TEXT NOT NULL,
                object_key TEXT NOT NULL,
                source_time BIGINT NOT NULL,
                received_at BIGINT NOT NULL,
                fingerprint TEXT NOT NULL,
                body TEXT NOT NULL,
                PRIMARY KEY(device_id, event_id),
                UNIQUE(device_id, sequence))
            """,
        "CREATE INDEX IF NOT EXISTS events_received ON events(received_at)",
        """
            CREATE TABLE IF NOT EXISTS alerts(
                id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                host_name TEXT NOT NULL,
                type TEXT NOT NULL,
                object_key TEXT NOT NULL,
                summary TEXT NOT NULL,
                state TEXT NOT NULL,
                last_sequence BIGINT NOT NULL,
                first_seen BIGINT NOT NULL,
                last_seen BIGINT NOT NULL,
                acknowledged BIGINT NOT NULL)
            """,
        "CREATE INDEX IF NOT EXISTS alerts_device ON alerts(device_id)",
        "CREATE INDEX IF NOT EXISTS alerts_last_seen ON alerts(last_seen)",
        "CREATE TABLE IF NOT EXISTS snapshot_incidents(id TEXT PRIMARY KEY, device_id TEXT NOT NULL, scope TEXT NOT NULL, modules TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS snapshot_incidents_device ON snapshot_incidents(device_id)",
        "CREATE TABLE IF NOT EXISTS policy_releases(version BIGINT PRIMARY KEY, payload TEXT NOT NULL, signature TEXT NOT NULL, key_id TEXT NOT NULL, published_at BIGINT NOT NULL)",
        """
            CREATE TABLE IF NOT EXISTS policy_drafts(
                id TEXT PRIMARY KEY,
                document TEXT NOT NULL,
                created_by TEXT NOT NULL,
                approved_by TEXT NULL,
                published BIGINT NOT NULL,
                impact_reviewed BIGINT NOT NULL,
                created_at BIGINT NOT NULL)
            """,
        "CREATE TABLE IF NOT EXISTS commands(id TEXT PRIMARY KEY, device_id TEXT NOT NULL, type TEXT NOT NULL, expires_at BIGINT NOT NULL, reply TEXT NULL)",
        "CREATE INDEX IF NOT EXISTS commands_device ON commands(device_id, expires_at)",
        "CREATE TABLE IF NOT EXISTS audit(id TEXT PRIMARY KEY, at BIGINT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS audit_at ON audit(at)",
        // Same shape as the 0.1.0 table, so existing databases keep it as is.
        "CREATE TABLE IF NOT EXISTS nonces(device TEXT NOT NULL, nonce TEXT NOT NULL, expires BIGINT NOT NULL, PRIMARY KEY(device, nonce))",
        "CREATE INDEX IF NOT EXISTS nonces_expiry ON nonces(expires)",
    ];

    /// <summary>Every release so far belongs to the default policy; named policies add rows to <c>policies</c>.</summary>
    /// <summary>
    /// "used" becomes a count of devices enrolled with the code; existing single-use codes keep max_uses 1. Codes
    /// created before this have no id and are not listed.
    /// </summary>
    static async Task MultiUseCodes(Transaction tx)
    {
        foreach (
            var column in new[]
            {
                "id TEXT NOT NULL DEFAULT ''",
                "label TEXT NOT NULL DEFAULT ''",
                "max_uses BIGINT NOT NULL DEFAULT 1",
                "created_at BIGINT NOT NULL DEFAULT 0",
                "created_by TEXT NOT NULL DEFAULT ''",
                "revoked BIGINT NOT NULL DEFAULT 0",
            }
        )
            await tx.Execute("ALTER TABLE enrollment_codes ADD COLUMN " + column);
    }

    /// <summary>
    /// Settings changed in the management UI, and which alerts were pushed. Alerts that exist already count as
    /// notified, so turning notifications on does not send the whole backlog.
    /// </summary>
    static async Task DeviceNetwork(Transaction tx)
    {
        await tx.Execute("ALTER TABLE devices ADD COLUMN network TEXT NOT NULL DEFAULT ''");
        await tx.Execute("ALTER TABLE devices ADD COLUMN source_address TEXT NOT NULL DEFAULT ''");
    }

    static async Task SettingsAndNotifications(Transaction tx)
    {
        await tx.Execute("CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL)");
        await tx.Execute("ALTER TABLE alerts ADD COLUMN notified BIGINT NOT NULL DEFAULT 1");
        await tx.Execute("CREATE INDEX IF NOT EXISTS alerts_pending ON alerts(notified, state)");
    }

    static async Task MultiplePolicies(Transaction tx)
    {
        await tx.Execute("ALTER TABLE policy_releases ADD COLUMN policy_key TEXT NOT NULL DEFAULT 'default'");
        await tx.Execute(
            "CREATE TABLE IF NOT EXISTS policies(key TEXT PRIMARY KEY, created_at BIGINT NOT NULL, deleted_at BIGINT NULL)"
        );
        await tx.InsertPolicy(ComplianceService.DefaultPolicy, DateTimeOffset.UtcNow);
    }

    static async Task CreateSchema(Transaction tx)
    {
        foreach (var statement in Schema)
            await tx.Execute(statement);
    }

    /// <summary>
    /// 0.1.0 kept everything in <c>records(kind, id, json)</c>. Copy it into the typed tables once,
    /// then keep the original as <c>records_legacy_v0</c> for inspection or rollback.
    /// </summary>
    static async Task ImportLegacyRecords(Transaction tx)
    {
        if (!await tx.TableExists("records"))
            return;

        foreach (var (kind, id, json) in await tx.LegacyRecords())
        {
            switch (kind)
            {
                case "user":
                    await tx.InsertUser(Wire.Read<UserRecord>(json));
                    break;
                case "session":
                    await tx.InsertSession(id, Wire.Read<SessionRecord>(json));
                    break;
                case "code":
                    await tx.InsertLegacyCode(id, Wire.Read<CodeRecord>(json));
                    break;
                case "device":
                    await tx.InsertDevice(Wire.Read<DeviceRecord>(json));
                    break;
                case "event":
                    // id = "<deviceId>:<eventId>"; device ids are GUIDs, event ids may contain ':'.
                    await tx.InsertEvent(id[..id.IndexOf(':')], Wire.Read<StoredEvent>(json));
                    break;
                case "alert":
                    await tx.InsertLegacyAlert(Wire.Read<AlertSummary>(json));
                    break;
                case "snapshot-incident":
                    await tx.PutSnapshotIncident(Wire.Read<SnapshotIncident>(json));
                    break;
                case "release":
                    var signed = Wire.Read<SignedPolicy>(json);
                    await tx.InsertRelease(long.Parse(id), signed, Wire.Read<PolicyDocument>(signed.Payload).IssuedAt);
                    break;
                case "draft":
                    await tx.InsertDraft(Wire.Read<DraftRecord>(json), DateTimeOffset.UnixEpoch);
                    break;
                case "command":
                    await tx.InsertCommand(Wire.Read<CommandRecord>(json));
                    break;
                case "audit":
                    await tx.InsertAudit(Wire.Read<AuditRecord>(json));
                    break;
                case "policy": // "current" is now derived from the newest release
                case "sequence": // now a UNIQUE(device_id, sequence) constraint on events
                    break;
                default:
                    throw new InvalidOperationException(
                        $"Unknown legacy record kind '{kind}'; refusing a partial import"
                    );
            }
        }

        await tx.Execute("ALTER TABLE records RENAME TO records_legacy_v0");
    }
}
