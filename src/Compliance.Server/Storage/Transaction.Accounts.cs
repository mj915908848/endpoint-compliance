using System.Data.Common;
using System.Globalization;
using Compliance.Core;

namespace Compliance.Server;

public sealed partial class Transaction
{
    // ---- users and sessions --------------------------------------------------------------

    public Task<UserRecord?> GetUser(string username) =>
        Single(
            "SELECT username, password_hash, roles FROM users WHERE username = @username",
            r => new UserRecord(r.GetString(0), r.GetString(1), Wire.Read<string[]>(r.GetString(2))),
            ("username", username)
        );

    public Task InsertUser(UserRecord user) =>
        Execute(
            "INSERT INTO users(username, password_hash, roles) VALUES(@username, @hash, @roles)",
            ("username", user.Username),
            ("hash", user.PasswordHash),
            ("roles", Wire.Serialize(user.Roles))
        );

    public Task<SessionRecord?> GetSession(string tokenHash) =>
        Single(
            "SELECT username, csrf_token, expires_at, last_active FROM sessions WHERE token_hash = @hash",
            r => new SessionRecord(r.GetString(0), r.GetString(1), Time(r, 2), Time(r, 3)),
            ("hash", tokenHash)
        );

    public Task InsertSession(string tokenHash, SessionRecord session) =>
        Execute(
            "INSERT INTO sessions(token_hash, username, csrf_token, expires_at, last_active) VALUES(@hash, @username, @csrf, @expires, @active)",
            ("hash", tokenHash),
            ("username", session.Username),
            ("csrf", session.CsrfToken),
            ("expires", session.ExpiresAt),
            ("active", session.LastActive)
        );

    public Task InsertLegacySession(string tokenHash, SessionRecord session) =>
        Execute(
            "INSERT INTO sessions(token_hash, username, csrf_token, expires_at) VALUES(@hash, @username, @csrf, @expires)",
            ("hash", tokenHash),
            ("username", session.Username),
            ("csrf", session.CsrfToken),
            ("expires", session.ExpiresAt)
        );

    public Task TouchSession(string tokenHash, DateTimeOffset lastActive) =>
        Execute(
            "UPDATE sessions SET last_active = @active WHERE token_hash = @hash AND last_active < @active",
            ("hash", tokenHash),
            ("active", lastActive)
        );

    public Task DeleteSession(string tokenHash) =>
        Execute("DELETE FROM sessions WHERE token_hash = @hash", ("hash", tokenHash));

    /// <summary>Signs the user out everywhere except the session <paramref name="keepTokenHash"/>.</summary>
    public Task<int> DeleteOtherSessions(string username, string keepTokenHash) =>
        Execute(
            "DELETE FROM sessions WHERE username = @username AND token_hash <> @keep",
            ("username", username),
            ("keep", keepTokenHash)
        );

    public Task SetPassword(string username, string passwordHash) =>
        Execute(
            "UPDATE users SET password_hash = @hash WHERE username = @username",
            ("hash", passwordHash),
            ("username", username)
        );

    // ---- settings ------------------------------------------------------------------------

    public Task<string?> GetSetting(string key) =>
        Single("SELECT value FROM settings WHERE key = @key", r => r.GetString(0), ("key", key));

    public Task PutSetting(string key, string value) =>
        Execute(
            "INSERT INTO settings(key, value) VALUES(@key, @value) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            ("key", key),
            ("value", value)
        );

    // ---- enrollment codes ----------------------------------------------------------------

    const string CodeColumns = "id, label, expires_at, max_uses, used, created_at, created_by, revoked, group_name";

    static EnrollmentCode ReadCode(DbDataReader r) =>
        new(
            r.GetString(0),
            r.GetString(1),
            Time(r, 2),
            (int)Long(r, 3),
            (int)Long(r, 4),
            Time(r, 5),
            r.GetString(6),
            Long(r, 7) != 0,
            r.GetString(8)
        );

    public Task<EnrollmentCode?> GetCode(string codeHash) =>
        Single($"SELECT {CodeColumns} FROM enrollment_codes WHERE code_hash = @hash", ReadCode, ("hash", codeHash));

    /// <summary>Codes created since multi-use codes exist, newest first.</summary>
    public Task<List<EnrollmentCode>> RecentCodes(int limit) =>
        Query(
            $"SELECT {CodeColumns} FROM enrollment_codes WHERE id <> '' ORDER BY created_at DESC LIMIT {limit}",
            ReadCode
        );

    public Task InsertCode(string codeHash, EnrollmentCode code) =>
        Execute(
            $"INSERT INTO enrollment_codes(code_hash, {CodeColumns}) VALUES(@hash, @id, @label, @expires, @max, 0, @created, @by, 0, @group)",
            ("hash", codeHash),
            ("id", code.Id),
            ("label", code.Label),
            ("expires", code.ExpiresAt),
            ("max", code.MaxUses),
            ("created", code.CreatedAt),
            ("by", code.CreatedBy),
            ("group", code.Group)
        );

    /// <summary>Migration 2 imports 0.1.0 codes before migration 5 adds the other columns.</summary>
    public Task InsertLegacyCode(string codeHash, CodeRecord code) =>
        Execute(
            "INSERT INTO enrollment_codes(code_hash, expires_at, used) VALUES(@hash, @expires, @used)",
            ("hash", codeHash),
            ("expires", code.ExpiresAt),
            ("used", code.Used)
        );

    public Task CountCodeUse(string codeHash) =>
        Execute("UPDATE enrollment_codes SET used = used + 1 WHERE code_hash = @hash", ("hash", codeHash));

    public Task<int> RevokeCode(string id) =>
        Execute("UPDATE enrollment_codes SET revoked = 1 WHERE id = @id AND id <> ''", ("id", id));
}
