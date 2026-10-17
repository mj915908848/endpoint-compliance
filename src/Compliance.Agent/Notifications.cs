using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using Compliance.Core;
using Microsoft.Data.Sqlite;

namespace Compliance.Agent;

public sealed class NotificationStore : IAsyncDisposable
{
    private readonly SqliteConnection db;
    private readonly SemaphoreSlim gate = new(1, 1);

    public NotificationStore(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path }.ToString());
        db.Open();
        using var command = db.CreateCommand();
        command.CommandText =
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; "
            + "CREATE TABLE IF NOT EXISTS notices(id TEXT PRIMARY KEY,sid TEXT,message TEXT NOT NULL,at TEXT NOT NULL); "
            + "CREATE TABLE IF NOT EXISTS acknowledgments(id TEXT NOT NULL,sid TEXT NOT NULL,at TEXT NOT NULL,PRIMARY KEY(id,sid));";
        command.ExecuteNonQuery();
    }

    public async Task AddAsync(string eventId, string? userSid, string message, CancellationToken ct = default)
    {
        await gate.WaitAsync(ct);
        try
        {
            using var command = db.CreateCommand();
            command.CommandText = "INSERT OR IGNORE INTO notices(id,sid,message,at) VALUES($id,$sid,$message,$at)";
            command.Parameters.AddWithValue("$id", eventId);
            command.Parameters.AddWithValue("$sid", (object?)userSid ?? DBNull.Value);
            command.Parameters.AddWithValue("$message", EvidenceSanitizer.Clean(message));
            command.Parameters.AddWithValue("$at", DateTimeOffset.UtcNow.ToString("O"));
            await command.ExecuteNonQueryAsync(ct);
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task<TrayNotice[]> ListAsync(string userSid, CancellationToken ct = default)
    {
        await gate.WaitAsync(ct);
        try
        {
            using var command = db.CreateCommand();
            command.CommandText =
                "SELECT n.id,n.sid,n.message,n.at, EXISTS(SELECT 1 FROM acknowledgments a WHERE a.id=n.id AND a.sid=$sid) FROM "
                + "notices n WHERE n.sid IS NULL OR n.sid=$sid ORDER BY n.at DESC LIMIT 50";
            command.Parameters.AddWithValue("$sid", userSid);
            using var reader = await command.ExecuteReaderAsync(ct);
            var records = new List<TrayNotice>();
            while (await reader.ReadAsync(ct))
                records.Add(
                    new(
                        reader.GetString(0),
                        reader.IsDBNull(1) ? null : reader.GetString(1),
                        reader.GetString(2),
                        DateTimeOffset.Parse(reader.GetString(3)),
                        reader.GetInt64(4) != 0
                    )
                );
            return records.ToArray();
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task<bool> AckAsync(string userSid, string eventId, CancellationToken ct = default)
    {
        await gate.WaitAsync(ct);
        try
        {
            using var check = db.CreateCommand();
            check.CommandText = "SELECT COUNT(*) FROM notices WHERE id=$id AND (sid IS NULL OR sid=$sid)";
            check.Parameters.AddWithValue("$id", eventId);
            check.Parameters.AddWithValue("$sid", userSid);
            if (Convert.ToInt64(await check.ExecuteScalarAsync(ct)) == 0)
                return false;
            using var insert = db.CreateCommand();
            insert.CommandText = "INSERT OR IGNORE INTO acknowledgments(id,sid,at) VALUES($id,$sid,$at)";
            insert.Parameters.AddWithValue("$id", eventId);
            insert.Parameters.AddWithValue("$sid", userSid);
            insert.Parameters.AddWithValue("$at", DateTimeOffset.UtcNow.ToString("O"));
            await insert.ExecuteNonQueryAsync(ct);
            return true;
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await db.DisposeAsync();
        gate.Dispose();
    }
}

/// <summary>
/// The service's end of <see cref="TrayPipe"/>. Without a store the service is waiting to be enrolled, and every
/// request is answered with <see cref="TrayPipe.NotEnrolled"/>.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed class NotificationPipe(NotificationStore? store)
{
    public async Task RunAsync(CancellationToken ct)
    {
        var security = new PipeSecurity();
        security.AddAccessRule(
            new PipeAccessRule(
                new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
                PipeAccessRights.ReadWrite,
                AccessControlType.Allow
            )
        );
        security.AddAccessRule(
            new PipeAccessRule(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                PipeAccessRights.FullControl,
                AccessControlType.Allow
            )
        );
        // The account running the pipe (SYSTEM for the service) needs FullControl to create further instances.
        security.AddAccessRule(
            new PipeAccessRule(
                WindowsIdentity.GetCurrent().User!,
                PipeAccessRights.FullControl,
                AccessControlType.Allow
            )
        );
        using var slots = new SemaphoreSlim(5, 5);
        var failed = false;
        while (!ct.IsCancellationRequested)
        {
            await slots.WaitAsync(ct);
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = NamedPipeServerStreamAcl.Create(
                    TrayPipe.Name,
                    PipeDirection.InOut,
                    5,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,
                    4096,
                    4096,
                    security
                );
                await pipe.WaitForConnectionAsync(ct);
                var connected = pipe;
                _ = Task.Run(
                    async () =>
                    {
                        try
                        {
                            await HandleAsync(connected, ct);
                        }
                        finally
                        {
                            connected.Dispose();
                            slots.Release();
                        }
                    },
                    CancellationToken.None
                );
                pipe = null;
            }
            catch (IOException ex)
            {
                // A client that disconnects before the accept completes breaks only this instance; keep listening.
                Console.Error.WriteLine($"托盘通知管道连接失败：{ex.Message}");
                failed = true;
            }
            finally
            {
                pipe?.Dispose();
                if (pipe is not null)
                    slots.Release();
            }
            if (failed)
            {
                failed = false;
                await Task.Delay(TimeSpan.FromSeconds(1), ct);
            }
        }
    }

    private async Task HandleAsync(NamedPipeServerStream pipe, CancellationToken stop)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stop);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        var ct = timeout.Token;
        try
        {
            using var reader = new StreamReader(pipe, leaveOpen: true);
            using var writer = new StreamWriter(pipe, leaveOpen: true) { AutoFlush = true };
            var line = await ReadLimitedLineAsync(reader, ct);
            if (line is null)
                return;
            string? sid = null;
            pipe.RunAsClient(() => sid = ClientSid());
            if (sid is null)
                return;
            var request = Wire.Read<TrayRequest>(line);
            object reply = store is null
                ? new TrayError(TrayPipe.NotEnrolled)
                : request switch
                {
                    { Action: TrayPipe.List } => await store.ListAsync(sid, ct),
                    { Action: TrayPipe.Ack, EventId: { Length: > 0 } eventId } => new TrayAck(
                        await store.AckAsync(sid, eventId, ct)
                    ),
                    _ => new TrayError("Unsupported notification request"),
                };
            await writer.WriteLineAsync(Wire.Serialize(reply));
        }
        catch (Exception ex) when (ex is OperationCanceledException && stop.IsCancellationRequested) { }
        catch (Exception ex)
        {
            // Never let a bad request fault the handler silently: the tray would only see a dropped connection.
            Console.Error.WriteLine($"托盘通知请求失败：{ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>
    /// The connected user's SID. The tray connects at Identification level, so the thread token must be opened
    /// with the service's own rights (OpenAsSelf); WindowsIdentity.GetCurrent() opens it as the client and fails
    /// with "bad impersonation level".
    /// </summary>
    private static string? ClientSid()
    {
        const uint TokenQuery = 0x0008;
        if (!OpenThreadToken(GetCurrentThread(), TokenQuery, true, out var token))
            throw new System.ComponentModel.Win32Exception();
        using (token)
        using (var identity = new WindowsIdentity(token.DangerousGetHandle()))
            return identity.User?.Value;
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentThread();

    [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenThreadToken(
        IntPtr thread,
        uint access,
        bool openAsSelf,
        out Microsoft.Win32.SafeHandles.SafeAccessTokenHandle token
    );

    private static async Task<string?> ReadLimitedLineAsync(StreamReader reader, CancellationToken ct)
    {
        var chars = new char[1];
        var result = new System.Text.StringBuilder();
        while (result.Length <= 4096)
        {
            if (await reader.ReadAsync(chars.AsMemory(), ct) == 0)
                return null;
            if (chars[0] == '\n')
                return result.ToString().TrimEnd('\r');
            result.Append(chars[0]);
        }
        return null;
    }
}
