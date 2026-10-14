using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Compliance.Agent;

public record LocalNotice(string EventId,string? UserSid,string Message,DateTimeOffset At,bool Acknowledged);

public sealed class NotificationStore : IAsyncDisposable
{
    private readonly SqliteConnection db;
    private readonly SemaphoreSlim gate=new(1,1);
    public NotificationStore(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        db=new SqliteConnection(new SqliteConnectionStringBuilder { DataSource=path }.ToString()); db.Open();
        using var command=db.CreateCommand();
        command.CommandText="PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS notices(id TEXT PRIMARY KEY,sid TEXT,message TEXT NOT NULL,at TEXT NOT NULL); CREATE TABLE IF NOT EXISTS acknowledgments(id TEXT NOT NULL,sid TEXT NOT NULL,at TEXT NOT NULL,PRIMARY KEY(id,sid));";
        command.ExecuteNonQuery();
    }
    public async Task AddAsync(string eventId,string? userSid,string message,CancellationToken ct=default)
    {
        await gate.WaitAsync(ct);
        try
        {
            using var command=db.CreateCommand(); command.CommandText="INSERT OR IGNORE INTO notices(id,sid,message,at) VALUES($id,$sid,$message,$at)";
            command.Parameters.AddWithValue("$id",eventId); command.Parameters.AddWithValue("$sid",(object?)userSid??DBNull.Value);
            command.Parameters.AddWithValue("$message",Compliance.Core.EvidenceSanitizer.Clean(message)); command.Parameters.AddWithValue("$at",DateTimeOffset.UtcNow.ToString("O"));
            await command.ExecuteNonQueryAsync(ct);
        }
        finally { gate.Release(); }
    }
    public async Task<LocalNotice[]> ListAsync(string userSid,CancellationToken ct=default)
    {
        await gate.WaitAsync(ct);
        try
        {
            using var command=db.CreateCommand(); command.CommandText="SELECT n.id,n.sid,n.message,n.at, EXISTS(SELECT 1 FROM acknowledgments a WHERE a.id=n.id AND a.sid=$sid) FROM notices n WHERE n.sid IS NULL OR n.sid=$sid ORDER BY n.at DESC LIMIT 50";
            command.Parameters.AddWithValue("$sid",userSid); using var reader=await command.ExecuteReaderAsync(ct); var records=new List<LocalNotice>();
            while(await reader.ReadAsync(ct)) records.Add(new(reader.GetString(0),reader.IsDBNull(1)?null:reader.GetString(1),reader.GetString(2),DateTimeOffset.Parse(reader.GetString(3)),reader.GetInt64(4)!=0));
            return records.ToArray();
        }
        finally { gate.Release(); }
    }
    public async Task<bool> AckAsync(string userSid,string eventId,CancellationToken ct=default)
    {
        await gate.WaitAsync(ct);
        try
        {
            using var check=db.CreateCommand(); check.CommandText="SELECT COUNT(*) FROM notices WHERE id=$id AND (sid IS NULL OR sid=$sid)";
            check.Parameters.AddWithValue("$id",eventId); check.Parameters.AddWithValue("$sid",userSid);
            if(Convert.ToInt64(await check.ExecuteScalarAsync(ct))==0) return false;
            using var insert=db.CreateCommand(); insert.CommandText="INSERT OR IGNORE INTO acknowledgments(id,sid,at) VALUES($id,$sid,$at)";
            insert.Parameters.AddWithValue("$id",eventId); insert.Parameters.AddWithValue("$sid",userSid); insert.Parameters.AddWithValue("$at",DateTimeOffset.UtcNow.ToString("O"));
            await insert.ExecuteNonQueryAsync(ct); return true;
        }
        finally { gate.Release(); }
    }
    public async ValueTask DisposeAsync() { await db.DisposeAsync(); gate.Dispose(); }
}

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed class NotificationPipe(NotificationStore store)
{
    public const string PipeName="ComplianceAgent.Notifications.v1";
    public async Task RunAsync(CancellationToken ct)
    {
        var security=new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid,null),PipeAccessRights.ReadWrite,AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),PipeAccessRights.FullControl,AccessControlType.Allow));
        using var slots=new SemaphoreSlim(5,5);
        while(!ct.IsCancellationRequested)
        {
            await slots.WaitAsync(ct);
            NamedPipeServerStream? pipe=null;
            try {
                pipe=NamedPipeServerStreamAcl.Create(PipeName,PipeDirection.InOut,5,PipeTransmissionMode.Byte,PipeOptions.Asynchronous,4096,4096,security);
                await pipe.WaitForConnectionAsync(ct);
                var connected=pipe;
                _=Task.Run(async ()=> { try { await HandleAsync(connected,ct); } finally { connected.Dispose(); slots.Release(); } },CancellationToken.None);
                pipe=null;
            }
            finally { pipe?.Dispose(); if(pipe is not null) slots.Release(); }
        }
    }
    private async Task HandleAsync(NamedPipeServerStream pipe,CancellationToken stop)
    {
            using var timeout=CancellationTokenSource.CreateLinkedTokenSource(stop);
            timeout.CancelAfter(TimeSpan.FromSeconds(5));
            var ct=timeout.Token;
            try {
                using var reader=new StreamReader(pipe,leaveOpen:true); using var writer=new StreamWriter(pipe,leaveOpen:true) { AutoFlush=true };
                var line=await ReadLimitedLineAsync(reader,ct);
                if(line is null) return;
                string? sid=null;
                pipe.RunAsClient(()=>sid=WindowsIdentity.GetCurrent().User?.Value);
                if(sid is null) return;
                using var doc=JsonDocument.Parse(line);
                var action=doc.RootElement.TryGetProperty("action",out var a)?a.GetString():null;
                object reply=action switch
                {
                    "list"=>await store.ListAsync(sid,ct),
                    "ack" when doc.RootElement.TryGetProperty("eventId",out var id) && id.GetString() is { Length:>0 } eventId =>new { ok=await store.AckAsync(sid,eventId,ct) },
                    _=>new { error="Unsupported notification request" }
                };
                await writer.WriteLineAsync(Compliance.Core.Wire.Serialize(reply));
            }
            catch(Exception ex) when(ex is IOException or JsonException or UnauthorizedAccessException or OperationCanceledException) { Console.Error.WriteLine("Notification IPC request rejected: "+ex.GetType().Name); }
    }
    private static async Task<string?> ReadLimitedLineAsync(StreamReader reader,CancellationToken ct)
    {
        var chars=new char[1]; var result=new System.Text.StringBuilder();
        while(result.Length<=4096)
        {
            if(await reader.ReadAsync(chars.AsMemory(),ct)==0) return null;
            if(chars[0]=='\n') return result.ToString().TrimEnd('\r');
            result.Append(chars[0]);
        }
        return null;
    }
}
