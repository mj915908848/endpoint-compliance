using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using Compliance.Core;
using Microsoft.Data.Sqlite;
using Npgsql;
namespace Compliance.Server;

public sealed class Settings
{
    public bool DemoMode {get;set;}
    public string Storage {get;set;}="Postgres";
    public string Database {get;set;}="";
    public string SigningKeyPath {get;set;}="";
    public string BootstrapUsers {get;set;}="[]";
    public string[] TrustedProxies {get;set;}=[];
}
public sealed record UserRecord(string Username,string PasswordHash,string[] Roles);
public sealed record BootstrapUser(string Username,string Password,string[] Roles);
public sealed record SessionRecord(string Username,string CsrfToken,DateTimeOffset ExpiresAt);
public sealed record CodeRecord(DateTimeOffset ExpiresAt,bool Used);
public sealed record DeviceRecord(string Id,string HostName,string PublicKeyPem,DateTimeOffset? LastHeartbeat=null,long AppliedPolicyVersion=0,ControlState[]? Controls=null,ScanSnapshot? Snapshot=null,long SnapshotSequence=0,long TargetPolicyVersion=1);
public sealed record SnapshotIncident(string Id,string DeviceId,string Scope,string[] Modules);
public sealed record StoredEvent(string Fingerprint,AgentEvent Event,DateTimeOffset ReceivedAt);
public sealed record DraftRecord(string Id,PolicyDocument Document,string CreatedBy,string? ApprovedBy,bool Published,bool ImpactReviewed);
public sealed record CommandRecord(string DeviceId,DeviceCommand Command,CommandReply? Reply=null);
public sealed record AuditRecord(string Id,string Actor,string Action,string Target,DateTimeOffset At);
public sealed class ApiError(int status,string message):Exception(message) {public int Status=>status;}
public static class Secrets
{
    public static string Token()=>Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
    public static string Hash(string value)=>Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    public static string Password(string value){var salt=RandomNumberGenerator.GetBytes(16);return Convert.ToBase64String(salt)+":"+Convert.ToBase64String(Rfc2898DeriveBytes.Pbkdf2(value,salt,210000,HashAlgorithmName.SHA256,32));}
    public static bool Check(string value,string stored){var p=stored.Split(':');return CryptographicOperations.FixedTimeEquals(Convert.FromBase64String(p[1]),Rfc2898DeriveBytes.Pbkdf2(value,Convert.FromBase64String(p[0]),210000,HashAlgorithmName.SHA256,32));}
}
public sealed class Store(Settings settings)
{
    readonly SemaphoreSlim gate=new(1);
    public async Task Initialize()
    {
        if(settings.Storage=="Sqlite" && !settings.DemoMode) throw new InvalidOperationException("SQLite requires explicit loopback demo mode");
        if(settings.Storage is not ("Sqlite" or "Postgres") || string.IsNullOrWhiteSpace(settings.Database)) throw new InvalidOperationException("Configure Compliance:Storage and Compliance:Database");
        if(settings.Storage=="Sqlite") Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(settings.Database))!);
        await using var c=Connection();await c.OpenAsync();await using var command=c.CreateCommand();command.CommandText="CREATE TABLE IF NOT EXISTS records(kind TEXT NOT NULL,id TEXT NOT NULL,json TEXT NOT NULL,PRIMARY KEY(kind,id))";await command.ExecuteNonQueryAsync();
        command.CommandText="CREATE TABLE IF NOT EXISTS nonces(device TEXT NOT NULL,nonce TEXT NOT NULL,expires BIGINT NOT NULL,PRIMARY KEY(device,nonce)); CREATE INDEX IF NOT EXISTS nonces_expiry ON nonces(expires)";await command.ExecuteNonQueryAsync();
    }
    DbConnection Connection()=>settings.Storage=="Sqlite" ? new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=settings.Database,Mode=SqliteOpenMode.ReadWriteCreate,DefaultTimeout=30}.ToString()):new NpgsqlConnection(settings.Database);
    public async Task<T> Transaction<T>(Func<Transaction,Task<T>> action)
    {
        await gate.WaitAsync();try{
            await using var c=Connection();await c.OpenAsync();await using var tx=await c.BeginTransactionAsync();
            if(settings.Storage=="Postgres"){await using var lockCommand=c.CreateCommand();lockCommand.Transaction=tx;lockCommand.CommandText="SELECT pg_advisory_xact_lock(819227143)";await lockCommand.ExecuteNonQueryAsync();}
            var result=await action(new(c,tx));await tx.CommitAsync();return result;
        }finally{gate.Release();}
    }
}
public sealed class Transaction(DbConnection connection,DbTransaction transaction)
{
    DbCommand Command(string sql,params (string,object)[] args){var c=connection.CreateCommand();c.Transaction=transaction;c.CommandText=sql;foreach(var (name,value) in args){var p=c.CreateParameter();p.ParameterName=name;p.Value=value;c.Parameters.Add(p);}return c;}
    public async Task<T?> Get<T>(string kind,string id){await using var c=Command("SELECT json FROM records WHERE kind=@kind AND id=@id",("kind",kind),("id",id));var v=await c.ExecuteScalarAsync();return v is string s?Wire.Read<T>(s):default;}
    public async Task<T[]> All<T>(string kind){await using var c=Command("SELECT json FROM records WHERE kind=@kind",("kind",kind));await using var reader=await c.ExecuteReaderAsync();var list=new List<T>();while(await reader.ReadAsync())list.Add(Wire.Read<T>(reader.GetString(0)));return list.ToArray();}
    public async Task Put<T>(string kind,string id,T value){await using var c=Command("INSERT INTO records(kind,id,json) VALUES(@kind,@id,@json) ON CONFLICT(kind,id) DO UPDATE SET json=excluded.json",("kind",kind),("id",id),("json",Wire.Serialize(value)));await c.ExecuteNonQueryAsync();}
    public async Task Delete(string kind,string id){await using var c=Command("DELETE FROM records WHERE kind=@kind AND id=@id",("kind",kind),("id",id));await c.ExecuteNonQueryAsync();}
    public async Task<bool> AcceptNonce(string device,string nonce,DateTimeOffset now)
    {
        await using(var cleanup=Command("DELETE FROM nonces WHERE expires<@now",("now",now.ToUnixTimeSeconds())))await cleanup.ExecuteNonQueryAsync();
        await using var insert=Command("INSERT INTO nonces(device,nonce,expires) VALUES(@device,@nonce,@expires) ON CONFLICT(device,nonce) DO NOTHING",("device",device),("nonce",nonce),("expires",now.AddMinutes(10).ToUnixTimeSeconds()));return await insert.ExecuteNonQueryAsync()==1;
    }
    public Task Audit(string actor,string action,string target,DateTimeOffset now){var id=Guid.NewGuid().ToString();return Put("audit",id,new AuditRecord(id,actor,action,target,now));}
}
