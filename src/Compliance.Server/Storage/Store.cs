using System.Data.Common;
using Microsoft.Data.Sqlite;
using Npgsql;

namespace Compliance.Server;

/// <summary>
/// Opens connections and runs units of work. PostgreSQL transactions run concurrently and take
/// fine-grained advisory locks through <see cref="Transaction.Lock"/> (per device, policy, enrollment, ...).
/// SQLite is the loopback demo store and stays serialized to one writer per process.
/// </summary>
public sealed class Store(Settings settings)
{
    readonly SemaphoreSlim sqliteGate = new(1);

    bool IsSqlite => settings.Storage == "Sqlite";

    public async Task Initialize()
    {
        if (IsSqlite && !settings.DemoMode)
            throw new InvalidOperationException("SQLite requires explicit loopback demo mode");
        if (settings.Storage is not ("Sqlite" or "Postgres") || string.IsNullOrWhiteSpace(settings.Database))
            throw new InvalidOperationException("Configure Compliance:Storage and Compliance:Database");
        if (IsSqlite)
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(settings.Database))!);

        await Transaction(tx => Migrations.Apply(tx));
    }

    DbConnection Connection() => IsSqlite
        ? new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = settings.Database,
            Mode = SqliteOpenMode.ReadWriteCreate,
            DefaultTimeout = 30,
        }.ToString())
        : new NpgsqlConnection(settings.Database);

    public async Task<T> Transaction<T>(Func<Transaction, Task<T>> action)
    {
        if (IsSqlite) await sqliteGate.WaitAsync();
        try
        {
            await using var connection = Connection();
            await connection.OpenAsync();
            await using var transaction = await connection.BeginTransactionAsync();
            var result = await action(new Transaction(connection, transaction, IsSqlite));
            await transaction.CommitAsync();
            return result;
        }
        finally
        {
            if (IsSqlite) sqliteGate.Release();
        }
    }
}
