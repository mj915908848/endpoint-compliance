using System.Data.Common;
using System.Globalization;
using Compliance.Core;

namespace Compliance.Server;

/// <summary>
/// One unit of work against the relational schema (see <see cref="Migrations"/>).
/// Times are stored as UTC ticks (BIGINT) so ordering and range filters run in SQL.
/// Only free-form documents (snapshots, controls, policy payloads, event bodies) are JSON text.
/// Queries are grouped by table family in the Transaction.*.cs partial files.
/// </summary>
public sealed partial class Transaction
{
    readonly DbConnection connection;
    readonly DbTransaction transaction;

    internal Transaction(DbConnection connection, DbTransaction transaction, bool isSqlite)
    {
        this.connection = connection;
        this.transaction = transaction;
        IsSqlite = isSqlite;
    }

    internal bool IsSqlite { get; }

    // ---- locking -------------------------------------------------------------------------

    /// <summary>
    /// Serializes concurrent writers that share <paramref name="key"/> until commit or rollback.
    /// SQLite transactions are already serialized by <see cref="Store"/>.
    /// </summary>
    public async Task Lock(string key)
    {
        if (IsSqlite)
            return;
        await Execute("SELECT pg_advisory_xact_lock(hashtextextended(@key, 0))", ("key", key));
    }

    // ---- schema helpers (migrations) -----------------------------------------------------

    internal async Task<bool> TableExists(string name) =>
        await Count(
            IsSqlite
                ? "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = @name"
                : "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = @name",
            ("name", name)
        ) > 0;

    internal Task<List<(string Kind, string Id, string Json)>> LegacyRecords() =>
        Query("SELECT kind, id, json FROM records", r => (r.GetString(0), r.GetString(1), r.GetString(2)));

    // ---- plumbing ------------------------------------------------------------------------

    DbCommand Command(string sql, (string Name, object? Value)[] args)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach (var (name, value) in args)
        {
            var parameter = command.CreateParameter();
            parameter.ParameterName = name;
            parameter.Value = value switch
            {
                null => DBNull.Value,
                bool flag => flag ? 1L : 0L,
                DateTimeOffset time => time.UtcTicks,
                _ => value,
            };
            command.Parameters.Add(parameter);
        }
        return command;
    }

    internal async Task<int> Execute(string sql, params (string Name, object? Value)[] args)
    {
        await using var command = Command(sql, args);
        return await command.ExecuteNonQueryAsync();
    }

    async Task<long> Count(string sql, params (string Name, object? Value)[] args)
    {
        await using var command = Command(sql, args);
        return Convert.ToInt64(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Runs <paramref name="sql"/> once per few hundred <paramref name="values"/>, which replace "{in}" as a
    /// parameter list; parameter counts stay well inside both databases' limits.
    /// </summary>
    async Task<List<T>> QueryIn<T, TValue>(
        string sql,
        IEnumerable<TValue> values,
        Func<DbDataReader, T> map,
        params (string Name, object? Value)[] args
    )
    {
        var rows = new List<T>();
        foreach (var chunk in values.Chunk(500))
            rows.AddRange(
                await Query(
                    sql.Replace("{in}", string.Join(", ", chunk.Select((_, i) => "@in" + i))),
                    map,
                    [.. args, .. chunk.Select((value, i) => ("in" + i, (object?)value))]
                )
            );
        return rows;
    }

    async Task<List<T>> Query<T>(string sql, Func<DbDataReader, T> map, params (string Name, object? Value)[] args)
    {
        await using var command = Command(sql, args);
        await using var reader = await command.ExecuteReaderAsync();
        var rows = new List<T>();
        while (await reader.ReadAsync())
            rows.Add(map(reader));
        return rows;
    }

    async Task<T?> Single<T>(string sql, Func<DbDataReader, T> map, params (string Name, object? Value)[] args)
        where T : class
    {
        var rows = await Query(sql, map, args);
        return rows.Count == 0 ? null : rows[0];
    }

    static long Long(DbDataReader r, int i) => Convert.ToInt64(r.GetValue(i), CultureInfo.InvariantCulture);

    static DateTimeOffset Time(DbDataReader r, int i) => new(Long(r, i), TimeSpan.Zero);

    static DateTimeOffset? OptionalTime(DbDataReader r, int i) => r.IsDBNull(i) ? null : Time(r, i);
}
