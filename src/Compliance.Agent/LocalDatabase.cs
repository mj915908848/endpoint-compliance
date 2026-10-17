using Microsoft.Data.Sqlite;

namespace Compliance.Agent;

/// <summary>
/// Opens the agent's own SQLite stores. A file that is damaged (a failing disk, an antivirus quarantining its journal)
/// is set aside as <c>.corrupt-&lt;time&gt;</c> and started afresh, so the service keeps checking and ending programs
/// instead of failing at every start.
/// </summary>
public static class LocalDatabase
{
    // SQLITE_CORRUPT and SQLITE_NOTADB.
    static bool Damaged(SqliteException e) => e.SqliteErrorCode is 11 or 26;

    public static T Open<T>(string path, Func<string, T> open, Action<string>? rebuilt = null)
    {
        try
        {
            return open(path);
        }
        catch (SqliteException e) when (Damaged(e))
        {
            SqliteConnection.ClearAllPools();
            var stamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
            foreach (var suffix in new[] { "", "-wal", "-shm" })
                if (File.Exists(path + suffix))
                    File.Move(path + suffix, $"{path}.corrupt-{stamp}{suffix}", true);
            var message =
                $"本机数据库 {Path.GetFileName(path)} 已损坏（{e.Message}），已另存为 .corrupt-{stamp} 并重新创建；其中尚未上报的记录已丢失";
            Console.Error.WriteLine(message);
            rebuilt?.Invoke(message);
            return open(path);
        }
    }
}
