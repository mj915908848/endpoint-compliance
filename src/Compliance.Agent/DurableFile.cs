namespace Compliance.Agent;

/// <summary>
/// Writes state the agent must find again after a power cut. Moving a temporary file over the old one is not enough on
/// its own: NTFS can commit the rename before the data, leaving an empty file. The data is flushed to disk first, and
/// the previous version is kept beside it as <c>.bak</c> for when the newest one still turns out unreadable.
/// </summary>
public static class DurableFile
{
    public static string BackupPath(string path) => path + ".bak";

    public static void Write(string path, string text)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var file = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var writer = new StreamWriter(file))
            {
                writer.Write(text);
                writer.Flush();
                file.Flush(true);
            }
            if (File.Exists(path))
                File.Replace(temp, path, BackupPath(path), ignoreMetadataErrors: true);
            else
                File.Move(temp, path);
        }
        finally
        {
            File.Delete(temp);
        }
    }

    /// <summary>
    /// Reads and parses the file, falling back to the previous version when the current one is missing, truncated or
    /// fails <paramref name="parse"/>. Throws what reading the current file threw when neither can be used.
    /// </summary>
    public static T Read<T>(string path, Func<string, T> parse)
    {
        try
        {
            return parse(File.ReadAllText(path));
        }
        catch (Exception first)
        {
            var backup = BackupPath(path);
            if (!File.Exists(backup))
                throw;
            try
            {
                var value = parse(File.ReadAllText(backup));
                Console.Error.WriteLine($"{Path.GetFileName(path)} 无法使用（{first.GetType().Name}），已改用上一份");
                return value;
            }
            catch
            {
                throw first;
            }
        }
    }

    /// <summary>Whether the file or its previous version is there to read.</summary>
    public static bool Exists(string path) => File.Exists(path) || File.Exists(BackupPath(path));
}
