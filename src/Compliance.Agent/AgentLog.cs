using System.Text;

namespace Compliance.Agent;

/// <summary>
/// Console output of the resident service, which otherwise goes nowhere, written to agent.log in the data directory
/// with a timestamp per line. At 1 MB the file is moved to agent.log.1, so at most 2 MB are kept.
/// </summary>
public sealed class AgentLog(string path, long maxBytes = 1 << 20) : TextWriter
{
    private readonly StringBuilder line = new();

    public override Encoding Encoding => Encoding.UTF8;

    /// <summary>Output goes to the log file, so each check is summarized in one line instead of a full report.</summary>
    public static bool Active { get; private set; }

    public static void Attach(string dataDirectory)
    {
        Active = true;
        var log = Synchronized(new AgentLog(Path.Combine(dataDirectory, "agent.log")));
        Console.SetOut(log);
        Console.SetError(log);
    }

    public override void Write(char value)
    {
        if (value == '\n')
            Flush();
        else if (value != '\r')
            line.Append(value);
    }

    public override void Write(string? value)
    {
        foreach (var c in value ?? "")
            Write(c);
    }

    public override void WriteLine(string? value)
    {
        Write(value);
        Flush();
    }

    public override void Flush()
    {
        if (line.Length == 0)
            return;
        var text = $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss} {line}{Environment.NewLine}";
        line.Clear();
        try
        {
            if (File.Exists(path) && new FileInfo(path).Length > maxBytes)
                File.Move(path, path + ".1", true);
            File.AppendAllText(path, text, Encoding.UTF8);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Logging must never stop the checks.
        }
    }
}
