using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;

namespace Compliance.Core;

/// <summary>
/// A request from the tray to the agent service: <c>list</c>, <c>ack</c> with an event id,
/// <c>exception-options</c>, or <c>exception-request</c> with the request.
/// </summary>
public record TrayRequest(string Action, string? EventId = null, ExceptionRequest? Exception = null);

/// <summary>A notice the service keeps for the tray; <see cref="UserSid"/> is null for notices to every user.</summary>
public record TrayNotice(string EventId, string? UserSid, string Message, DateTimeOffset At, bool Acknowledged);

public record TrayAck(bool Ok);

public record TrayError(string Error);

/// <summary>
/// The named pipe between the agent service and the tray: one JSON line each way. <c>list</c> is answered with
/// <see cref="TrayNotice"/>[], <c>ack</c> with <see cref="TrayAck"/>, anything else (and every request while the
/// service waits to be enrolled) with <see cref="TrayError"/>. The version in the name changes only when this does.
/// </summary>
public static class TrayPipe
{
    public const string Name = "ComplianceAgent.Notifications.v1";
    public const string List = "list";
    public const string Ack = "ack";
    public const string ExceptionOptions = "exception-options";
    public const string RequestException = "exception-request";
    public const string NotEnrolled = "not-enrolled";

    /// <summary>The notices for the user running the tray, or null while the service waits to be enrolled.</summary>
    public static async Task<TrayNotice[]?> ListAsync()
    {
        var reply = await RequestAsync(new(List));
        using var json = JsonDocument.Parse(reply);
        var root = json.RootElement;
        if (
            root.ValueKind == JsonValueKind.Object
            && root.TryGetProperty("error", out var error)
            && error.ValueKind == JsonValueKind.String
            && error.GetString() == NotEnrolled
        )
            return null;
        if (root.ValueKind != JsonValueKind.Array)
            throw new JsonException("Service refused the request: " + reply);
        // Entries without an id are skipped rather than failing the whole list; other fields fall back.
        return root.EnumerateArray()
            .Where(n =>
                n.ValueKind == JsonValueKind.Object
                && n.TryGetProperty("eventId", out var id)
                && id.ValueKind == JsonValueKind.String
                && id.GetString() is { Length: > 0 }
            )
            .Select(n => new TrayNotice(
                n.GetProperty("eventId").GetString()!,
                n.TryGetProperty("userSid", out var sid) && sid.ValueKind == JsonValueKind.String
                    ? sid.GetString()
                    : null,
                n.TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.String ? m.GetString()! : "",
                n.TryGetProperty("at", out var at)
                && at.ValueKind == JsonValueKind.String
                && at.TryGetDateTimeOffset(out var time)
                    ? time
                    : DateTimeOffset.Now,
                n.TryGetProperty("acknowledged", out var ack) && ack.ValueKind == JsonValueKind.True
            ))
            .ToArray();
    }

    public static async Task<bool> AcknowledgeAsync(string eventId) =>
        Wire.Read<TrayAck>(await RequestAsync(new(Ack, eventId))).Ok;

    /// <summary>What the user may ask an exception for, or null while the service waits to be enrolled.</summary>
    public static async Task<ExceptionOption[]?> ExceptionOptionsAsync()
    {
        var reply = await RequestAsync(new(ExceptionOptions));
        if (reply.TrimStart().StartsWith('{'))
            return null;
        return Wire.Read<ExceptionOption[]>(reply) ?? [];
    }

    /// <summary>Sends an exception request to the administrators; null when it was taken, otherwise why not.</summary>
    public static async Task<string?> RequestExceptionAsync(ExceptionRequest request)
    {
        using var json = JsonDocument.Parse(await RequestAsync(new(RequestException, Exception: request)));
        return json.RootElement.TryGetProperty("ok", out var ok) && ok.ValueKind == JsonValueKind.True ? null
            : json.RootElement.TryGetProperty("error", out var error) ? error.GetString() ?? "提交失败"
            : "提交失败";
    }

    static async Task<string> RequestAsync(TrayRequest request)
    {
        // Identification lets the service tell which user asks, without letting it act as that user.
        using var pipe = new NamedPipeClientStream(
            ".",
            Name,
            PipeDirection.InOut,
            PipeOptions.Asynchronous,
            TokenImpersonationLevel.Identification
        );
        await pipe.ConnectAsync(2000);
        // An end that accepts but never answers must not leave the tray waiting for ever.
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try
        {
            using var writer = new StreamWriter(pipe, leaveOpen: true) { AutoFlush = true };
            using var reader = new StreamReader(pipe, leaveOpen: true);
            await writer.WriteLineAsync(Wire.Serialize(request).AsMemory(), timeout.Token);
            return await reader.ReadLineAsync(timeout.Token) ?? throw new IOException("Empty service response");
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            throw new IOException("The service did not answer");
        }
    }
}
