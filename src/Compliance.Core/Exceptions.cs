namespace Compliance.Core;

/// <summary>
/// A time-limited exception for one device, approved by an administrator: a forbidden product it may use, or a USB
/// disk it may use whatever the storage setting. The server puts the exceptions in force into every policy release,
/// so they reach devices signed like the rest of the policy.
/// </summary>
/// <param name="Id">The approved request, or the exception an administrator created.</param>
/// <param name="Kind"><see cref="PolicyExceptions.Product"/> or <see cref="PolicyExceptions.Usb"/>.</param>
/// <param name="Target">The product's id, or the USB disk's instance id.</param>
public record PolicyException(string Id, string DeviceId, string Kind, string Target, DateTimeOffset ExpiresAt)
{
    /// <summary>What people call it: the product's name, or the disk's description.</summary>
    public string Label { get; init; } = "";

    /// <summary>When it was approved; the device tells its user about exceptions approved in the last day.</summary>
    public DateTimeOffset GrantedAt { get; init; }
}

/// <summary>Something the user of a device may ask an exception for: a product found there, or a restricted disk.</summary>
public record ExceptionOption(string Kind, string Target, string Label);

/// <summary>What a user asks for from the tray, sent to the server as the detail of an <see cref="PolicyExceptions.RequestEvent"/>.</summary>
/// <param name="User">The Windows account that asked.</param>
public record ExceptionRequest(string Kind, string Target, string Label, string Reason, int Days, string User);

public static class PolicyExceptions
{
    public const string Product = "Product";
    public const string Usb = "Usb";
    public static readonly string[] Kinds = [Product, Usb];

    /// <summary>States of a request on the server: waiting, approved (until it expires), rejected, or revoked.</summary>
    public const string Pending = "Pending";
    public const string Approved = "Approved";
    public const string Rejected = "Rejected";
    public const string Revoked = "Revoked";

    /// <summary>The agent event that carries an <see cref="ExceptionRequest"/>.</summary>
    public const string RequestEvent = "ExceptionRequest";

    public const int MaxDays = 90;
    public const int MaxReason = 300;

    /// <summary>Longest event detail the server accepts; a request has to fit in one.</summary>
    public const int MaxDetail = 2048;
    public const int MaxExceptions = 2000;

    public static string KindLabel(string kind) =>
        kind switch
        {
            Product => "允许使用软件",
            Usb => "放行 U 盘",
            _ => kind,
        };

    public static void Validate(PolicyException[]? exceptions)
    {
        if (exceptions is null || exceptions.Length > MaxExceptions)
            throw new ArgumentException($"例外最多 {MaxExceptions} 项");
        foreach (var e in exceptions)
            if (
                e is null
                || string.IsNullOrWhiteSpace(e.Id)
                || string.IsNullOrWhiteSpace(e.DeviceId)
                || !Kinds.Contains(e.Kind)
                || e.Target is not { Length: > 0 and <= 256 }
                || e.Label is null
            )
                throw new ArgumentException("例外无效");
    }

    /// <summary>A request as sent from the tray, with its text bounded; null when it cannot be one.</summary>
    public static ExceptionRequest? Check(ExceptionRequest? r) =>
        r is { Kind: not null, Target: { Length: > 0 and <= 256 }, Label: not null, Reason: not null, User: not null }
        && Kinds.Contains(r.Kind)
        && r.Days is >= 1 and <= MaxDays
        && r.Reason.Trim().Length is > 0 and <= MaxReason
        && r.Label.Length <= 256
        && r.User.Length <= 256
            ? r with
            {
                Reason = r.Reason.Trim(),
            }
            : null;

    static readonly System.Text.Json.JsonSerializerOptions RequestJson = new(Wire.Json)
    {
        // Chinese reasons stay readable and short: escaped, each character would take six of the detail's.
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>The request as an event detail, or null when it is too long to be one.</summary>
    public static string? Serialize(ExceptionRequest request)
    {
        var detail = System.Text.Json.JsonSerializer.Serialize(request, RequestJson);
        return detail.Length <= MaxDetail ? detail : null;
    }

    /// <summary>The device's exceptions in force at <paramref name="now"/>.</summary>
    public static PolicyException[] Active(PolicyDocument policy, string deviceId, DateTimeOffset now) =>
        [.. (policy.Exceptions ?? []).Where(e => e.DeviceId == deviceId && e.ExpiresAt > now)];

    /// <summary>
    /// The policy as the device enforces it now: excepted products are not ended, and excepted USB disks are allowed.
    /// The verdict instead keeps reporting what was found, as allowed by the exception (see <see cref="ReportEngine"/>).
    /// </summary>
    public static PolicyDocument ForEnforcement(PolicyDocument policy, string deviceId, DateTimeOffset now)
    {
        var active = Active(policy, deviceId, now);
        if (active.Length == 0)
            return policy;
        var products = active.Where(e => e.Kind == Product).Select(e => e.Target).ToHashSet(StringComparer.Ordinal);
        var disks = active
            .Where(e => e.Kind == Usb)
            .Select(e => new UsbAllowedDevice(e.Target) { Note = "例外" })
            .ToArray();
        return policy with
        {
            Products = [.. policy.Products.Where(p => !products.Contains(p.Id))],
            Usb = policy.Usb with { AllowedDevices = [.. policy.Usb.AllowedDevices, .. disks] },
        };
    }
}
