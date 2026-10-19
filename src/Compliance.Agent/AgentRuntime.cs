using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Compliance.Core;

namespace Compliance.Agent;

public sealed record AgentConfiguration(
    string ServerUrl,
    string DataDirectory,
    string? DeviceId = null,
    string? PolicyPublicKeyPem = null,
    string? PolicyKeyId = null,
    // Set by the trial installer: the resident service may use a private-network HTTP server that
    // reports trial mode. Production configurations leave it false and require HTTPS.
    bool HttpTrial = false,
    // The key the server announced, under the current one, to sign with once its rotation completes.
    string? NextPolicyPublicKeyPem = null,
    string? NextPolicyKeyId = null
)
{
    public static AgentConfiguration Read(string path) => DurableFile.Read(path, Wire.Read<AgentConfiguration>);

    public static bool Exists(string path) => DurableFile.Exists(path);

    public static void Save(string path, AgentConfiguration value) => DurableFile.Write(path, Wire.Serialize(value));
}

/// <summary>
/// The policy signing keys a client trusts: the one it received at enrollment and, while the server rotates its key,
/// the next one, announced in heartbeat replies and signed with the current key. Policies and packages signed with the
/// next key verify as soon as it is known; the first policy that does makes it the current key.
/// </summary>
public static class PolicyKeys
{
    public const string KeyChanged = "Policy key ID changed";

    /// <summary>The public key a signature by <paramref name="keyId"/> must verify with.</summary>
    public static string PublicKeyFor(AgentConfiguration config, string keyId)
    {
        if (keyId == config.NextPolicyKeyId && config.NextPolicyPublicKeyPem is { } next)
            return next;
        // Configurations written before enrollment returned a key id accept the pinned key for any id.
        if (config.PolicyKeyId is null || keyId == config.PolicyKeyId)
            return config.PolicyPublicKeyPem ?? throw new CryptographicException("No policy key");
        throw new CryptographicException(KeyChanged);
    }

    /// <summary>
    /// The configuration trusting the key a server announced, or the same configuration when the announcement is the
    /// known one. Throws when the current key did not sign it.
    /// </summary>
    public static AgentConfiguration Accept(AgentConfiguration config, SignedKeyRotation announced)
    {
        var rotation = KeyRotationCrypto.Verify(announced, config.PolicyPublicKeyPem!);
        if (rotation.NewKeyId == config.PolicyKeyId || rotation.NewKeyId == config.NextPolicyKeyId)
            return config;
        return config with { NextPolicyPublicKeyPem = rotation.NewPublicKeyPem, NextPolicyKeyId = rotation.NewKeyId };
    }

    /// <summary>The configuration after a policy signed by <paramref name="keyId"/> verified.</summary>
    public static AgentConfiguration Verified(AgentConfiguration config, string keyId) =>
        keyId == config.NextPolicyKeyId && config.NextPolicyPublicKeyPem is { } next
            ? config with
            {
                PolicyPublicKeyPem = next,
                PolicyKeyId = keyId,
                NextPolicyPublicKeyPem = null,
                NextPolicyKeyId = null,
            }
            : config;

    /// <summary>
    /// The server now signs with the next key: completing the rotation re-signed the release this client holds, which
    /// has to be fetched again for the next key to become current. A key the client never learned of is not a reason
    /// to fetch, since no policy signed with it could verify.
    /// </summary>
    public static bool Resigned(AgentConfiguration config, string? signingKeyId) =>
        signingKeyId is not null && signingKeyId == config.NextPolicyKeyId;

    /// <summary>The key ids reported in heartbeats, so the server can tell when every client knows the next key.</summary>
    public static string[] Ids(AgentConfiguration config) =>
        new[] { config.PolicyKeyId, config.NextPolicyKeyId }.OfType<string>().ToArray();
}

public sealed class DeviceIdentity
{
    private readonly string keyPath;
    private readonly bool simulation;

    public DeviceIdentity(string dataDirectory, bool simulation)
    {
        Directory.CreateDirectory(dataDirectory);
        keyPath = Path.Combine(dataDirectory, simulation ? "device.simulated.pk8" : "device.dpapi");
        this.simulation = simulation;
        if (!simulation && !OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("DPAPI device identity requires Windows");
    }

    /// <summary>
    /// The key of an enrolled device. A missing or unreadable key is never replaced here: the server knows this device
    /// by its public key, so a new one could not sign a single request. The device has to enroll again instead.
    /// </summary>
    public ECDsa Load() =>
        TryLoad(out var key, out var problem) ? key! : throw new DeviceIdentityLostException(problem!);

    public bool TryLoad(out ECDsa? key, out string? problem)
    {
        key = null;
        problem = null;
        if (!File.Exists(keyPath))
        {
            problem = "设备密钥文件不存在";
            return false;
        }
        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(keyPath);
            if (!simulation)
            {
                if (!OperatingSystem.IsWindows())
                    throw new PlatformNotSupportedException();
                bytes = UnprotectWindows(bytes);
            }
        }
        catch (Exception e) when (e is CryptographicException or IOException)
        {
            problem = "设备密钥文件无法读取（" + e.GetType().Name + "）";
            return false;
        }
        var loaded = ECDsa.Create();
        try
        {
            loaded.ImportPkcs8PrivateKey(bytes, out _);
        }
        catch (CryptographicException)
        {
            loaded.Dispose();
            problem = "设备密钥文件已损坏";
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
        key = loaded;
        return true;
    }

    /// <summary>
    /// The key to enroll with: the existing one if it can be read, otherwise a new one, which replaces a damaged file.
    /// Only for a device that is not enrolled, or whose key is lost.
    /// </summary>
    public ECDsa ForEnrollment()
    {
        if (TryLoad(out var existing, out _))
            return existing!;
        var created = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var raw = created.ExportPkcs8PrivateKey();
        if (!simulation && !OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException();
        var stored = simulation ? raw : ProtectWindows(raw);
        // Written to a temporary file and flushed to disk before it takes the key's name, so a power cut leaves
        // either the old file or the whole new one, never a truncated key.
        var temp = keyPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var file = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                file.Write(stored);
                file.Flush(true);
            }
            if (simulation && !OperatingSystem.IsWindows())
                File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.Move(temp, keyPath, true);
        }
        finally
        {
            File.Delete(temp);
            CryptographicOperations.ZeroMemory(raw);
        }
        return created;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static byte[] ProtectWindows(byte[] data) =>
        ProtectedData.Protect(data, null, DataProtectionScope.LocalMachine);

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static byte[] UnprotectWindows(byte[] data) =>
        ProtectedData.Unprotect(data, null, DataProtectionScope.LocalMachine);
}

/// <summary>An enrolled device whose key is missing or damaged; only enrolling again recovers it.</summary>
public sealed class DeviceIdentityLostException(string problem)
    : InvalidOperationException(
        $"{problem}。本机无法再向管理端证明身份，请在管理端删除这台终端后用新的登记码重新登记。"
    );

/// <summary>The configuration names another device than the running service: it was enrolled again.</summary>
public sealed class DeviceReenrolledException() : Exception("本机已重新登记，服务重新启动后使用新的登记");

public sealed class AgentApiException(
    string message,
    HttpStatusCode status,
    TimeSpan? retryAfter,
    string? serverError = null
) : HttpRequestException(message, null, status)
{
    public TimeSpan? RetryAfter { get; } = retryAfter;

    /// <summary>The <c>error</c> the server gave, if it gave one.</summary>
    public string? ServerError { get; } = serverError;

    /// <summary>The server does not know this device: an administrator deleted it.</summary>
    public bool DeviceUnknown =>
        StatusCode == HttpStatusCode.Unauthorized && ServerError == RequestAuthentication.UnknownDevice;

    public static async Task<string?> ErrorOf(HttpResponseMessage response, CancellationToken ct)
    {
        try
        {
            var body = await response.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.TryGetProperty("error", out var error) ? error.GetString() : null;
        }
        catch (Exception e) when (e is JsonException or HttpRequestException or InvalidOperationException)
        {
            return null;
        }
    }
}

public sealed class AgentApi(HttpClient client, Uri baseUri, string? deviceId, ECDsa key)
{
    /// <summary>Bodies from this size on are compressed when <see cref="Gzip"/> is set.</summary>
    public const int GzipFrom = 4096;

    /// <summary>The server accepts gzip-compressed bodies; it says so in its heartbeat reply.</summary>
    public bool Gzip { get; set; }

    public async Task<T> SendAsync<T>(HttpMethod method, string path, object? body, CancellationToken ct)
    {
        var bytes = body is null ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(Wire.Serialize(body));
        var compress = Gzip && bytes.Length >= GzipFrom;
        if (compress)
            bytes = Compress(bytes);
        using var request = new HttpRequestMessage(method, new Uri(baseUri, path));
        if (body is not null)
        {
            request.Content = new ByteArrayContent(bytes)
            {
                Headers = { ContentType = new MediaTypeHeaderValue("application/json") },
            };
            if (compress)
                request.Content.Headers.ContentEncoding.Add("gzip");
        }
        if (path != "/api/agent/enroll")
        {
            if (string.IsNullOrWhiteSpace(deviceId))
                throw new InvalidOperationException("Device has not enrolled");
            var timestamp = DateTimeOffset
                .UtcNow.ToUnixTimeSeconds()
                .ToString(System.Globalization.CultureInfo.InvariantCulture);
            var nonce = Guid.NewGuid().ToString("D");
            request.Headers.Add("X-Device-Id", deviceId);
            request.Headers.Add("X-Timestamp", timestamp);
            request.Headers.Add("X-Nonce", nonce);
            request.Headers.Add(
                "X-Signature",
                RequestAuthentication.Sign(key, method.Method, path, timestamp, nonce, bytes)
            );
        }
        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request, ct);
        }
        catch (OperationCanceledException ex) when (!ct.IsCancellationRequested)
        {
            throw new HttpRequestException("Agent API request timed out", ex, HttpStatusCode.RequestTimeout);
        }
        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                var retry =
                    response.Headers.RetryAfter?.Delta
                    ?? (response.Headers.RetryAfter?.Date is { } date ? date - DateTimeOffset.UtcNow : null);
                throw new AgentApiException(
                    $"Agent API {path}: {(int)response.StatusCode}",
                    response.StatusCode,
                    retry,
                    await AgentApiException.ErrorOf(response, ct)
                );
            }
            return Wire.Read<T>(await response.Content.ReadAsStringAsync(ct));
        }
    }

    /// <summary>
    /// Downloads a file the server hosts into <paramref name="destination"/>, refusing more than
    /// <paramref name="maxSize"/> bytes. Large files may take longer than an API request is allowed to.
    /// </summary>
    public async Task DownloadAsync(string path, string destination, long maxSize, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(baseUri, path));
        var timestamp = DateTimeOffset
            .UtcNow.ToUnixTimeSeconds()
            .ToString(System.Globalization.CultureInfo.InvariantCulture);
        var nonce = Guid.NewGuid().ToString("D");
        request.Headers.Add("X-Device-Id", deviceId);
        request.Headers.Add("X-Timestamp", timestamp);
        request.Headers.Add("X-Nonce", nonce);
        request.Headers.Add("X-Signature", RequestAuthentication.Sign(key, "GET", path, timestamp, nonce, []));
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromMinutes(30));
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        if (!response.IsSuccessStatusCode)
            throw new AgentApiException($"Agent API {path}: {(int)response.StatusCode}", response.StatusCode, null);
        await using var body = await response.Content.ReadAsStreamAsync(timeout.Token);
        await using var file = File.Create(destination);
        var buffer = new byte[81920];
        long size = 0;
        int read;
        while ((read = await body.ReadAsync(buffer, timeout.Token)) > 0)
        {
            size += read;
            if (size > maxSize)
                throw new HttpRequestException($"Agent API {path}: larger than announced");
            await file.WriteAsync(buffer.AsMemory(0, read), timeout.Token);
        }
    }

    public static byte[] Compress(byte[] plain)
    {
        using var output = new MemoryStream();
        using (var gzip = new System.IO.Compression.GZipStream(output, System.IO.Compression.CompressionLevel.Fastest))
            gzip.Write(plain);
        return output.ToArray();
    }
}

public sealed class AgentRuntime(
    AgentConfiguration config,
    string configPath,
    bool simulated,
    string? fixturePath,
    bool localDemo = false
)
{
    /// <summary>
    /// Written while the server says it does not know this device (an administrator deleted it); while it is there,
    /// enrolling again with a code is allowed although the device has a configuration and key.
    /// </summary>
    public const string RemovedMarker = "removed-from-server";

    public static bool RemovedFromServer(string dataDirectory) =>
        File.Exists(Path.Combine(dataDirectory, RemovedMarker));

    public const string DataAclRepairedMessage =
        "客户端数据目录的访问权限被修改过（允许了系统和管理员以外的账户），已自动恢复。期间该账户可能读取过本机的登记密钥；如不是管理员本人操作，请删除该终端并重新登记。";

    /// <summary>Set when startup removed access to the data directory that someone had granted; reported once.</summary>
    public bool DataAclRepaired { get; set; }

    private readonly string statePath = Path.Combine(config.DataDirectory, "policy.signed.json");
    private PolicyDocument? policy;
    private SignedPolicy? signedPolicy;
    private DateTimeOffset lastFull = DateTimeOffset.MinValue;
    private VolumeCatalog? volumes;
    private DateTimeOffset lastLight = DateTimeOffset.MinValue;
    private ScanSnapshot? latest;

    // Native agents only; a fixture snapshot already carries whatever sensitive file results it simulates.
    private SensitiveFileScanner? sensitiveFiles;

    // A one-time check waits for the file name scan so its results are part of the single upload.
    private bool waitForSensitiveFiles;
    private int reportedSensitiveRevision;
    private ProcessEnforcer? processes;
    private BrowserBlocklist? browsers;

    // A fixture stands in for another machine, so report its host name rather than this one's.
    private string HostName =>
        simulated
        && fixturePath is not null
        && Wire.Read<ScanSnapshot>(File.ReadAllText(fixturePath)).HostName is { Length: > 0 } name
            ? name
            : Environment.MachineName;

    public static Uri ValidateServer(string url, bool simulation, bool localDemo = false)
    {
        var uri = new Uri(url, UriKind.Absolute);
        if (localDemo)
        {
            if (
                uri.Scheme == Uri.UriSchemeHttp
                && IsTrialAddress(uri.Host)
                && uri.AbsolutePath == "/"
                && uri.Query.Length == 0
                && uri.Fragment.Length == 0
                && uri.UserInfo.Length == 0
            )
                return uri;
            throw new InvalidOperationException(
                "HTTP trial requires an explicit loopback or private IPv4 server address without a path"
            );
        }
        if (uri.Scheme == Uri.UriSchemeHttps)
            return uri;
        if (
            simulation
            && uri.Scheme == Uri.UriSchemeHttp
            && IPAddress.TryParse(uri.Host, out var ip)
            && IPAddress.IsLoopback(ip)
        )
            return uri;
        if (
            simulation
            && uri.Scheme == Uri.UriSchemeHttp
            && uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
        )
            return uri;
        throw new InvalidOperationException(
            "Agent server requires HTTPS; HTTP is allowed only for explicit loopback fixture simulation"
        );
    }

    private static bool IsTrialAddress(string host)
    {
        if (!IPAddress.TryParse(host, out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return false;
        var b = ip.GetAddressBytes();
        return b[0] == 127 || b[0] == 10 || b[0] == 172 && b[1] >= 16 && b[1] <= 31 || b[0] == 192 && b[1] == 168;
    }

    public static bool IsLoopbackDemoStatus(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            return document.RootElement.TryGetProperty("mode", out var mode)
                && mode.ValueKind == JsonValueKind.String
                && mode.GetString() is "LoopbackDemo" or "LanHttpTrial";
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private async Task VerifyLocalDemoAsync(
        HttpClient client,
        Uri uri,
        CancellationToken ct,
        bool tolerateOffline = false
    )
    {
        if (!localDemo)
            return;
        if (tolerateOffline)
        {
            // A resident service may start before the server; uploads queue until it is reachable. A server
            // that answers but is not in trial mode is still refused.
            try
            {
                await VerifyLocalDemoAsync(client, uri, ct);
            }
            catch (HttpRequestException ex)
            {
                Console.Error.WriteLine("Trial server not reachable yet: " + ex.Message);
            }
            return;
        }
        using var response = await client.GetAsync(new Uri(uri, "/api/status"), ct);
        response.EnsureSuccessStatusCode();
        if (!IsLoopbackDemoStatus(await response.Content.ReadAsStringAsync(ct)))
            throw new InvalidOperationException("The HTTP server has not enabled trial mode");
    }

    public async Task EnrollAsync(string code, CancellationToken ct)
    {
        using var key = new DeviceIdentity(config.DataDirectory, simulated).ForEnrollment();
        using var client = CreateInternalClient();
        var uri = ValidateServer(config.ServerUrl, simulated, localDemo);
        await VerifyLocalDemoAsync(client, uri, ct);
        var api = new AgentApi(client, uri, null, key);
        var response = await api.SendAsync<EnrollmentResponse>(
            HttpMethod.Post,
            "/api/agent/enroll",
            new EnrollmentRequest(code, HostName, key.ExportSubjectPublicKeyInfoPem()),
            ct
        );
        config = config with
        {
            DeviceId = response.DeviceId,
            PolicyPublicKeyPem = response.PolicyPublicKeyPem,
            PolicyKeyId = response.PolicyKeyId,
        };
        AgentConfiguration.Save(configPath, config);
    }

    public async Task RunAsync(bool once, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(config.DeviceId) || string.IsNullOrWhiteSpace(config.PolicyPublicKeyPem))
            throw new InvalidOperationException("Enroll first with --enroll --code");
        var uri = ValidateServer(config.ServerUrl, simulated, localDemo);
        using var key = new DeviceIdentity(config.DataDirectory, simulated).Load();
        using var client = CreateInternalClient();
        await VerifyLocalDemoAsync(client, uri, ct, tolerateOffline: !once);
        var api = new AgentApi(client, uri, config.DeviceId, key);
        var rebuilt = new List<string>();
        await using var queue = LocalDatabase.Open(
            Path.Combine(config.DataDirectory, "outbox.sqlite"),
            path => new EventOutbox(path),
            rebuilt.Add
        );
        await using var notices = LocalDatabase.Open(
            Path.Combine(config.DataDirectory, "notices.sqlite"),
            path => new NotificationStore(path),
            rebuilt.Add
        );
        foreach (var message in rebuilt)
            await TryEnqueueAsync(queue, notices, "Health", "agent:local-database", null, message, ct);
        if (DataAclRepaired)
        {
            await TryEnqueueAsync(queue, notices, "Health", "agent:data-acl", null, DataAclRepairedMessage, ct);
            DataAclRepaired = false;
        }
        var pipeTask =
            OperatingSystem.IsWindows() && !once ? new NotificationPipe(notices).RunAsync(ct) : Task.CompletedTask;
        await LoadCachedPolicy();
        // One copy of each volume's file records serves the sensitive file scan and the program file scan.
        volumes = OperatingSystem.IsWindows() && !simulated ? new VolumeCatalog(NtfsVolume.TryOpen) : null;
        using var scanner =
            OperatingSystem.IsWindows() && !simulated
                ? new SensitiveFileScanner(
                    Path.Combine(config.DataDirectory, "sensitive-files.json"),
                    SensitiveFileScanner.WindowsTargets,
                    SensitiveFileScanner.WindowsOwner,
                    volume => volumes!.Open(volume)
                )
                : null;
        sensitiveFiles = scanner;
        if (OperatingSystem.IsWindows() && !simulated)
        {
            processes = new ProcessEnforcer(new WindowsProcessTable());
            browsers = new BrowserBlocklist(
                new WindowsBlocklistStore(),
                Path.Combine(config.DataDirectory, "browser-blocklist.json")
            );
        }
        if (once)
        {
            waitForSensitiveFiles = true;
            await CheckAsync(api, queue, notices, true, ct);
            await UploadAsync(api, queue, notices, ct);
            if (localDemo && await queue.UnsentCountAsync(ct) > 0)
                throw new InvalidOperationException(
                    "Local scan finished but upload is still queued; keep the demo server running and retry this scan"
                );
            return;
        }
        var enforceTask = processes is null ? Task.CompletedTask : EnforceAsync(queue, notices, ct);
        var failures = new Dictionary<string, DateTimeOffset>();
        while (!ct.IsCancellationRequested)
        {
            // Enrolled again (as a new device) by an administrator: the service restarts to use it.
            if (EnrolledElsewhere())
                throw new DeviceReenrolledException();
            // A failed side task is started again on its own; checking and uploading carry on meanwhile. The loop's
            // own delay paces restarts of a task that keeps failing.
            if (pipeTask.IsFaulted && OperatingSystem.IsWindows())
            {
                await ReportTaskFailureAsync(queue, notices, failures, "notification-pipe", pipeTask.Exception!, ct);
                pipeTask = new NotificationPipe(notices).RunAsync(ct);
            }
            if (enforceTask.IsFaulted)
            {
                await ReportTaskFailureAsync(queue, notices, failures, "enforcement", enforceTask.Exception!, ct);
                enforceTask = EnforceAsync(queue, notices, ct);
            }
            // A failed check must not stop the upload, which is what empties the queue.
            try
            {
                await CheckAsync(api, queue, notices, false, ct);
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                Console.Error.WriteLine(
                    $"Agent cycle failed: {e.GetType().Name}: {EvidenceSanitizer.Clean(e.Message)}"
                );
                // A failure that repeats every cycle is reported at most once an hour.
                if (!failures.TryGetValue("cycle", out var at) || at <= DateTimeOffset.UtcNow.AddHours(-1))
                {
                    failures["cycle"] = DateTimeOffset.UtcNow;
                    await TryEnqueueAsync(
                        queue,
                        notices,
                        "Health",
                        "agent:cycle",
                        null,
                        "Cycle failure: " + e.GetType().Name,
                        ct
                    );
                }
            }
            try
            {
                await UploadAsync(api, queue, notices, ct);
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                Console.Error.WriteLine($"Upload failed: {e.GetType().Name}: {EvidenceSanitizer.Clean(e.Message)}");
            }
            if (queue.Dropped > reportedDrops)
            {
                Console.Error.WriteLine($"本地待上报记录已满，已丢弃 {queue.Dropped - reportedDrops} 份较早的检查结果");
                reportedDrops = queue.Dropped;
            }
            await Task.Delay(TimeSpan.FromSeconds(55 + Random.Shared.Next(11)), ct);
        }
    }

    private int reportedDrops;

    private bool EnrolledElsewhere()
    {
        try
        {
            return AgentConfiguration.Read(configPath).DeviceId is { Length: > 0 } id && id != config.DeviceId;
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Queues an event. When the queue is full of events that cannot be dropped, the user is told and the service
    /// carries on: it must keep uploading, which is what empties the queue.
    /// </summary>
    private static async Task TryEnqueueAsync(
        EventOutbox queue,
        NotificationStore notices,
        string type,
        string objectKey,
        ScanSnapshot? snapshot,
        string? detail,
        CancellationToken ct
    )
    {
        try
        {
            await queue.EnqueueAsync(type, objectKey, snapshot, detail, ct);
        }
        catch (OutboxCapacityException e)
        {
            Console.Error.WriteLine(e.Message);
            await notices.AddAsync(
                "health:outbox-capacity",
                null,
                "本机待上报的记录已达上限，新的记录可能无法保存，请联系管理员。",
                ct
            );
        }
    }

    /// <summary>Logs a failed side task every time and reports it to the server at most once an hour.</summary>
    private static async Task ReportTaskFailureAsync(
        EventOutbox queue,
        NotificationStore notices,
        Dictionary<string, DateTimeOffset> reported,
        string task,
        AggregateException failure,
        CancellationToken ct
    )
    {
        var e = failure.Flatten().InnerException ?? failure;
        Console.Error.WriteLine($"{task} failed, restarting: {e.GetType().Name}: {EvidenceSanitizer.Clean(e.Message)}");
        if (reported.TryGetValue(task, out var at) && at > DateTimeOffset.UtcNow.AddHours(-1))
            return;
        reported[task] = DateTimeOffset.UtcNow;
        try
        {
            await TryEnqueueAsync(
                queue,
                notices,
                "Health",
                "agent:" + task,
                null,
                "Task failure: " + e.GetType().Name,
                ct
            );
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Console.Error.WriteLine($"Could not report {task} failure: {ex.GetType().Name}");
        }
    }

    /// <summary>
    /// Ends forbidden programs every 2 seconds while the policy enforces it. Each product is reported to the
    /// server and to the user's tray at most once per 10 minutes, however often it is restarted.
    /// </summary>
    private async Task EnforceAsync(EventOutbox queue, NotificationStore notices, CancellationToken ct)
    {
        var reported = new Dictionary<string, DateTimeOffset>();
        while (!ct.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromSeconds(2), ct);
            if (policy is not { } current || processes is null)
                continue;
            List<BlockedProcess> blocked;
            try
            {
                blocked = processes.Sweep(current, DateTimeOffset.UtcNow);
                foreach (var reason in processes.Skipped)
                    Console.WriteLine("发现同名程序但未确认：" + reason);
                processes.Skipped.Clear();
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                Console.Error.WriteLine($"结束禁用程序时出错：{e.GetType().Name}: {e.Message}");
                continue;
            }
            foreach (var b in blocked)
            {
                Console.WriteLine($"已结束禁用程序 {b.ProductName}（{b.Executable}，进程号 {b.Pid}）");
                var key = b.ProductId + "|" + b.UserSid;
                if (reported.TryGetValue(key, out var at) && at > DateTimeOffset.UtcNow.AddMinutes(-10))
                    continue;
                reported[key] = DateTimeOffset.UtcNow;
                var detail = $"{b.ProductName}（{b.Executable}）已被结束：单位策略禁止在本机使用该程序";
                // Failing to record it (a full disk, a locked database) must not stop ending programs.
                try
                {
                    await notices.AddAsync(Guid.NewGuid().ToString("D"), b.UserSid, "Blocked: " + detail, ct);
                }
                catch (Exception e) when (e is not OperationCanceledException)
                {
                    Console.Error.WriteLine($"拦截提示写入失败：{e.GetType().Name}: {e.Message}");
                }
                try
                {
                    await TryEnqueueAsync(queue, notices, "BlockedAttempt", "blocked:" + b.ProductId, null, detail, ct);
                }
                catch (Exception e) when (e is not OperationCanceledException)
                {
                    Console.Error.WriteLine($"拦截记录入队失败：{e.GetType().Name}: {e.Message}");
                }
            }
        }
    }

    private async Task LoadCachedPolicy()
    {
        if (!DurableFile.Exists(statePath))
            return;
        try
        {
            // A cache the power cut emptied falls back to the policy before it rather than to the detection-only seed.
            var (signed, doc) = DurableFile.Read(
                statePath,
                text =>
                {
                    var read = Wire.Read<SignedPolicy>(text);
                    return (read, VerifyRetained(read, 0));
                }
            );
            signedPolicy = signed;
            policy = doc;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine("Cached policy invalid: " + e.GetType().Name);
        }
    }

    private PolicyDocument VerifyRetained(SignedPolicy signed, long minimumSerial)
    {
        var untrusted = Wire.Read<PolicyDocument>(signed.Payload);
        var verificationTime =
            untrusted.ExpiresAt < DateTimeOffset.UtcNow ? untrusted.ExpiresAt : DateTimeOffset.UtcNow;
        return PolicyCrypto.Verify(
            signed,
            PolicyKeys.PublicKeyFor(config, signed.KeyId),
            config.DeviceId!,
            minimumSerial,
            verificationTime
        );
    }

    private async Task CheckAsync(
        AgentApi api,
        EventOutbox queue,
        NotificationStore notices,
        bool forceFull,
        CancellationToken ct
    )
    {
        string? policyIssue = null;
        long? assignedSerial = null;
        string? signingKeyId = null;
        // Health goes first when connectivity resumes, then historical events.
        try
        {
            var heartbeat = new HeartbeatRequest(
                HostName,
                ReleaseVersion.Of(typeof(AgentRuntime).Assembly),
                DateTimeOffset.UtcNow,
                signedPolicy is null ? 0 : policy?.Serial ?? 0,
                latest?.Controls ?? [],
                // A fixture stands in for another machine; this one's adapters would be wrong for it.
                simulated ? null : NetworkInventory.Read(),
                PolicyKeys.Ids(config)
            );
            var reply = await api.SendAsync<JsonElement>(HttpMethod.Post, "/api/agent/heartbeat", heartbeat, ct);
            File.Delete(Path.Combine(config.DataDirectory, RemovedMarker));
            // Servers before 0.2.9 do not say so and take uncompressed bodies only.
            api.Gzip =
                reply.ValueKind == JsonValueKind.Object
                && reply.TryGetProperty("gzipUploads", out var gzip)
                && gzip.ValueKind == JsonValueKind.True;
            // Servers from 0.2.23 say the highest event sequence they hold for this device.
            if (
                reply.ValueKind == JsonValueKind.Object
                && reply.TryGetProperty("lastSequence", out var last)
                && last.TryGetInt64(out var sequence)
                && await queue.AdvanceSequenceAsync(sequence, ct)
            )
                Console.Error.WriteLine($"本地上报序号落后于管理端，已改为从 {sequence + 1} 继续");
            // Servers from this release say which policy release is assigned; one already held is not fetched again.
            if (
                reply.ValueKind == JsonValueKind.Object
                && reply.TryGetProperty("policySerial", out var serial)
                && serial.TryGetInt64(out var assigned)
            )
                assignedSerial = assigned;
            if (
                reply.ValueKind == JsonValueKind.Object
                && reply.TryGetProperty("policyKeyId", out var signing)
                && signing.ValueKind == JsonValueKind.String
            )
                signingKeyId = signing.GetString();
            // While the server rotates its policy key it announces the next one, signed with the current key. The
            // next key is kept until a policy signed with it arrives, even when a reply stops announcing it: the
            // rotation may have completed between two heartbeats.
            if (
                reply.ValueKind == JsonValueKind.Object
                && reply.TryGetProperty("keyRotation", out var announced)
                && announced.ValueKind == JsonValueKind.Object
            )
                try
                {
                    var accepted = PolicyKeys.Accept(config, Wire.Read<SignedKeyRotation>(announced.GetRawText()));
                    if (accepted != config)
                    {
                        config = accepted;
                        AgentConfiguration.Save(configPath, config);
                        Console.WriteLine($"管理端将更换策略签名密钥，已记下新密钥 {config.NextPolicyKeyId}");
                    }
                }
                catch (Exception e) when (e is CryptographicException or ArgumentException or JsonException)
                {
                    Console.Error.WriteLine("Key rotation announcement rejected: " + e.GetType().Name);
                }
            // Newer servers say the oldest client they serve fully; the tray tells the user once per minimum.
            var own = ReleaseVersion.Of(typeof(AgentRuntime).Assembly);
            if (
                reply.ValueKind == JsonValueKind.Object
                && reply.TryGetProperty("minimumAgentVersion", out var minimum)
                && minimum.GetString() is { Length: > 0 } oldest
                && ReleaseVersion.Unsupported(own, oldest)
            )
            {
                Console.Error.WriteLine($"客户端 {own} 低于管理端要求的最低版本 {oldest}，请升级");
                await notices.AddAsync(
                    "client-unsupported:" + oldest,
                    null,
                    $"本机的终端合规客户端（{own}）低于管理端要求的最低版本 {oldest}，检查结果可能不完整，请联系管理员升级客户端。",
                    ct
                );
            }
        }
        catch (AgentApiException e) when (e.DeviceUnknown)
        {
            // Checking and blocking go on with the last policy; reports cannot reach the server until it is enrolled
            // again, which the marker allows.
            var marker = Path.Combine(config.DataDirectory, RemovedMarker);
            if (!File.Exists(marker))
            {
                File.WriteAllText(marker, DateTimeOffset.UtcNow.ToString("O"));
                Console.Error.WriteLine("管理端已删除本机，需要用登记码重新登记");
            }
            await notices.AddAsync(
                "device-removed",
                null,
                "本机已从管理端删除，检查结果无法上报，请联系管理员用新的登记码重新登记。",
                ct
            );
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or JsonException)
        {
            Console.Error.WriteLine("Heartbeat pending: " + e.GetType().Name);
        }
        // The same release comes back unchanged, so it is fetched (up to 4 MB) only when another one is assigned, or when
        // a completed key rotation re-signed it with the next key, which only a policy signed with it makes current.
        var held =
            signedPolicy is not null
            && policy is not null
            && assignedSerial == policy.Serial
            && !PolicyKeys.Resigned(config, signingKeyId);
        if (!held)
            try
            {
                var fetched = await api.SendAsync<SignedPolicy>(HttpMethod.Get, "/api/agent/policy", null, ct);
                var verified = PolicyCrypto.Verify(
                    fetched,
                    PolicyKeys.PublicKeyFor(config, fetched.KeyId),
                    config.DeviceId!,
                    policy?.Serial ?? 0,
                    DateTimeOffset.UtcNow
                );
                if (
                    policy is not null
                    && verified.Serial == policy.Serial
                    && signedPolicy is not null
                    && fetched.Payload != signedPolicy.Payload
                )
                    throw new CryptographicException("Immutable policy version changed content");
                if (policy?.Serial != verified.Serial)
                {
                    forceFull = true;
                    Console.WriteLine(
                        $"收到新策略“{verified.PolicyId}”v{verified.Version}"
                            + (policy is null ? "" : $"（原“{policy.PolicyId}”v{policy.Version}）")
                            + "，立即完整检查"
                    );
                }
                policy = verified;
                // Rewritten only when it changed: the same policy comes back every minute.
                if (
                    signedPolicy is null
                    || fetched.Payload != signedPolicy.Payload
                    || fetched.KeyId != signedPolicy.KeyId
                )
                    DurableFile.Write(statePath, Wire.Serialize(fetched));
                signedPolicy = fetched;
                if (PolicyKeys.Verified(config, fetched.KeyId) is var promoted && promoted != config)
                {
                    config = promoted;
                    AgentConfiguration.Save(configPath, config);
                    Console.WriteLine($"管理端已更换策略签名密钥，现在信任 {config.PolicyKeyId}");
                }
            }
            catch (Exception e)
                when (e
                        is HttpRequestException
                            or TaskCanceledException
                            or CryptographicException
                            or ArgumentException
                            or JsonException
                )
            {
                policyIssue =
                    (e is HttpRequestException or TaskCanceledException) && signedPolicy is not null
                        ? null
                        : "Policy refresh failed: " + e.GetType().Name;
                Console.Error.WriteLine("Policy refresh failed; retained last signed policy: " + e.GetType().Name);
                // The server completed a key rotation this device never heard of: only enrolling again helps.
                if (e is CryptographicException { Message: PolicyKeys.KeyChanged })
                    await notices.AddAsync(
                        "policy-key-changed",
                        null,
                        "管理端已更换策略签名密钥，本机没有收到新密钥，无法再接收策略。请联系管理员在终端列表删除本机，再用登记码重新登记。",
                        ct
                    );
            }
        if (policy is null)
        {
            policy = PolicySeed.Create();
            policyIssue = "No valid signed policy; local seed used for detection only";
        }
        if (policy.ExpiresAt < DateTimeOffset.UtcNow)
            policyIssue = "Last signed policy expired; OS controls retained";
        DeviceCommand[] commands = [];
        try
        {
            commands = await api.SendAsync<DeviceCommand[]>(HttpMethod.Get, "/api/agent/commands", null, ct);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or JsonException)
        {
            Console.Error.WriteLine("Commands pending: " + e.GetType().Name);
        }
        var scanCommands = commands.Where(x => x.Type == "ScanNow" && x.ExpiresAt > DateTimeOffset.UtcNow).ToArray();
        if (scanCommands.Length > 0)
            Console.WriteLine("管理端请求重新检查，开始完整检查");
        var upgrade = commands.FirstOrDefault(x =>
            x.Type == ClientUpgrade.Command && x.ExpiresAt > DateTimeOffset.UtcNow
        );
        foreach (var unsupported in commands.Except(scanCommands).Where(x => x != upgrade))
            await AckAsync(api, unsupported, new CommandReply(false, "Unsupported or expired command"), ct);
        if (upgrade != null)
            await UpgradeAsync(api, upgrade, ct);
        if (scanCommands.Length > 0)
            forceFull = true;
        bool full =
            forceFull || latest is null || lastFull < DateTimeOffset.UtcNow.AddMinutes(-policy.FullCheckMinutes);
        // A background sensitive file scan that has finished with new results is reported at once, not at the next
        // quick check.
        bool sensitiveNews =
            sensitiveFiles is { Completion.IsCompleted: true } finished
            && finished.Revision != reportedSensitiveRevision;
        bool due = full || lastLight < DateTimeOffset.UtcNow.AddMinutes(-policy.QuickCheckMinutes);
        if (sensitiveNews && !due && AgentLog.Active)
            Console.WriteLine("敏感文件扫描有新结果，立即上报");
        bool light = due || sensitiveNews;
        if (light)
        {
            // Both scans' names are declared before either reads a volume, so one read of a file table serves both.
            volumes?.Want(VolumeInterest.SensitiveFiles, VolumeInterest.Sensitive(policy.SensitiveFiles));
            volumes?.Want(
                VolumeInterest.ProgramFiles,
                policy.RequiredModules.Contains("programs") ? VolumeInterest.Programs(policy) : null
            );
            if (sensitiveFiles is not null)
            {
                sensitiveFiles.Update(policy.SensitiveFiles, scanCommands.Length > 0, DateTimeOffset.UtcNow);
                // Waited for before the other checks so their results are not aged by a long walk.
                if (waitForSensitiveFiles && policy.SensitiveFiles.Enabled)
                {
                    Console.WriteLine("正在扫描敏感文件名，磁盘文件较多时可能需要几分钟……");
                    await sensitiveFiles.Completion.WaitAsync(ct);
                }
            }
            ScanSnapshot scan = simulated
                ? await FixtureCollector.LoadAsync(fixturePath!, ct)
                : await CollectNativeAsync(config.DeviceId!, policy, full ? null : latest, volumes, ct);
            if (sensitiveFiles is not null)
            {
                reportedSensitiveRevision = sensitiveFiles.Revision;
                var (found, results) = sensitiveFiles.Results(policy.SensitiveFiles, DateTimeOffset.UtcNow);
                scan = scan with { Evidence = [.. scan.Evidence, .. found], Modules = [.. scan.Modules, .. results] };
            }
            browsers?.Apply(policy);
            ControlState[] controls =
                processes is not null && browsers is not null
                    ? [processes.State(policy), browsers.State(policy)]
                    : UnavailableControls.For(
                        policy,
                        simulated ? "模拟终端不执行防护措施" : "非 Windows 环境无法执行防护措施"
                    );
            // Lightweight cadence uses fresh module results only for modules actually collected.
            var moduleResults = policyIssue is null
                ? scan.Modules
                : [.. scan.Modules, new ModuleResult("policy", "agent", "Error", DateTimeOffset.UtcNow, policyIssue)];
            latest = EvidenceSanitizer.Sanitize(
                scan with
                {
                    DeviceId = config.DeviceId!,
                    PolicyVersion = signedPolicy is null ? 0 : policy.Serial,
                    Controls = controls,
                    Modules = moduleResults,
                }
            );
            await TryEnqueueAsync(queue, notices, "Snapshot", "device:" + config.DeviceId, latest, null, ct);
            var report = ReportEngine.Evaluate(policy, latest, DateTimeOffset.UtcNow);
            var findings = BuildLocalFindings(policy, latest, report);
            var scopes = latest
                .Evidence.Where(e => e.UserSid is not null)
                .GroupBy(LocalKey)
                .ToDictionary(g => g.Key, g => g.First().UserSid);
            var changes = await queue.SyncFindingsAsync(findings, report.Verdict == Verdict.PASS, scopes, ct: ct);
            foreach (var change in changes)
            {
                // One notice per finding and user: reminders and the recovery update it instead of piling up.
                await notices.AddAsync(
                    $"finding:{change.ObjectKey}|{change.UserSid}",
                    change.UserSid,
                    $"{change.Type}: {change.Detail}",
                    ct,
                    replace: true
                );
            }
            if (AgentLog.Active)
                Console.WriteLine(
                    $"{(full ? "完整检查" : "快速检查")}完成：{report.Summary}；证据 {report.EvidenceCount} 条，检查缺口 {report.CoverageGaps.Length} 项，策略“{policy.PolicyId}”v{policy.Version}"
                );
            else
                Console.WriteLine(ReportRenderer.Markdown(report));
            lastLight = DateTimeOffset.UtcNow;
            if (full)
                lastFull = lastLight;
            foreach (var command in scanCommands)
                await AckAsync(api, command, new CommandReply(true, "Full scan completed and queued"), ct);
        }
    }

    /// <summary>
    /// Installs the client package an upgrade command names. Only the installed service upgrades: a console run or a
    /// simulation has no installation to replace. A download that fails is tried again at the next check.
    /// </summary>
    private async Task UpgradeAsync(AgentApi api, DeviceCommand command, CancellationToken ct)
    {
        if (
            !OperatingSystem.IsWindows()
            || simulated
            || !Microsoft.Extensions.Hosting.WindowsServices.WindowsServiceHelpers.IsWindowsService()
        )
        {
            await AckAsync(api, command, new CommandReply(false, "只有安装为 Windows 服务的客户端可以远程升级"), ct);
            return;
        }
        Console.WriteLine($"管理端要求升级客户端到 {command.Version}");
        (CommandReply Reply, string? Installer) prepared;
        try
        {
            prepared = await ClientUpgrade.PrepareAsync(
                api,
                command,
                keyId => PolicyKeys.PublicKeyFor(config, keyId),
                config.DataDirectory,
                ct
            );
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException or JsonException)
        {
            Console.Error.WriteLine("客户端安装包下载失败，下次检查时重试：" + e.GetType().Name);
            return;
        }
        Console.WriteLine(prepared.Reply.Detail);
        // The reply goes first: the installer stops this service.
        await AckAsync(api, command, prepared.Reply, ct);
        if (prepared.Installer != null)
            try
            {
                ClientUpgrade.Install(prepared.Installer);
            }
            catch (System.ComponentModel.Win32Exception e)
            {
                // Already answered; the version the next heartbeat reports shows the upgrade did not happen.
                Console.Error.WriteLine("无法启动客户端安装程序：" + e.Message);
            }
    }

    /// <summary>
    /// Answers a command. A reply the server does not take is logged and the command comes again; it never stops the
    /// check or the upload that follow.
    /// </summary>
    private static async Task AckAsync(AgentApi api, DeviceCommand command, CommandReply reply, CancellationToken ct)
    {
        try
        {
            await api.SendAsync<JsonElement>(
                HttpMethod.Post,
                $"/api/agent/commands/{Uri.EscapeDataString(command.Id)}/ack",
                reply,
                ct
            );
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or JsonException)
        {
            Console.Error.WriteLine($"Command {command.Type} reply pending: {e.GetType().Name}");
        }
    }

    /// <summary>
    /// Sends batches until the queue is empty or one fails, so a device back from days offline catches up within the
    /// cycle instead of one batch a minute. Bounded, so checking resumes even when events keep arriving.
    /// </summary>
    private async Task UploadAsync(AgentApi api, EventOutbox queue, NotificationStore notices, CancellationToken ct)
    {
        for (var round = 0; round < 50; round++)
            if (!await UploadBatchAsync(api, queue, notices, ct))
                return;
    }

    /// <summary>Sends one batch; whether all of it was accepted and more may be waiting.</summary>
    private async Task<bool> UploadBatchAsync(
        AgentApi api,
        EventOutbox queue,
        NotificationStore notices,
        CancellationToken ct
    )
    {
        var pending = await queue.PendingBatchAsync(100, 1_500_000, ct);
        if (queue.OversizedInLastBatch > 0)
        {
            await notices.AddAsync(
                Guid.NewGuid().ToString("D"),
                null,
                "有一条记录超出管理端的大小限制，已单独保存；审计记录可能不完整。",
                ct
            );
            await TryEnqueueAsync(
                queue,
                notices,
                "Health",
                "agent:oversized-event",
                null,
                "One or more events were quarantined due to API size limit",
                ct
            );
            if (pending.Length == 0)
                pending = await queue.PendingBatchAsync(100, 1_500_000, ct);
        }
        if (pending.Length == 0)
            return false;
        var result = await EventUpload.SendAsync(
            queue,
            pending,
            (batch, token) => api.SendAsync<EventReceipt>(HttpMethod.Post, "/api/agent/events", batch, token),
            ct
        );
        if (result.Accepted > 0 || result.Refused > 0)
            Console.WriteLine(
                $"已上报 {result.Accepted} 条记录"
                    + (result.Refused > 0 ? $"，{result.Refused} 条未被接收，稍后重试" : "")
            );
        if (result.Failure is { } failure && result.Quarantined == 0)
            Console.WriteLine(
                $"上报失败（{failure.Message}），{pending.Length - result.Accepted - result.Refused} 条记录保存在本地，稍后重试"
            );
        if (result.Quarantined > 0)
        {
            Console.Error.WriteLine($"管理端拒收 {result.Quarantined} 条记录，已单独保存，不再重试");
            await TryEnqueueAsync(
                queue,
                notices,
                "Health",
                "agent:refused-event",
                null,
                $"{result.Quarantined} event(s) refused by the server were quarantined",
                ct
            );
        }
        return result.Failure is null && result.Accepted == pending.Length;
    }

    private static string LocalKey(Evidence e) =>
        e.Kind == EvidenceKind.Proxy
            ? "proxy:" + (e.UserSid ?? "machine") + ":" + e.ObjectKey
            : "product:" + e.ProductId + ":" + (e.UserSid ?? "machine");

    private static Dictionary<string, string> BuildLocalFindings(
        PolicyDocument policy,
        ScanSnapshot snapshot,
        ComplianceReport report
    )
    {
        var now = DateTimeOffset.UtcNow;
        var known = policy.Products.Select(p => p.Id).ToHashSet(StringComparer.Ordinal);
        var findings = new Dictionary<string, string>();
        foreach (var e in snapshot.Evidence)
        {
            if (
                !e.Confirmed
                || e.Kind
                    is not (
                        EvidenceKind.Installation
                        or EvidenceKind.Process
                        or EvidenceKind.Extension
                        or EvidenceKind.Proxy
                    )
                || e.Kind != EvidenceKind.Proxy && !known.Contains(e.ProductId)
            )
                continue;
            var module = e.Kind switch
            {
                EvidenceKind.Installation => "installed",
                EvidenceKind.Extension => "extensions",
                EvidenceKind.Proxy => "proxy",
                _ => "processes",
            };
            var times = snapshot
                .Modules.Where(m => m.Module == module && (m.Scope == e.UserSid || m.Scope == "machine"))
                .Select(m => m.CollectedAt)
                .ToArray();
            var sourceTime = e.CollectedAt ?? (times.Length > 0 ? times.Min() : snapshot.CollectedAt);
            var minutes = e.Kind is EvidenceKind.Installation or EvidenceKind.Extension
                ? policy.InventoryFreshMinutes
                : policy.LightweightFreshMinutes;
            if (sourceTime < now.AddMinutes(-minutes) || sourceTime > now.AddMinutes(2))
                continue;
            findings[LocalKey(e)] = e.ProductName + "：" + e.Summary;
        }
        if (report.CoverageGaps.Length > 0)
            findings["health:coverage"] = "本机的检查或防护未能完全覆盖，请联系管理员查看设备报告。";
        return findings;
    }

    private static Task<ScanSnapshot> CollectNativeAsync(
        string deviceId,
        PolicyDocument policy,
        ScanSnapshot? previous,
        VolumeCatalog? volumes,
        CancellationToken ct
    )
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException();
        return new WindowsCollector(
            volumes is null ? null : v => volumes.Open(v, ct),
            volumes is null ? null : volumes.FirstReadRunning
        ).CollectAsync(deviceId, policy, ct, previous);
    }

    // Direct on purpose: a proxy on this machine is what the client checks for, and one could intercept or block its
    // reports. The tray's connection test connects the same way.
    private static HttpClient CreateInternalClient() =>
        new(new HttpClientHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(30) };
}
