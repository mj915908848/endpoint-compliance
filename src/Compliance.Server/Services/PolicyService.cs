using System.Collections.Concurrent;
using System.Security.Cryptography;
using Compliance.Core;

namespace Compliance.Server;

/// <summary>The policy signing key, policies and their releases, and which release each device follows.</summary>
public sealed partial class PolicyService(Settings settings, TimeProvider clock) : IDisposable
{
    readonly ECDsa signer = ECDsa.Create();

    // Completing a key rotation replaces the key in place; this keeps signing and exporting from seeing it half done.
    readonly Lock signing = new();

    public string PublicKey
    {
        get
        {
            lock (signing)
                return signer.ExportSubjectPublicKeyInfoPem();
        }
    }
    public string KeyId
    {
        get
        {
            lock (signing)
                return IdOf(signer);
        }
    }

    static string IdOf(ECDsa key) => Secrets.Hash(key.ExportSubjectPublicKeyInfoPem())[..16];

    DateTimeOffset Now => clock.GetUtcNow();

    /// <summary>
    /// Held by everything that publishes or reassigns policies, and by enrollment. Taken after "bootstrap" and
    /// <see cref="ComplianceService.EnrollmentLock"/>, never before them.
    /// </summary>
    public const string PolicyLock = "policy";
    public const string DefaultPolicy = "default";

    /// <summary>Names the default policy had in earlier versions; renamed to "Default" at startup.</summary>
    static readonly string[] LegacyDefaultNames = ["customer-no-foreign-ai", "endpoint-compliance"];

    /// <summary>
    /// Loads the signing key, creating it on first start. A rotation's completion, or its undo, stopped between its two
    /// moves leaves no key, the new one pending and the old one retired; the old key goes back, since the transaction
    /// re-signing the releases never committed.
    /// </summary>
    public async Task LoadSigningKey()
    {
        if (string.IsNullOrWhiteSpace(settings.SigningKeyPath))
            throw new InvalidOperationException("Configure a durable Compliance:SigningKeyPath");

        Directory.CreateDirectory(Path.GetDirectoryName(KeyPath)!);
        if (!File.Exists(KeyPath))
        {
            if (File.Exists(NextKeyPath) && NewestRetired() is { } retired)
                File.Move(retired, KeyPath);
            else
                CreateKeyFile(KeyPath);
        }
        Replace(await File.ReadAllTextAsync(KeyPath));
        await LoadNextKey();
    }

    /// <summary>A new P-256 private key in a file only this account can read.</summary>
    static void CreateKeyFile(string path)
    {
        using var created = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using var stream = new FileStream(path, options);
        using var writer = new StreamWriter(stream);
        writer.Write(created.ExportECPrivateKeyPem());
    }

    /// <summary>
    /// At startup, under <see cref="PolicyLock"/>: seeds the first release, or checks the key matches the stored ones.
    /// </summary>
    public async Task Seed(Transaction tx)
    {
        var current = await tx.CurrentRelease();
        if (current != null && current.KeyId != KeyId && !await RecoverRotation(current.KeyId))
            throw new InvalidOperationException(
                "Configured signing key does not match persisted policy; restore original key"
            );
        if (current == null)
        {
            var doc = PolicySeed.Create() with
            {
                Mode = "Audit",
                Version = 1,
                Sequence = 1,
                IssuedAt = Now,
                ExpiresAt = Now + PolicyValidity,
            };
            await tx.InsertRelease(1, Sign(doc), Now);
            await tx.Audit("bootstrap", "SeedAuditPolicy", "1", Now);
        }
        else
            await RenameLegacyDefault(tx);
    }

    public sealed record PolicyState(string Key, SignedPolicy Release, PolicyDocument Document)
    {
        public bool IsDefault => Key == DefaultPolicy;
    }

    public async Task<List<PolicyState>> All(Transaction tx) =>
        (await tx.LatestReleases())
            .Select(r => new PolicyState(r.Key, r.Release, Wire.Read<PolicyDocument>(r.Release.Payload)))
            .OrderBy(p => p.IsDefault ? 0 : 1)
            .ThenBy(p => p.Document.PolicyId, StringComparer.CurrentCultureIgnoreCase)
            .ToList();

    /// <summary>The default policy's newest release: it applies to every device no other policy names.</summary>
    public async Task<SignedPolicy> CurrentRelease(Transaction tx) =>
        (await All(tx)).FirstOrDefault(p => p.IsDefault)?.Release
        ?? throw new InvalidOperationException("No policy release; database was not initialized");

    /// <summary>A device follows the named policy that lists it, otherwise the default policy.</summary>
    public static PolicyState PolicyFor(string deviceId, List<PolicyState> policies) =>
        policies.FirstOrDefault(p => !p.IsDefault && p.Document.TargetDeviceIds.Contains(deviceId))
        ?? policies.First(p => p.IsDefault);

    /// <summary>
    /// Points every device at the newest release of its policy. Agents refuse a lower serial than they hold, so a
    /// policy that devices move to from a newer release is first re-issued under a new serial; its own version, which
    /// administrators see, stays the same since its content does.
    /// </summary>
    async Task Reassign(Transaction tx)
    {
        var policies = await All(tx);
        var devices = await tx.AllDeviceHeads();
        foreach (
            var stale in policies
                .Where(p =>
                    devices.Any(d => d.TargetPolicyVersion > p.Document.Serial && PolicyFor(d.Id, policies) == p)
                )
                .ToList()
        )
        {
            var doc = stale.Document with
            {
                Sequence = await NextSerial(tx),
                IssuedAt = Now,
                ExpiresAt = Now + PolicyValidity,
            };
            await tx.InsertRelease(doc.Serial, Sign(doc), Now, stale.Key);
            await tx.Audit("system", "ReissuePolicy", $"{doc.PolicyId} v{doc.Version}", Now);
        }
        policies = await All(tx);
        foreach (var d in devices)
        {
            var serial = PolicyFor(d.Id, policies).Document.Serial;
            if (d.TargetPolicyVersion != serial)
                await tx.SetTargetPolicy(d.Id, serial);
        }
    }

    /// <summary>Releases are stored under their serial, so the newest release overall holds the highest.</summary>
    async Task<long> NextSerial(Transaction tx) =>
        Wire.Read<PolicyDocument>((await tx.CurrentRelease())!.Payload).Serial + 1;

    async Task RenameLegacyDefault(Transaction tx)
    {
        var current = (await All(tx)).FirstOrDefault(p => p.IsDefault)?.Document;
        // A legacy release limited to pilot devices keeps its name until an administrator republishes it.
        if (
            current == null
            || !LegacyDefaultNames.Contains(current.PolicyId)
            || current.TargetDeviceIds.Length > 0
            || current.Mode != "Audit"
        )
            return;
        var doc = current with
        {
            PolicyId = "Default",
            Version = current.Version + 1,
            Sequence = await NextSerial(tx),
            IssuedAt = Now,
            ExpiresAt = Now + PolicyValidity,
        };
        await tx.InsertRelease(doc.Serial, Sign(doc), Now);
        await tx.Audit("bootstrap", "RenameDefaultPolicy", "v" + doc.Version, Now);
        await Reassign(tx);
    }

    public async Task<SignedPolicy> AssignedPolicy(Transaction tx, DeviceRecord device) =>
        await tx.GetRelease(device.TargetPolicyVersion) ?? throw new ApiError(409, "Assigned policy unavailable");

    /// <summary>Policies stay valid this long after publishing; agents treat an expired policy as unknown.</summary>
    public static readonly TimeSpan PolicyValidity = TimeSpan.FromDays(365);

    /// <summary>
    /// Publishes a new release of the policy <paramref name="key"/>, or creates a policy when the key is null.
    /// The server owns the version and validity; the default policy always covers every other device. With
    /// <paramref name="baseVersion"/>, publishing fails with 409 when the policy has had another release since.
    /// </summary>
    public async Task<(string Key, SignedPolicy Release)> Publish(
        Transaction tx,
        string? key,
        PolicyDocument? submitted,
        long? baseVersion = null
    )
    {
        if (submitted == null)
            throw new ApiError(400, "策略内容为空");
        var policies = await All(tx);
        var existing =
            key == null
                ? null
                : policies.FirstOrDefault(p => p.Key == key) ?? throw new ApiError(404, "策略不存在或已删除");
        if (existing != null && baseVersion is { } based && based != existing.Document.Version)
            throw new ApiError(
                409,
                $"“{existing.Document.PolicyId}”已被他人更新为 v{existing.Document.Version}，请载入最新版本后再修改"
            );
        var isDefault = existing?.IsDefault ?? false;
        var doc = submitted with
        {
            SchemaVersion = Wire.SchemaVersion,
            PolicyId = submitted.PolicyId?.Trim() ?? "",
            // Each policy counts its own releases; the serial orders releases of every policy.
            Version = (existing?.Document.Version ?? 0) + 1,
            Sequence = await NextSerial(tx),
            IssuedAt = Now,
            ExpiresAt = Now + PolicyValidity,
            DenyInstalled = true,
            DenyProxy = true,
            RequiredControls = Controls.Normalize(submitted.RequiredControls),
            // A result counts as current until two check intervals have passed.
            LightweightFreshMinutes = submitted.QuickCheckMinutes * 2,
            InventoryFreshMinutes = submitted.FullCheckMinutes * 2,
            TargetDeviceIds = isDefault ? [] : (submitted.TargetDeviceIds ?? []).Distinct().ToArray(),
        };
        if (
            doc.RequiredModules == null
            || doc.RequiredModules.Length == 0
            || doc.Products == null
            || doc.BlockDomains == null
            || doc.BlockDomains.Length > 1000
            || doc.ApplicationRules == null
            || doc.ApplicationRules.Length > 1000
        )
            throw new ApiError(400, "策略不完整：至少需要一个必需检查项");
        try
        {
            PolicyCrypto.Validate(doc);
        }
        catch (ArgumentException e)
        {
            throw new ApiError(400, "策略内容无效：" + e.Message);
        }
        var others = policies.Where(p => p.Key != key).ToList();
        if (others.Any(p => string.Equals(p.Document.PolicyId, doc.PolicyId, StringComparison.OrdinalIgnoreCase)))
            throw new ApiError(409, $"已有名为“{doc.PolicyId}”的策略，请换一个名称");
        if (isDefault && doc.Mode == "Enforce")
            throw new ApiError(409, "默认策略适用于所有终端，只能使用审计模式；强制模式请新建策略并指定试点终端");
        if (!isDefault)
        {
            if (doc.TargetDeviceIds.Length == 0)
                throw new ApiError(400, "请选择这份策略适用的终端；未指定的终端使用默认策略");
            foreach (var id in doc.TargetDeviceIds)
                if (others.FirstOrDefault(p => !p.IsDefault && p.Document.TargetDeviceIds.Contains(id)) is { } taken)
                    throw new ApiError(
                        409,
                        $"终端 {(await tx.GetDevice(id))?.HostName ?? id} 已在策略“{taken.Document.PolicyId}”中，一台终端只能使用一份策略"
                    );
        }
        await ValidateEnforcement(tx, doc);
        key ??= "p-" + Guid.NewGuid().ToString("N")[..12];
        await tx.InsertPolicy(key, Now);
        var signed = Sign(doc);
        await tx.InsertRelease(doc.Serial, signed, Now, key);
        await Reassign(tx);
        return (key, signed);
    }

    /// <summary>Deletes a named policy; its devices fall back to the default policy.</summary>
    public async Task<string> DeletePolicy(Transaction tx, string key)
    {
        var policy = (await All(tx)).FirstOrDefault(p => p.Key == key) ?? throw new ApiError(404, "策略不存在或已删除");
        if (policy.IsDefault)
            throw new ApiError(409, "默认策略不能删除");
        await tx.DeletePolicy(key, Now);
        await Reassign(tx);
        return policy.Document.PolicyId;
    }

    /// <summary>
    /// Enforcement starts only on pilot devices that are online with a fresh real scan and report every required
    /// measure as ready (or already in effect) under the policy they hold now.
    /// </summary>
    async Task ValidateEnforcement(Transaction tx, PolicyDocument doc)
    {
        if (doc.Mode != "Enforce")
            return;

        if (doc.TargetDeviceIds.Length == 0 || doc.RequiredControls.Length == 0)
            throw new ApiError(409, "强制模式需要指定试点终端，并选择至少一项防护措施");
        if (doc.RequiredControls.Contains(Controls.Process) && !doc.Products.Any(p => p.ExecutableNames.Length > 0))
            throw new ApiError(409, "“发现即结束进程”需要至少一个填写了程序文件名的禁用产品");
        if (doc.RequiredControls.Contains(Controls.Browser) && doc.BlockDomains.Length == 0)
            throw new ApiError(409, "“浏览器网址拦截”需要至少一个禁止访问的域名");
        foreach (var id in doc.TargetDeviceIds)
        {
            var d = await tx.RequireDevice(id);
            if (
                DeviceStatus.Online(d, Now) != "Online"
                || d.Snapshot == null
                || d.Snapshot.Simulated
                || d.Snapshot.CollectedAt < Now.AddMinutes(-10)
            )
                throw new ApiError(409, $"试点终端 {d.HostName} 需要在线，且 10 分钟内有真实（非模拟）的检查结果");
            foreach (var control in doc.RequiredControls)
            {
                var c = d.Controls?.FirstOrDefault(x => x.Id == control);
                if (
                    c == null
                    || !c.Verified
                    || c.RebootRequired
                    || c.Version != d.TargetPolicyVersion
                    || c.State is not ("Ready" or "Applied" or "Verified")
                )
                    throw new ApiError(
                        409,
                        $"试点终端 {d.HostName} 的“{Labels.Control(control)}”尚不可用：{c?.Detail ?? "终端未上报，请更新客户端"}"
                    );
            }
        }
    }

    public SignedPolicy Sign(PolicyDocument doc)
    {
        lock (signing)
            return PolicyCrypto.Sign(doc, signer, IdOf(signer));
    }

    public SignedClientPackage Sign(ClientPackage package)
    {
        lock (signing)
            return PackageCrypto.Sign(package, signer, IdOf(signer));
    }

    void Replace(string pem)
    {
        lock (signing)
            signer.ImportFromPem(pem);
    }

    public void Dispose()
    {
        signer.Dispose();
        next?.Dispose();
    }
}
