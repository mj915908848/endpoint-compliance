using Compliance.Core;

namespace Compliance.Server;

/// <summary>
/// The server's services and what they share: the clock, transactions and device lookups. Endpoints reach the
/// services through it.
/// </summary>
public sealed class ComplianceService : IDisposable
{
    readonly Store store;
    readonly Settings settings;
    readonly TimeProvider clock;

    public ComplianceService(Store store, Settings settings, TimeProvider clock)
    {
        this.store = store;
        this.settings = settings;
        this.clock = clock;
        Policies = new(settings, clock);
        Verdicts = new(store, Policies, clock);
        Ingest = new(Verdicts, Policies, clock);
        Housekeeping = new(store, settings, clock);
        Packages = new(settings, clock);
    }

    public PolicyService Policies { get; }
    public VerdictService Verdicts { get; }
    public IngestService Ingest { get; }
    public Housekeeping Housekeeping { get; }
    public PackageService Packages { get; }

    public DateTimeOffset Now => clock.GetUtcNow();

    /// <summary>How long a management session may go without the administrator using the page; null if unlimited.</summary>
    public TimeSpan? SessionIdle =>
        settings.SessionIdleMinutes > 0 ? TimeSpan.FromMinutes(settings.SessionIdleMinutes) : null;

    /// <summary>This server's release version; clients of the same release report the same one.</summary>
    public static readonly string Version = ReleaseVersion.Of(typeof(ComplianceService).Assembly);

    public static string DeviceLock(string deviceId) => "device:" + deviceId;

    public const string EnrollmentLock = "enrollment";

    public async Task Initialize()
    {
        await store.Initialize();
        await Policies.LoadSigningKey();
        await store.Transaction(async tx =>
        {
            await tx.Lock("bootstrap");
            // Renaming the legacy default reassigns devices, like a publish.
            await tx.Lock(PolicyService.PolicyLock);
            foreach (var user in Wire.Read<BootstrapUser[]>(settings.BootstrapUsers))
            {
                if (
                    string.IsNullOrWhiteSpace(user.Username)
                    || user.Username.Length > 100
                    || user.Password.Length < 16
                    || user.Roles.Length == 0
                    || user.Roles.Any(r => !UserRoles.All.Contains(r))
                )
                    throw new InvalidOperationException(
                        "Bootstrap users need names, >=16 character passwords and defined roles"
                    );
                if (await tx.GetUser(user.Username) == null)
                {
                    // Configurations from before accounts were managed on the page name full administrators by
                    // Operator and Publisher; they manage accounts too, as upgraded installations' do.
                    var roles =
                        user.Roles.Contains("Operator") && user.Roles.Contains("Publisher")
                            ? [.. user.Roles.Union([UserRoles.Admin])]
                            : user.Roles;
                    await tx.InsertUser(new UserRecord(user.Username, Secrets.Password(user.Password), roles));
                    await tx.Audit("bootstrap", "CreateUser", user.Username, Now);
                }
            }

            await Policies.Seed(tx);
            return true;
        });
    }

    public Task<T> Tx<T>(Func<Transaction, Task<T>> action) => store.Transaction(action);

    public Task<DeviceRecord> Device(Transaction tx, string id) => tx.RequireDevice(id);

    /// <summary>A device without its controls and snapshot, for requests that need neither.</summary>
    public Task<DeviceRecord> DeviceHead(Transaction tx, string id) => tx.RequireDeviceHead(id);

    public void Dispose() => Policies.Dispose();
}
