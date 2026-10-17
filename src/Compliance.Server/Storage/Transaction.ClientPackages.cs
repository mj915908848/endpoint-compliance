using System.Data.Common;
using Compliance.Core;

namespace Compliance.Server;

public sealed partial class Transaction
{
    // ---- client packages -----------------------------------------------------------------

    const string PackageColumns = "version, sha256, size, uploaded_at, uploaded_by, payload, signature, key_id";

    static ClientPackageRecord ReadPackage(DbDataReader r) =>
        new(
            new ClientPackage(r.GetString(0), r.GetString(1), Long(r, 2), Time(r, 3)),
            r.GetString(4),
            new SignedClientPackage(r.GetString(5), r.GetString(6), r.GetString(7))
        );

    public Task<ClientPackageRecord?> GetClientPackage(string version) =>
        Single(
            $"SELECT {PackageColumns} FROM client_packages WHERE version = @version",
            ReadPackage,
            ("version", version)
        );

    public Task<List<ClientPackageRecord>> ClientPackages() =>
        Query($"SELECT {PackageColumns} FROM client_packages", ReadPackage);

    public Task InsertClientPackage(ClientPackageRecord p) =>
        Execute(
            $"INSERT INTO client_packages({PackageColumns}) VALUES(@version, @sha, @size, @at, @by, @payload, @signature, @key)",
            ("version", p.Package.Version),
            ("sha", p.Package.Sha256),
            ("size", p.Package.Size),
            ("at", p.Package.UploadedAt),
            ("by", p.UploadedBy),
            ("payload", p.Signed.Payload),
            ("signature", p.Signed.Signature),
            ("key", p.Signed.KeyId)
        );

    public async Task<bool> DeleteClientPackage(string version) =>
        await Execute("DELETE FROM client_packages WHERE version = @version", ("version", version)) > 0;

    public async Task<bool> ClientPackageFileUsed(string sha256) =>
        await Count("SELECT COUNT(*) FROM client_packages WHERE sha256 = @sha", ("sha", sha256)) > 0;
}
