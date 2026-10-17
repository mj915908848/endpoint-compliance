using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Compliance.Core;
using Xunit;

namespace Compliance.Server.Tests;

public class PackageTests
{
    static byte[] Msi(int size = 4096)
    {
        var bytes = RandomNumberGenerator.GetBytes(size);
        PackageCrypto.MsiSignature.CopyTo(bytes);
        return bytes;
    }

    static Task<HttpResponseMessage> Upload(Fixture f, string version, byte[] file)
    {
        var content = new ByteArrayContent(file);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        return f.Client.PostAsync($"/api/client-packages?version={version}", content);
    }

    static async Task<DeviceCommand[]> Commands(Fixture f) =>
        (await (await f.Agent("GET", "/api/agent/commands")).Content.ReadFromJsonAsync<DeviceCommand[]>(Wire.Json))!;

    [Fact]
    public async Task An_uploaded_package_reaches_a_device_signed_and_unchanged()
    {
        await using var f = new Fixture();
        await f.Login();
        var enrolled = await f.Enroll(await f.Code());
        f.Device = enrolled.DeviceId;
        await f.Agent("POST", "/api/agent/heartbeat", new HeartbeatRequest("host", "0.2.8", f.Clock.Now, 1, []));
        var file = Msi();

        Assert.Equal(HttpStatusCode.OK, (await Upload(f, "0.2.30", file)).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await Upload(f, "0.2.30", Msi())).StatusCode);
        var listed = Assert.Single(
            (await f.Client.GetFromJsonAsync<ClientPackageItem[]>("/api/client-packages", Wire.Json))!
        );
        Assert.Equal(("0.2.30", 1), (listed.Version, listed.Outdated));

        var r = await f.Client.PostAsJsonAsync($"/api/devices/{f.Device}/commands", new { type = "Upgrade" });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var command = Assert.Single(await Commands(f));
        Assert.Equal(("Upgrade", "0.2.30"), (command.Type, command.Version));

        var signed = (
            await (
                await f.Agent("GET", "/api/agent/client-packages/0.2.30")
            ).Content.ReadFromJsonAsync<SignedClientPackage>(Wire.Json)
        )!;
        var package = PackageCrypto.Verify(signed, enrolled.PolicyPublicKeyPem);
        var download = await f.Agent("GET", "/api/agent/client-packages/0.2.30/file");
        Assert.Equal(HttpStatusCode.OK, download.StatusCode);
        var bytes = await download.Content.ReadAsByteArrayAsync();
        Assert.Equal(file, bytes);
        Assert.Equal(package.Sha256, Convert.ToHexStringLower(SHA256.HashData(bytes)));
        Assert.Equal(file.Length, package.Size);

        // A package signature does not pass as a policy signature.
        Assert.ThrowsAny<Exception>(() =>
            PolicyCrypto.Verify(
                new SignedPolicy(signed.Payload, signed.Signature, signed.KeyId),
                enrolled.PolicyPublicKeyPem,
                f.Device,
                0,
                f.Clock.Now
            )
        );
    }

    [Fact]
    public async Task Only_publishers_upload_and_only_MSI_files_are_kept()
    {
        await using var f = new Fixture();
        await f.Login("reader");
        Assert.Equal(HttpStatusCode.Forbidden, (await Upload(f, "0.2.30", Msi())).StatusCode);
        await f.Login();
        Assert.Equal(HttpStatusCode.BadRequest, (await Upload(f, "0.2.30", [1, 2, 3, 4, 5, 6, 7, 8, 9])).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Upload(f, "latest", Msi())).StatusCode);
        Assert.Empty((await f.Client.GetFromJsonAsync<ClientPackageItem[]>("/api/client-packages", Wire.Json))!);
        Assert.Empty(Directory.GetFiles(Path.Combine(f.Directory, "client-packages")));
    }

    [Fact]
    public async Task A_rollout_reaches_each_outdated_device_once_and_deleting_removes_the_file()
    {
        await using var f = new Fixture();
        await f.Login();
        var devices = new List<string>();
        foreach (var version in new[] { "0.2.8", "0.2.30", "0.3.0" })
        {
            f.Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            f.Device = (await f.Enroll(await f.Code())).DeviceId;
            await f.Agent("POST", "/api/agent/heartbeat", new HeartbeatRequest("host", version, f.Clock.Now, 1, []));
            devices.Add(f.Device);
        }
        Assert.Equal(HttpStatusCode.OK, (await Upload(f, "0.2.30", Msi())).StatusCode);

        var up = await f.Client.PostAsync("/api/client-packages/0.2.30/rollout", null);
        Assert.Equal(1, (await up.Content.ReadFromJsonAsync<UpgradeRollout>(Wire.Json))!.Queued);
        up = await f.Client.PostAsync("/api/client-packages/0.2.30/rollout", null);
        Assert.Equal(0, (await up.Content.ReadFromJsonAsync<UpgradeRollout>(Wire.Json))!.Queued);
        // A device already on the version is not sent it.
        var r = await f.Client.PostAsJsonAsync($"/api/devices/{devices[2]}/commands", new { type = "Upgrade" });
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);

        Assert.Equal(HttpStatusCode.OK, (await f.Client.DeleteAsync("/api/client-packages/0.2.30")).StatusCode);
        Assert.Empty(Directory.GetFiles(Path.Combine(f.Directory, "client-packages")));
        Assert.Equal(
            HttpStatusCode.NotFound,
            (await f.Agent("GET", "/api/agent/client-packages/0.2.30/file")).StatusCode
        );
    }
}
