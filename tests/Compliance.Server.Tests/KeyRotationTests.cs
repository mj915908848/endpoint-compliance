using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Compliance.Core;
using Xunit;

namespace Compliance.Server.Tests;

public class KeyRotationTests
{
    static async Task<SigningKeyState> State(Fixture f) =>
        (await f.Client.GetFromJsonAsync<SigningKeyState>("/api/settings/signing-key", Wire.Json))!;

    static async Task<SigningKeyState> Read(HttpResponseMessage r)
    {
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<SigningKeyState>(Wire.Json))!;
    }

    static async Task<JsonElement> Heartbeat(Fixture f, params string[] keys)
    {
        var r = await f.Agent(
            "POST",
            "/api/agent/heartbeat",
            new HeartbeatRequest("host", "0.2.30", f.Clock.Now, 1, [], PolicyKeyIds: keys)
        );
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return await r.Content.ReadFromJsonAsync<JsonElement>();
    }

    static async Task<SignedPolicy> Policy(Fixture f) =>
        (await (await f.Agent("GET", "/api/agent/policy")).Content.ReadFromJsonAsync<SignedPolicy>(Wire.Json))!;

    [Fact]
    public async Task Clients_learn_the_next_key_under_the_current_one_and_completion_resigns_everything()
    {
        await using var f = new Fixture();
        await f.Login();
        var first = await f.Enroll(await f.Code());
        var firstKey = f.Key;
        f.Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        f.Device = (await f.Enroll(await f.Code())).DeviceId;
        await Heartbeat(f, first.PolicyKeyId);
        var package = RandomNumberGenerator.GetBytes(4096);
        PackageCrypto.MsiSignature.CopyTo(package);
        var content = new ByteArrayContent(package);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        Assert.Equal(
            HttpStatusCode.OK,
            (await f.Client.PostAsync("/api/client-packages?version=0.2.30", content)).StatusCode
        );

        var idle = await State(f);
        Assert.Equal((first.PolicyKeyId, null), (idle.KeyId, idle.Rotation));
        Assert.Equal(JsonValueKind.Null, (await Heartbeat(f, first.PolicyKeyId)).GetProperty("keyRotation").ValueKind);

        var started = await Read(await f.Client.PostAsync("/api/settings/signing-key/rotation", null));
        var progress = started.Rotation!;
        Assert.Equal((2, 0), (progress.Devices, progress.Ready));
        Assert.Equal(
            HttpStatusCode.Conflict,
            (await f.Client.PostAsync("/api/settings/signing-key/rotation", null)).StatusCode
        );

        // The announcement verifies with the key the device pinned at enrollment.
        var announced = (await Heartbeat(f, first.PolicyKeyId))
            .GetProperty("keyRotation")
            .Deserialize<SignedKeyRotation>(Wire.Json)!;
        var rotation = KeyRotationCrypto.Verify(announced, first.PolicyPublicKeyPem);
        Assert.Equal(progress.NextKeyId, rotation.NewKeyId);
        await Heartbeat(f, first.PolicyKeyId, rotation.NewKeyId);
        progress = (await State(f)).Rotation!;
        Assert.Equal(1, progress.Ready);
        Assert.Equal(first.DeviceId, Assert.Single(progress.Waiting).Id);

        // Policies stay signed with the current key until the rotation completes.
        Assert.Equal(first.PolicyKeyId, (await Policy(f)).KeyId);
        Assert.Equal(first.PolicyKeyId, (await Heartbeat(f, first.PolicyKeyId)).GetProperty("policyKeyId").GetString());
        var waiting = await f.Client.PostAsJsonAsync("/api/settings/signing-key/rotation/complete", new { });
        Assert.Equal(HttpStatusCode.Conflict, waiting.StatusCode);

        var done = await Read(
            await f.Client.PostAsJsonAsync("/api/settings/signing-key/rotation/complete", new { force = true })
        );
        Assert.Equal((rotation.NewKeyId, null), (done.KeyId, done.Rotation));
        Assert.Single(Directory.GetFiles(f.Directory, "policy.pem.retired-*"));
        Assert.False(File.Exists(Path.Combine(f.Directory, "policy.pem.next")));

        var resigned = await Policy(f);
        Assert.Equal(rotation.NewKeyId, resigned.KeyId);
        // The release keeps its serial, so heartbeats name the new key for clients to fetch it again.
        var after = await Heartbeat(f, first.PolicyKeyId, rotation.NewKeyId);
        Assert.Equal(rotation.NewKeyId, after.GetProperty("policyKeyId").GetString());
        Assert.Equal(Wire.Read<PolicyDocument>(resigned.Payload).Serial, after.GetProperty("policySerial").GetInt64());
        PolicyCrypto.Verify(resigned, rotation.NewPublicKeyPem, f.Device, 0, f.Clock.Now);
        Assert.ThrowsAny<CryptographicException>(() =>
            PolicyCrypto.Verify(resigned, first.PolicyPublicKeyPem, f.Device, 0, f.Clock.Now)
        );
        var signedPackage = (
            await (
                await f.Agent("GET", "/api/agent/client-packages/0.2.30")
            ).Content.ReadFromJsonAsync<SignedClientPackage>(Wire.Json)
        )!;
        Assert.Equal(rotation.NewKeyId, signedPackage.KeyId);
        PackageCrypto.Verify(signedPackage, rotation.NewPublicKeyPem);

        // New devices pin the new key.
        f.Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Assert.Equal(rotation.NewKeyId, (await f.Enroll(await f.Code())).PolicyKeyId);
        firstKey.Dispose();
    }

    [Fact]
    public async Task Only_publishers_rotate_and_a_cancelled_rotation_is_no_longer_announced()
    {
        await using var f = new Fixture();
        await f.Login("reader");
        Assert.Equal(HttpStatusCode.Forbidden, (await f.Client.GetAsync("/api/settings/signing-key")).StatusCode);
        Assert.Equal(
            HttpStatusCode.Forbidden,
            (await f.Client.PostAsync("/api/settings/signing-key/rotation", null)).StatusCode
        );
        await f.Login();
        var enrolled = await f.Enroll(await f.Code());
        f.Device = enrolled.DeviceId;
        await Read(await f.Client.PostAsync("/api/settings/signing-key/rotation", null));
        Assert.True(File.Exists(Path.Combine(f.Directory, "policy.pem.next")));

        var cancelled = await Read(await f.Client.DeleteAsync("/api/settings/signing-key/rotation"));
        Assert.Equal((enrolled.PolicyKeyId, null), (cancelled.KeyId, cancelled.Rotation));
        Assert.False(File.Exists(Path.Combine(f.Directory, "policy.pem.next")));
        Assert.Equal(
            JsonValueKind.Null,
            (await Heartbeat(f, enrolled.PolicyKeyId)).GetProperty("keyRotation").ValueKind
        );
        Assert.Equal(
            HttpStatusCode.Conflict,
            (
                await f.Client.PostAsJsonAsync("/api/settings/signing-key/rotation/complete", new { force = true })
            ).StatusCode
        );
    }

    [Fact]
    public async Task A_completion_that_never_committed_is_undone_at_startup()
    {
        await using var f = new Fixture();
        await f.Login();
        var enrolled = await f.Enroll(await f.Code());
        f.Device = enrolled.DeviceId;
        var next = (await Read(await f.Client.PostAsync("/api/settings/signing-key/rotation", null)))
            .Rotation!
            .NextKeyId;

        // The key files as a completion leaves them, with the releases still signed by the old key.
        var key = Path.Combine(f.Directory, "policy.pem");
        File.Move(key, key + ".retired-20260101000000");
        File.Move(key + ".next", key);

        await using var restart = new Fixture(f.Directory, f.Clock);
        restart.Key = f.Key;
        restart.Device = f.Device;
        await restart.Login();
        var state = await State(restart);
        Assert.Equal((enrolled.PolicyKeyId, next), (state.KeyId, state.Rotation?.NextKeyId));
        PolicyCrypto.Verify(await Policy(restart), enrolled.PolicyPublicKeyPem, f.Device, 0, f.Clock.Now);
    }
}
