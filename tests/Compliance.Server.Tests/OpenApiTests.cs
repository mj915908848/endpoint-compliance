using System.Net;
using Xunit;

namespace Compliance.Server.Tests;

public class OpenApiTests
{
    // The UI's types are generated from this copy (npm run api in ui/).
    static readonly string Copy = Path.Combine(RepositoryRoot(), "ui", "openapi.json");

    [Fact]
    public async Task The_UI_copy_of_the_API_document_matches_the_server()
    {
        await using var f = new Fixture();
        Assert.Equal(HttpStatusCode.Unauthorized, (await f.Client.GetAsync(ApiDocument.Path)).StatusCode);
        await f.Login("reader");
        var r = await f.Client.GetAsync(ApiDocument.Path);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var served = (await r.Content.ReadAsStringAsync()).ReplaceLineEndings("\n").TrimEnd() + "\n";
        if (Environment.GetEnvironmentVariable("UPDATE_OPENAPI") == "1")
            await File.WriteAllTextAsync(Copy, served);
        var copy = File.Exists(Copy) ? (await File.ReadAllTextAsync(Copy)).ReplaceLineEndings("\n") : "";
        Assert.True(
            copy == served,
            "ui/openapi.json differs from the API the server describes. Run UPDATE_OPENAPI=1 dotnet test "
                + "--filter OpenApiTests, then npm run api in ui/, and commit both."
        );
    }

    static string RepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "global.json")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Repository root not found");
    }
}
