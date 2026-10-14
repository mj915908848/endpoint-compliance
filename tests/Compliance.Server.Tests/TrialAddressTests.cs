using Compliance.Server;
using Xunit;

namespace Compliance.Server.Tests;

public class TrialAddressTests
{
    [Theory]
    [InlineData("http://127.0.0.1:5080", false, true)]
    [InlineData("http://192.168.1.15:5080", false, false)]
    [InlineData("http://192.168.1.15:5080", true, true)]
    [InlineData("http://10.1.2.3:6000", true, true)]
    [InlineData("http://8.8.8.8:5080", true, false)]
    [InlineData("http://0.0.0.0:5080", true, false)]
    [InlineData("https://192.168.1.15:5080", true, false)]
    public void Trial_listener_is_explicit_and_private(string url, bool lanEnabled, bool expected) =>
        Assert.Equal(expected, TrialNetwork.IsAllowedListener(url, lanEnabled));
}
