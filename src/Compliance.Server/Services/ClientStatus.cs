using Compliance.Core;

namespace Compliance.Server;

/// <summary>
/// What heartbeats say about the client itself: problems it reports with its own health, and how an upgrade it
/// started ended.
/// </summary>
public static class ClientStatus
{
    /// <summary>Waiting events this many or more, for longer than <see cref="BacklogAge"/>, mean uploads are stuck.</summary>
    public const int BacklogEvents = 100;

    public static readonly TimeSpan BacklogAge = TimeSpan.FromMinutes(30);

    /// <summary>An error ending programs counts this long; the loop runs every 2 seconds and retries by itself.</summary>
    public static readonly TimeSpan EnforcementErrorAge = TimeSpan.FromMinutes(10);

    public static string AlertId(string deviceId) => "client-health:" + deviceId;

    /// <summary>The problems <paramref name="h"/> shows at <paramref name="now"/>, in words for administrators.</summary>
    public static string[] Problems(ClientHealth? h, DateTimeOffset now)
    {
        if (h is null)
            return [];
        var problems = new List<string>();
        if (h.Queued >= BacklogEvents && h.OldestQueued is { } oldest && now - oldest >= BacklogAge)
            problems.Add("检查记录积压未上报");
        if (h.Refused > 0)
            problems.Add("有记录被管理端拒收");
        if (h.Dropped > 0)
            problems.Add("本机待上报队列已满，丢弃了较早的检查结果");
        if (h.EnforcementErrorAt is { } at && now - at < EnforcementErrorAge)
            problems.Add("结束禁用程序时出错");
        return [.. problems];
    }

    /// <summary>
    /// Keeps the device's client health alert in step with its latest health: active with the problems it names, and
    /// resolved once there are none. Written only when that changes, not at every heartbeat.
    /// </summary>
    public static async Task UpdateAlert(Transaction tx, DeviceRecord device, ClientHealth health, DateTimeOffset now)
    {
        var id = AlertId(device.Id);
        var problems = Problems(health, now);
        var previous = await tx.GetAlert(id);
        if (problems.Length == 0)
        {
            if (previous?.State == "Active")
                await tx.ResolveAlert(id, now);
            return;
        }
        var summary = "客户端运行异常：" + string.Join("；", problems);
        if (previous is { State: "Active" } && previous.Summary == summary)
            return;
        await tx.UpsertAlert(
            new AlertSummary(
                id,
                device.Id,
                device.HostName,
                "Health",
                "agent:heartbeat",
                summary,
                "Active",
                0,
                previous?.State == "Active" ? previous.FirstSeen : now,
                now,
                previous?.State == "Active" && previous.Acknowledged
            )
        );
    }

    /// <summary>An upgrade answered as started but with no result after this long did not take effect.</summary>
    public static readonly TimeSpan InstallTimeout = TimeSpan.FromHours(1);

    /// <summary>Where one device's upgrade to <paramref name="version"/> stands, and what to show about it.</summary>
    public static (string State, string Detail) Upgrade(
        CommandRecord c,
        DeviceRecord device,
        string version,
        DateTimeOffset now
    )
    {
        if (!ReleaseVersion.Older(device.AgentVersion, version) && device.AgentVersion.Length > 0)
            return ("Succeeded", $"已是 {device.AgentVersion}");
        if (c.Outcome is { } outcome)
            return (outcome.Succeeded ? "Succeeded" : "Failed", outcome.Detail);
        if (c.Reply is { } reply)
        {
            if (!reply.Success)
                return ("Failed", reply.Detail);
            // Clients that do not report outcomes leave only their version to go by.
            return c.RepliedAt is { } at && now - at >= InstallTimeout
                ? ("NotApplied", $"已开始安装，但终端仍是 {Shown(device.AgentVersion)}")
                : ("Installing", reply.Detail);
        }
        return c.Command.ExpiresAt <= now
            ? ("Expired", "终端在一天内没有联系管理端，升级已过期")
            : ("Waiting", "等待终端下载");
    }

    static string Shown(string version) => version.Length > 0 ? version : "旧版本";
}
