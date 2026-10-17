using Compliance.Core;

namespace Compliance.Server;

/// <summary>How many enrolled devices had each stored verdict at the end of one day (or now, for today).</summary>
public sealed record TrendDay(DateOnly Date, int Pass, int Fail, int Unknown);

public static class VerdictTrend
{
    /// <summary>
    /// The last <paramref name="days"/> days up to today, in the time zone <paramref name="offset"/> from UTC.
    /// <paramref name="before"/> holds each device's last change before the first day starts and
    /// <paramref name="changes"/> every later change, oldest first. A device counts from its first verdict on.
    /// </summary>
    public static TrendDay[] Daily(
        DateTimeOffset now,
        int days,
        TimeSpan offset,
        IEnumerable<VerdictChange> before,
        IEnumerable<VerdictChange> changes
    )
    {
        var today = DateOnly.FromDateTime(now.ToOffset(offset).DateTime);
        var state = new Dictionary<string, Verdict>();
        foreach (var c in before.OrderBy(c => c.At))
            state[c.DeviceId] = c.Verdict;
        var pending = new Queue<VerdictChange>(changes.OrderBy(c => c.At));
        var result = new TrendDay[days];
        for (var i = 0; i < days; i++)
        {
            var date = today.AddDays(i - days + 1);
            var end = new DateTimeOffset(date.AddDays(1).ToDateTime(TimeOnly.MinValue), offset);
            while (pending.Count > 0 && pending.Peek().At < end)
            {
                var c = pending.Dequeue();
                state[c.DeviceId] = c.Verdict;
            }
            result[i] = new(
                date,
                state.Values.Count(v => v == Verdict.PASS),
                state.Values.Count(v => v == Verdict.FAIL),
                state.Values.Count(v => v == Verdict.UNKNOWN)
            );
        }
        return result;
    }

    /// <summary>When the first of the last <paramref name="days"/> days starts, in that time zone.</summary>
    public static DateTimeOffset Start(DateTimeOffset now, int days, TimeSpan offset) =>
        new(
            DateOnly.FromDateTime(now.ToOffset(offset).DateTime).AddDays(1 - days).ToDateTime(TimeOnly.MinValue),
            offset
        );
}
