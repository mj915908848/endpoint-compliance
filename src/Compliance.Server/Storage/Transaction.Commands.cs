using System.Data.Common;
using System.Globalization;
using Compliance.Core;

namespace Compliance.Server;

public sealed partial class Transaction
{
    // ---- device commands -----------------------------------------------------------------

    static CommandRecord ReadCommand(DbDataReader r) =>
        new(
            r.GetString(1),
            new DeviceCommand(r.GetString(0), r.GetString(2), Time(r, 3), r.IsDBNull(5) ? null : r.GetString(5)),
            r.IsDBNull(4) ? null : Wire.Read<CommandReply>(r.GetString(4))
        );

    public Task<CommandRecord?> GetCommand(string id) =>
        Single(
            "SELECT id, device_id, type, expires_at, reply, version FROM commands WHERE id = @id",
            ReadCommand,
            ("id", id)
        );

    public Task<List<CommandRecord>> PendingCommands(string deviceId, DateTimeOffset now) =>
        Query(
            "SELECT id, device_id, type, expires_at, reply, version FROM commands WHERE device_id = @device AND reply IS NULL AND expires_at > @now ORDER BY expires_at, id",
            ReadCommand,
            ("device", deviceId),
            ("now", now)
        );

    public Task InsertCommand(CommandRecord c) =>
        Execute(
            "INSERT INTO commands(id, device_id, type, expires_at, reply, version) VALUES(@id, @device, @type, @expires, @reply, @version)",
            ("id", c.Command.Id),
            ("device", c.DeviceId),
            ("type", c.Command.Type),
            ("expires", c.Command.ExpiresAt),
            ("reply", c.Reply is null ? null : Wire.Serialize(c.Reply)),
            ("version", c.Command.Version)
        );

    /// <summary>Devices with an upgrade command not yet answered or expired.</summary>
    public Task<List<string>> DevicesUpgrading(DateTimeOffset now) =>
        Query(
            "SELECT DISTINCT device_id FROM commands WHERE type = 'Upgrade' AND reply IS NULL AND expires_at > @now",
            r => r.GetString(0),
            ("now", now)
        );

    public Task SetCommandReply(string id, CommandReply reply) =>
        Execute("UPDATE commands SET reply = @reply WHERE id = @id", ("reply", Wire.Serialize(reply)), ("id", id));
}
