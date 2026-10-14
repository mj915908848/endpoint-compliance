using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Compliance.Agent;

/// <summary>A listening TCP socket and the process that owns it.</summary>
public sealed record PortListener(IPAddress Address, int Port, int Pid, string? ProcessName);

/// <summary>Listening TCP sockets with their owning process, read through iphlpapi's GetExtendedTcpTable.</summary>
public static class TcpListeners
{
    private const int AfInet = 2,
        AfInet6 = 23,
        TcpTableOwnerPidListener = 3,
        ErrorInsufficientBuffer = 122;

    // MIB_TCPROW_OWNER_PID: state, local addr, local port, remote addr, remote port, owning pid (6 x DWORD).
    private const int Row4Size = 24;

    // MIB_TCP6ROW_OWNER_PID: local addr[16], scope, port, remote addr[16], scope, port, state, pid.
    private const int Row6Size = 56;

    [SupportedOSPlatform("windows")]
    public static PortListener[] Read()
    {
        var names = new Dictionary<int, string?>();
        string? Name(int pid)
        {
            if (names.TryGetValue(pid, out var known))
                return known;
            string? name = null;
            try
            {
                using var process = Process.GetProcessById(pid);
                name = process.ProcessName + ".exe";
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
            {
                // Exited between the table read and this lookup.
            }
            return names[pid] = name;
        }
        return
        [
            .. Parse(Table(AfInet), ipv6: false).Select(l => l with { ProcessName = Name(l.Pid) }),
            .. Parse(Table(AfInet6), ipv6: true).Select(l => l with { ProcessName = Name(l.Pid) }),
        ];
    }

    /// <summary>Decodes a TCP_TABLE_OWNER_PID_LISTENER buffer: a DWORD row count followed by fixed-size rows.</summary>
    public static PortListener[] Parse(byte[] table, bool ipv6)
    {
        if (table.Length < 4)
            return [];
        var count = BinaryPrimitives.ReadInt32LittleEndian(table);
        var size = ipv6 ? Row6Size : Row4Size;
        if (count < 0 || 4 + (long)count * size > table.Length)
            throw new InvalidDataException("TCP table truncated");
        var rows = new PortListener[count];
        for (var i = 0; i < count; i++)
        {
            var row = table.AsSpan(4 + i * size, size);
            // Ports are stored in network byte order in the low 16 bits of a DWORD.
            static int Port(ReadOnlySpan<byte> field) => field[0] << 8 | field[1];
            rows[i] = ipv6
                ? new(
                    new IPAddress(row[..16].ToArray()),
                    Port(row[20..]),
                    BinaryPrimitives.ReadInt32LittleEndian(row[52..]),
                    null
                )
                : new(
                    new IPAddress(row[4..8].ToArray()),
                    Port(row[8..]),
                    BinaryPrimitives.ReadInt32LittleEndian(row[20..]),
                    null
                );
        }
        return rows;
    }

    [SupportedOSPlatform("windows")]
    private static byte[] Table(int family)
    {
        var size = 0;
        for (var attempt = 0; attempt < 5; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(Math.Max(size, 4));
            try
            {
                var result = GetExtendedTcpTable(buffer, ref size, false, family, TcpTableOwnerPidListener, 0);
                if (result == ErrorInsufficientBuffer)
                    continue; // size now holds the required length; the table may also have grown meanwhile.
                if (result != 0)
                    throw new IOException($"GetExtendedTcpTable failed: {result}");
                var bytes = new byte[size];
                Marshal.Copy(buffer, bytes, 0, size);
                return bytes;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        throw new IOException("GetExtendedTcpTable kept growing");
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr table,
        ref int size,
        bool order,
        int family,
        int tableClass,
        uint reserved
    );
}
