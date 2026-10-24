using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace uAgent.Agent;

internal readonly record struct MachineDetails(
    string MachineName,
    string OsVersion,
    string DomainName,
    bool IsDomainJoined,
    TimeSpan Uptime,
    string DnsName,
    IReadOnlyList<string> IpAddresses);

internal static class MachineInfo
{
    public static MachineDetails Capture()
    {
        var properties = IPGlobalProperties.GetIPGlobalProperties();
        var domainName = properties.DomainName.Trim();
        var uptime = TimeSpan.FromMilliseconds(Math.Max(0, Environment.TickCount64));
        return new MachineDetails(
            Environment.MachineName,
            RuntimeInformation.OSDescription,
            domainName,
            domainName.Length > 0,
            uptime,
            ResolveDnsName(properties),
            ActiveIpv4Addresses());
    }

    public static MachineDetails Fallback() =>
        new(
            Environment.MachineName,
            RuntimeInformation.OSDescription,
            string.Empty,
            false,
            TimeSpan.FromMilliseconds(Math.Max(0, Environment.TickCount64)),
            Environment.MachineName,
            []);

    private static string ResolveDnsName(IPGlobalProperties properties)
    {
        try
        {
            var entry = Dns.GetHostEntry(Dns.GetHostName());
            if (!string.IsNullOrWhiteSpace(entry.HostName))
            {
                return entry.HostName.Trim().ToLowerInvariant();
            }
        }
        catch (SocketException)
        {
            // Name resolution is unavailable; fall back to host + primary DNS suffix below.
        }

        var host = properties.HostName.Trim();
        var suffix = properties.DomainName.Trim();
        return (suffix.Length > 0 ? $"{host}.{suffix}" : host).ToLowerInvariant();
    }

    private static IReadOnlyList<string> ActiveIpv4Addresses()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(nic => nic.OperationalStatus == OperationalStatus.Up &&
                              nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(nic => nic.GetIPProperties().UnicastAddresses)
                .Where(address => address.Address.AddressFamily == AddressFamily.InterNetwork)
                .Select(address => address.Address.ToString())
                .Distinct()
                .ToArray();
        }
        catch (NetworkInformationException)
        {
            return [];
        }
    }
}
