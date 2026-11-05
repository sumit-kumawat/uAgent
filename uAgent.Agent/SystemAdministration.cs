using System.Diagnostics;
using System.DirectoryServices.AccountManagement;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.ServiceProcess;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using uAgent.Shared;

namespace uAgent.Agent;

// System administration on the host: a read-only snapshot (identity, network, sessions, sign-ins, firewall,
// Remote Desktop, recent events) and the administration commands. Every command validates its input, refuses
// changes that would cut the host off from management, and reads the result back before reporting success.
[SupportedOSPlatform("windows")]
internal static class SystemAdministration
{
    public const string PortalRuleGroup = "uAgent portal";
    private const string RemoteDesktopRuleGroup = "@FirewallAPI.dll,-28752";
    private const string TerminalServerKey = @"SYSTEM\CurrentControlSet\Control\Terminal Server";
    private const string RdpTcpKey = TerminalServerKey + @"\WinStations\RDP-Tcp";
    private const string TerminalServicesPolicyKey = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
    private const string TcpipParametersKey = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
    private const int RestartDelaySeconds = 60;

    private static readonly TimeSpan ShortTimeout = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan LongTimeout = TimeSpan.FromSeconds(180);

    // Stopping these would take the host or its management down; Stop Agent and the firewall controls exist for the others.
    private static readonly HashSet<string> ProtectedServices = new(StringComparer.OrdinalIgnoreCase)
    {
        AgentPaths.ServiceName, "RpcSs", "RpcEptMapper", "DcomLaunch", "LSM", "SamSs", "BFE", "mpssvc", "nsi",
        "EventLog", "PlugPlay", "Power", "gpsvc", "BrokerInfrastructure", "SystemEventsBroker", "CoreMessagingRegistrar"
    };

    private static readonly Regex ServiceName = new(@"^[A-Za-z0-9_.\-$ ]{1,256}$", RegexOptions.CultureInvariant);
    private static readonly Regex NetBiosName = new(@"^(?![0-9]+$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?$", RegexOptions.CultureInvariant);
    private static readonly Regex DnsName = new(@"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$", RegexOptions.CultureInvariant);
    private static readonly Regex DnsSuffix = new(@"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$", RegexOptions.CultureInvariant);
    private static readonly Regex Workgroup = new(@"^[A-Za-z0-9_-]{1,15}$", RegexOptions.CultureInvariant);
    private static readonly Regex PortList = new(@"^(?:Any|(?:\d{1,5}(?:-\d{1,5})?)(?:,\d{1,5}(?:-\d{1,5})?)*)$", RegexOptions.CultureInvariant);
    private static readonly Regex AddressList = new(@"^(?:Any|LocalSubnet|[0-9A-Fa-f:./\-]{2,49}(?:,[0-9A-Fa-f:./\-]{2,49})*)$", RegexOptions.CultureInvariant);
    private static readonly Regex Printable = new(@"^[^\x00-\x1f\x7f]+$", RegexOptions.CultureInvariant);

    // ----------------------------------------------------------------------------------------------------
    // Snapshot

    public static Dictionary<string, object?> Collect(string managerUrl)
    {
        var errors = new List<string>();
        object? Part(string name, Func<object?> read)
        {
            try
            {
                return read();
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                errors.Add($"{name}: {ex.Message}");
                return null;
            }
        }

        var started = Stopwatch.GetTimestamp();
        var snapshot = new Dictionary<string, object?>
        {
            ["platform"] = "Windows",
            ["managerHost"] = Uri.TryCreate(managerUrl, UriKind.Absolute, out var manager) ? manager.Host : null,
            ["computer"] = Part("computer", () => PowerShellRunner.RunJson(ComputerScript, ShortTimeout)),
            ["network"] = Part("network", Network),
            ["connections"] = Part("connections", () => PowerShellRunner.RunJson(ConnectionsScript, ShortTimeout)),
            ["sessions"] = Part("sessions", Sessions),
            ["remoteDesktop"] = Part("remoteDesktop", RemoteDesktop),
            ["localAdministrators"] = Part("localAdministrators", LocalAdministrators),
            ["firewall"] = Part("firewall", () => PowerShellRunner.RunJson(FirewallScript, LongTimeout,
                new Dictionary<string, string> { ["PROTECTED"] = WindowsFirewall.RuleName, ["GROUP"] = PortalRuleGroup })),
            ["events"] = Part("events", () => PowerShellRunner.RunJson(EventsScript, LongTimeout))
        };
        snapshot["errors"] = errors;
        snapshot["collectMs"] = (int)Stopwatch.GetElapsedTime(started).TotalMilliseconds;
        return snapshot;
    }

    private const string ComputerScript = """
        $cs = Get-CimInstance Win32_ComputerSystem
        $os = Get-CimInstance Win32_OperatingSystem
        $tcp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
        $pending = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName').ComputerName
        $active = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName').ComputerName
        $reboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or ($pending -ne $active)
        $roles = 'Standalone workstation','Member workstation','Standalone server','Member server','Backup domain controller','Primary domain controller'
        $fqdn = $null; try { $fqdn = [System.Net.Dns]::GetHostEntry('').HostName } catch { }
        $edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
        [pscustomobject]@{
          hostname = $active; pendingHostname = $pending; fqdn = $fqdn
          primaryDnsSuffix = $tcp.Domain; configuredDnsSuffix = $tcp.'NV Domain'
          searchList = @(($tcp.SearchList -split ',') | Where-Object { $_ })
          partOfDomain = [bool]$cs.PartOfDomain; domain = $cs.Domain; workgroup = $cs.Workgroup; domainRole = $roles[[int]$cs.DomainRole]
          manufacturer = $cs.Manufacturer; model = $cs.Model
          osCaption = $os.Caption; osVersion = $os.Version; osBuild = $os.BuildNumber; edition = $edition; architecture = $os.OSArchitecture
          installDateUtc = $os.InstallDate.ToUniversalTime().ToString('o'); lastBootUtc = $os.LastBootUpTime.ToUniversalTime().ToString('o')
          totalMemoryBytes = [int64]$cs.TotalPhysicalMemory; freeMemoryBytes = [int64]$os.FreePhysicalMemory * 1024
          rebootPending = [bool]$reboot; timeZone = (Get-TimeZone).Id
        } | ConvertTo-Json -Compress -Depth 4
        """;

    private const string ConnectionsScript = """
        $names = @{}; Get-Process | ForEach-Object { $names[[int]$_.Id] = $_.ProcessName }
        $listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -First 400 | ForEach-Object {
          [pscustomobject]@{ protocol = 'TCP'; address = $_.LocalAddress; port = [int]$_.LocalPort; pid = [int]$_.OwningProcess; process = $names[[int]$_.OwningProcess] } })
        $udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -ne '::' -or $_.LocalPort -lt 49152 } | Select-Object -First 200 | ForEach-Object {
          [pscustomobject]@{ protocol = 'UDP'; address = $_.LocalAddress; port = [int]$_.LocalPort; pid = [int]$_.OwningProcess; process = $names[[int]$_.OwningProcess] } })
        $est = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -notin '127.0.0.1','::1' } | Select-Object -First 500 | ForEach-Object {
          [pscustomobject]@{ localAddress = $_.LocalAddress; localPort = [int]$_.LocalPort; remoteAddress = $_.RemoteAddress; remotePort = [int]$_.RemotePort; pid = [int]$_.OwningProcess; process = $names[[int]$_.OwningProcess] } })
        [pscustomobject]@{ listening = @($listen + $udp); established = $est } | ConvertTo-Json -Compress -Depth 4
        """;

    private const string FirewallScript = """
        $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
        $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
          $key = "$pol\$($_.Name)Profile"
          $managed = $false
          if (Test-Path $key) { $managed = $null -ne (Get-ItemProperty $key -ErrorAction SilentlyContinue).EnableFirewall }
          [pscustomobject]@{ name = $_.Name; enabled = ("$($_.Enabled)" -eq 'True'); defaultInbound = "$($_.DefaultInboundAction)"; defaultOutbound = "$($_.DefaultOutboundAction)"
            allowLocalRules = "$($_.AllowLocalFirewallRules)"; notifyOnListen = "$($_.NotifyOnListen)"; logAllowed = "$($_.LogAllowed)"; logBlocked = "$($_.LogBlocked)"; logFile = $_.LogFileName; policyManaged = $managed } })
        $networks = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ interface = $_.InterfaceAlias; network = $_.Name; category = "$($_.NetworkCategory)" } })
        $ports = @{}; Get-NetFirewallPortFilter -All -PolicyStore ActiveStore | ForEach-Object { $ports[$_.InstanceID] = $_ }
        $addresses = @{}; Get-NetFirewallAddressFilter -All -PolicyStore ActiveStore | ForEach-Object { $addresses[$_.InstanceID] = $_ }
        $apps = @{}; Get-NetFirewallApplicationFilter -All -PolicyStore ActiveStore | ForEach-Object { $apps[$_.InstanceID] = $_ }
        $all = @(Get-NetFirewallRule -PolicyStore ActiveStore)
        $rules = @($all | Select-Object -First 3000 | ForEach-Object {
          $p = $ports[$_.InstanceID]; $a = $addresses[$_.InstanceID]; $x = $apps[$_.InstanceID]
          [pscustomobject]@{ id = $_.Name; name = $_.DisplayName; group = $_.DisplayGroup; enabled = ("$($_.Enabled)" -eq 'True')
            direction = "$($_.Direction)"; action = "$($_.Action)"; profile = "$($_.Profile)"; protocol = "$($p.Protocol)"
            localPort = (@($p.LocalPort) -join ','); remotePort = (@($p.RemotePort) -join ','); remoteAddress = (@($a.RemoteAddress) -join ',')
            program = $x.Program; source = "$($_.PolicyStoreSourceType)"; portalManaged = ($_.Group -eq $env:UAGENT_GROUP); protected = ($_.DisplayName -eq $env:UAGENT_PROTECTED) } })
        [pscustomobject]@{ profiles = $profiles; networks = $networks; rules = $rules; ruleCount = $all.Count } | ConvertTo-Json -Compress -Depth 4
        """;

    // Security events need the agent's SYSTEM account; each query is bounded in time and count.
    private const string EventsScript = """
        function Ev([string]$log, [string]$xpath, [int]$max) { try { @(Get-WinEvent -LogName $log -FilterXPath $xpath -MaxEvents $max -ErrorAction Stop) } catch { @() } }
        function Msg($e) { $m = "$($e.Message)"; $m = ($m -split "`r?`n")[0]; if ($m.Length -gt 300) { $m = $m.Substring(0, 300) }; $m }
        function T($e) { $e.TimeCreated.ToUniversalTime().ToString('o') }
        function P($e, [int]$i) { if ($e.Properties.Count -gt $i) { "$($e.Properties[$i].Value)" } else { '' } }
        function Hex($e, [int]$i) { try { '0x{0:X8}' -f [int64]("$($e.Properties[$i].Value)" -replace '^0x','') } catch { P $e $i } }
        $d1 = 86400000; $d7 = 7 * $d1; $d30 = 30 * $d1; $d90 = 90 * $d1
        $skip = '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|DWM-\d+|UMFD-\d+|-|)$'
        $logons = @(Ev 'Security' "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $d30]] and EventData[Data[@Name='LogonType']='2' or Data[@Name='LogonType']='7' or Data[@Name='LogonType']='10' or Data[@Name='LogonType']='11']]" 400 |
          Where-Object { (P $_ 5) -notmatch $skip -and (P $_ 5) -notmatch '\$$' } | Select-Object -First 200 | ForEach-Object {
          [pscustomobject]@{ timeUtc = T $_; user = P $_ 5; domain = P $_ 6; logonType = [int](P $_ 8); workstation = P $_ 11; source = P $_ 18 } })
        $failed = @(Ev 'Security' "*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= $d7]]]" 300 | ForEach-Object {
          [pscustomobject]@{ timeUtc = T $_; user = P $_ 5; domain = P $_ 6; status = Hex $_ 7; subStatus = Hex $_ 9; logonType = [int](P $_ 10); workstation = P $_ 13; source = P $_ 19 } })
        $accountChanges = @(Ev 'Security' "*[System[(EventID=4720 or EventID=4722 or EventID=4725 or EventID=4726 or EventID=4732 or EventID=4733 or EventID=4740 or EventID=4719) and TimeCreated[timediff(@SystemTime) <= $d30]]]" 100 | ForEach-Object {
          [pscustomobject]@{ timeUtc = T $_; id = $_.Id; message = Msg $_ } })
        $power = @(Ev 'System' "*[System[(EventID=41 or EventID=1074 or EventID=1076 or EventID=6005 or EventID=6006 or EventID=6008) and TimeCreated[timediff(@SystemTime) <= $d90]]]" 40 | ForEach-Object {
          [pscustomobject]@{ timeUtc = T $_; id = $_.Id; message = Msg $_ } })
        $serviceChanges = @(Ev 'System' "*[System[(EventID=7040 or EventID=7045) and TimeCreated[timediff(@SystemTime) <= $d30]]]" 60 | ForEach-Object {
          [pscustomobject]@{ timeUtc = T $_; id = $_.Id; message = Msg $_ } })
        $fwLog = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
        $firewallChanges = @(Ev $fwLog "*[System[(EventID=2002 or EventID=2003 or EventID=2004 or EventID=2005 or EventID=2006 or EventID=2033 or EventID=2052 or EventID=2097 or EventID=2099) and TimeCreated[timediff(@SystemTime) <= $d30]]]" 60 | ForEach-Object {
          [pscustomobject]@{ timeUtc = T $_; id = $_.Id; message = Msg $_ } })
        $problems = @(@(Ev 'System' "*[System[(Level=1 or Level=2 or Level=3) and TimeCreated[timediff(@SystemTime) <= $d1]]]" 80) + @(Ev 'Application' "*[System[(Level=1 or Level=2 or Level=3) and TimeCreated[timediff(@SystemTime) <= $d1]]]" 80) |
          Sort-Object TimeCreated -Descending | Select-Object -First 120 | ForEach-Object {
          [pscustomobject]@{ timeUtc = T $_; log = $_.LogName; level = "$($_.LevelDisplayName)"; id = $_.Id; source = $_.ProviderName; message = Msg $_ } })
        $rdpAuth = @(Ev 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' "*[System[(EventID=1149) and TimeCreated[timediff(@SystemTime) <= $d30]]]" 50 | ForEach-Object {
          [pscustomobject]@{ timeUtc = T $_; user = P $_ 0; domain = P $_ 1; source = P $_ 2 } })
        $rdpSessions = @(Ev 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' "*[System[(EventID=21 or EventID=23 or EventID=24 or EventID=25) and TimeCreated[timediff(@SystemTime) <= $d30]]]" 60 | ForEach-Object {
          [pscustomobject]@{ timeUtc = T $_; id = $_.Id; user = P $_ 0; session = P $_ 1; source = P $_ 2 } })
        $rdpFailures = @(Ev 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational' "*[System[(EventID=140) and TimeCreated[timediff(@SystemTime) <= $d7]]]" 50 | ForEach-Object {
          [pscustomobject]@{ timeUtc = T $_; source = P $_ 0; message = Msg $_ } })
        [pscustomobject]@{ logons = $logons; failedLogons = $failed; accountChanges = $accountChanges; power = $power; serviceChanges = $serviceChanges
          firewallChanges = $firewallChanges; problems = $problems; rdpAuthentications = $rdpAuth; rdpSessions = $rdpSessions; rdpFailures = $rdpFailures } | ConvertTo-Json -Compress -Depth 4
        """;

    private static List<object> Network()
    {
        var list = new List<object>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
            {
                continue;
            }

            var ip = nic.GetIPProperties();
            int? index = null;
            bool? dhcp = null;
            try
            {
                var v4 = ip.GetIPv4Properties();
                index = v4.Index;
                dhcp = v4.IsDhcpEnabled;
            }
            catch (NetworkInformationException)
            {
                // IPv4 is not bound to this adapter.
            }

            var mac = nic.GetPhysicalAddress().GetAddressBytes();
            list.Add(new
            {
                index,
                name = nic.Name,
                description = nic.Description,
                type = nic.NetworkInterfaceType.ToString(),
                status = nic.OperationalStatus.ToString(),
                speedMbps = nic.Speed > 0 ? nic.Speed / 1_000_000 : (long?)null,
                mac = mac.Length == 0 ? null : string.Join("-", mac.Select(b => b.ToString("X2", CultureInfo.InvariantCulture))),
                dhcp,
                addresses = ip.UnicastAddresses.Select(a => $"{a.Address}/{a.PrefixLength}").ToList(),
                gateways = ip.GatewayAddresses.Select(g => g.Address.ToString()).Where(g => g != "0.0.0.0").ToList(),
                dnsServers = ip.DnsAddresses.Select(d => d.ToString()).ToList(),
                dnsSuffix = ip.DnsSuffix
            });
        }

        return list;
    }

    private static object RemoteDesktop()
    {
        using var ts = Registry.LocalMachine.OpenSubKey(TerminalServerKey);
        using var rdp = Registry.LocalMachine.OpenSubKey(RdpTcpKey);
        using var policy = Registry.LocalMachine.OpenSubKey(TerminalServicesPolicyKey);
        using var version = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
        var port = rdp?.GetValue("PortNumber") is int p && p > 0 ? p : 3389;
        var listening = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Any(e => e.Port == port);
        var edition = version?.GetValue("EditionID") as string ?? string.Empty;
        var services = new[] { "TermService", "SessionEnv", "UmRdpService" }.Select(name =>
        {
            try
            {
                using var sc = new ServiceController(name);
                return new { name, displayName = sc.DisplayName, status = sc.Status.ToString(), startType = sc.StartType.ToString() };
            }
            catch (InvalidOperationException)
            {
                return new { name, displayName = name, status = "NotInstalled", startType = "None" };
            }
        }).ToList();

        return new
        {
            // Home editions can connect to other computers but cannot accept Remote Desktop connections.
            hostSupported = !edition.Contains("Core", StringComparison.OrdinalIgnoreCase),
            edition,
            enabled = (ts?.GetValue("fDenyTSConnections") as int? ?? 1) == 0,
            policyDenyConnections = policy?.GetValue("fDenyTSConnections") as int?,
            nla = (rdp?.GetValue("UserAuthentication") as int? ?? 0) == 1,
            policyNla = policy?.GetValue("UserAuthentication") as int?,
            securityLayer = rdp?.GetValue("SecurityLayer") as int?,
            port,
            listening,
            services
        };
    }

    private static List<object> LocalAdministrators()
    {
        var list = new List<object>();
        using var machine = new PrincipalContext(ContextType.Machine);
        using var group = GroupPrincipal.FindByIdentity(machine, IdentityType.Sid, "S-1-5-32-544");
        if (group is null)
        {
            return list;
        }

        try
        {
            using var members = group.GetMembers(recursive: false);
            foreach (var member in members)
            {
                using (member)
                {
                    var local = member.ContextType == ContextType.Machine;
                    list.Add(new
                    {
                        name = local ? member.SamAccountName : $"{member.Context?.Name}\\{member.SamAccountName}",
                        kind = member is GroupPrincipal ? "Group" : "User",
                        local,
                        enabled = (member as UserPrincipal)?.Enabled
                    });
                }
            }
        }
        catch (Exception ex) when (ex is PrincipalOperationException or System.Runtime.InteropServices.COMException)
        {
            // A member whose domain cannot be reached; the rest is still listed.
        }

        return list;
    }

    // ----------------------------------------------------------------------------------------------------
    // Sessions (Terminal Services API): console, Remote Desktop and disconnected sessions, plus listeners.

    private static List<object> Sessions()
    {
        var list = new List<object>();
        if (!WTSEnumerateSessionsW(IntPtr.Zero, 0, 1, out var buffer, out var count))
        {
            throw new InvalidOperationException(InstallerProcess.DescribeWindowsError(Marshal.GetLastWin32Error()));
        }

        try
        {
            var size = Marshal.SizeOf<WtsSessionInfo>();
            for (var i = 0; i < count; i++)
            {
                var info = Marshal.PtrToStructure<WtsSessionInfo>(buffer + i * size);
                var station = info.WinStationName ?? string.Empty;
                var user = QueryString(info.SessionId, WtsUserName);
                if (info.SessionId == 0 && user.Length == 0)
                {
                    continue; // Services session.
                }

                var (logon, lastInput, connect) = SessionTimes(info.SessionId);
                list.Add(new
                {
                    id = info.SessionId,
                    station,
                    state = StateName(info.State),
                    user = user.Length == 0 ? null : user,
                    domain = NullIfEmpty(QueryString(info.SessionId, WtsDomainName)),
                    client = NullIfEmpty(QueryString(info.SessionId, WtsClientName)),
                    clientAddress = ClientAddress(info.SessionId),
                    remote = station.StartsWith("RDP-", StringComparison.OrdinalIgnoreCase),
                    logonUtc = logon,
                    connectUtc = connect,
                    lastInputUtc = lastInput
                });
            }
        }
        finally
        {
            WTSFreeMemory(buffer);
        }

        return list;
    }

    private static string StateName(int state) => state switch
    {
        0 => "Active",
        1 => "Connected",
        2 => "Connecting",
        3 => "Shadow",
        4 => "Disconnected",
        5 => "Idle",
        6 => "Listening",
        7 => "Reset",
        8 => "Down",
        9 => "Initializing",
        _ => "Unknown"
    };

    private static string QueryString(int sessionId, int infoClass)
    {
        if (!WTSQuerySessionInformationW(IntPtr.Zero, sessionId, infoClass, out var buffer, out _))
        {
            return string.Empty;
        }

        try
        {
            return Marshal.PtrToStringUni(buffer) ?? string.Empty;
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    private static string? ClientAddress(int sessionId)
    {
        if (!WTSQuerySessionInformationW(IntPtr.Zero, sessionId, WtsClientAddress, out var buffer, out var bytes) || bytes < 8)
        {
            return null;
        }

        try
        {
            var family = Marshal.ReadInt32(buffer);
            if (family != 2)
            {
                return null; // Only AF_INET is filled in reliably.
            }

            var address = new byte[4];
            Marshal.Copy(buffer + 4 + 2, address, 0, 4);
            var ip = new IPAddress(address);
            return ip.Equals(IPAddress.Any) ? null : ip.ToString();
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    // WTSINFOW: the FILETIME fields start at byte 176 (State, SessionId, six counters, three name buffers, padding).
    private static (DateTime? Logon, DateTime? LastInput, DateTime? Connect) SessionTimes(int sessionId)
    {
        if (!WTSQuerySessionInformationW(IntPtr.Zero, sessionId, WtsSessionInfoClass, out var buffer, out var bytes) || bytes < 216)
        {
            return (null, null, null);
        }

        try
        {
            static DateTime? At(IntPtr b, int offset)
            {
                var value = Marshal.ReadInt64(b, offset);
                return value <= 0 ? null : DateTime.FromFileTimeUtc(value);
            }

            return (At(buffer, 184), At(buffer, 176), At(buffer, 192));
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    private static string? NullIfEmpty(string value) => value.Length == 0 ? null : value;

    // ----------------------------------------------------------------------------------------------------
    // Commands

    public static SystemControlOutcome Execute(AgentCommand command, string managerUrl)
    {
        var parameters = command.Parameters ?? new Dictionary<string, string>();
        string Get(string key) => parameters.TryGetValue(key, out var value) ? (value ?? string.Empty).Trim() : string.Empty;
        bool Flag(string key) => string.Equals(Get(key), "true", StringComparison.OrdinalIgnoreCase);
        var secret = command.NewPassword ?? string.Empty;

        SystemControlOutcome outcome;
        try
        {
            outcome = command.CommandType switch
            {
                CommandTypes.ServiceControl => ServiceControl(Get("name"), Get("action")),
                CommandTypes.ShutdownComputer => Shutdown(),
                CommandTypes.SetFirewallProfile => SetFirewallProfile(Get("profile"), Flag("enabled")),
                CommandTypes.FirewallRule => FirewallRule(Get),
                CommandTypes.SetRemoteDesktop => SetRemoteDesktop(Flag("enabled")),
                CommandTypes.SetNla => SetNla(Flag("enabled")),
                CommandTypes.SetHostname => SetHostname(Get("name"), Get("dnsSuffix"), Get("user"), secret, Flag("restart")),
                CommandTypes.SetDns => SetDns(Get("interfaceIndex"), Get("servers"), Flag("setSearchList"), Get("searchList"), Get("testHost"), managerUrl),
                CommandTypes.JoinDomain => JoinDomain(Get("domain"), Get("user"), secret, Get("ouPath"), Flag("restart")),
                CommandTypes.LeaveDomain => LeaveDomain(Get("user"), secret, Get("workgroup"), Flag("restart")),
                _ => Fail($"'{command.CommandType}' is not a system administration command.")
            };
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or UnauthorizedAccessException or IOException
                                       or System.ComponentModel.Win32Exception or System.Security.SecurityException or JsonException
                                       or System.ServiceProcess.TimeoutException or KeyNotFoundException or FormatException)
        {
            outcome = Fail(ex.Message);
        }

        // Defence in depth: a domain password never leaves the host, even inside an error PowerShell echoed.
        return secret.Length == 0
            ? outcome
            : outcome with { Message = outcome.Message.Replace(secret, "********", StringComparison.Ordinal) };
    }

    private static SystemControlOutcome Ok(string message) => new(true, message);

    private static SystemControlOutcome Fail(string message) => new(false, message);

    private static SystemControlOutcome ServiceControl(string name, string action)
    {
        action = action.ToLowerInvariant();
        if (!ServiceName.IsMatch(name))
        {
            return Fail("Enter the service name (not the display name).");
        }

        if (action is not ("start" or "stop" or "restart"))
        {
            return Fail("The action must be start, stop or restart.");
        }

        if (ProtectedServices.Contains(name) && action != "start")
        {
            return Fail(string.Equals(name, AgentPaths.ServiceName, StringComparison.OrdinalIgnoreCase)
                ? "Use Restart agent or Stop agent for the uAgent service."
                : $"{name} is essential to Windows or to remote management and cannot be stopped from the portal. Use the firewall controls for the Windows Firewall service.");
        }

        using var service = new ServiceController(name);
        ServiceControllerStatus status;
        try
        {
            status = service.Status;
        }
        catch (InvalidOperationException)
        {
            return Fail($"There is no service named {name} on this computer.");
        }

        var wait = TimeSpan.FromSeconds(60);
        var dependents = service.DependentServices.Where(d => d.Status != ServiceControllerStatus.Stopped).Select(d => d.ServiceName).ToList();
        if (action is "stop" or "restart")
        {
            if (status != ServiceControllerStatus.Stopped)
            {
                if (!service.CanStop)
                {
                    return Fail($"{service.DisplayName} does not accept a stop request in its current state ({status}).");
                }

                service.Stop();
                service.WaitForStatus(ServiceControllerStatus.Stopped, wait);
            }
            else if (action == "stop")
            {
                return Ok($"{service.DisplayName} ({name}) was already stopped.");
            }
        }

        if (action is "start" or "restart")
        {
            service.Refresh();
            if (service.StartType == ServiceStartMode.Disabled)
            {
                return Fail($"{service.DisplayName} is disabled. Change its startup type on the host before starting it.");
            }

            if (service.Status != ServiceControllerStatus.Running)
            {
                service.Start();
                service.WaitForStatus(ServiceControllerStatus.Running, wait);
            }
            else if (action == "start")
            {
                return Ok($"{service.DisplayName} ({name}) was already running.");
            }

            if (action == "restart")
            {
                foreach (var dependent in dependents)
                {
                    using var dep = new ServiceController(dependent);
                    if (dep.Status == ServiceControllerStatus.Stopped && dep.StartType != ServiceStartMode.Disabled)
                    {
                        dep.Start();
                    }
                }
            }
        }

        service.Refresh();
        var note = dependents.Count > 0 && action != "start" ? $" Dependent services {(action == "restart" ? "restarted" : "stopped")}: {string.Join(", ", dependents)}." : string.Empty;
        return Ok($"{service.DisplayName} ({name}) is now {service.Status}.{note}");
    }

    private static SystemControlOutcome Shutdown()
    {
        var (code, output) = ServiceHardening.Run("shutdown.exe", "/s", "/t", RestartDelaySeconds.ToString(CultureInfo.InvariantCulture), "/d", "p:4:1", "/c", "Shutdown requested from the uAgent portal.");
        return code == 0
            ? Ok($"Shutdown scheduled in {RestartDelaySeconds} seconds. Use Cancel restart to abort. The computer stays off until it is powered on locally or through its management controller.")
            : Fail($"shutdown.exe exited with code {code}. {output}".Trim());
    }

    private static SystemControlOutcome SetFirewallProfile(string profile, bool enabled)
    {
        if (profile is not ("Domain" or "Private" or "Public"))
        {
            return Fail("The profile must be Domain, Private or Public.");
        }

        var result = PowerShellRunner.RunJson("""
            Set-NetFirewallProfile -Name $env:UAGENT_PROFILE -Enabled ([bool]::Parse($env:UAGENT_ENABLED))
            $local = Get-NetFirewallProfile -Name $env:UAGENT_PROFILE
            $active = Get-NetFirewallProfile -Name $env:UAGENT_PROFILE -PolicyStore ActiveStore
            [pscustomobject]@{ local = "$($local.Enabled)"; effective = "$($active.Enabled)" } | ConvertTo-Json -Compress
            """, ShortTimeout, new Dictionary<string, string> { ["PROFILE"] = profile, ["ENABLED"] = enabled ? "true" : "false" });
        var effective = result.GetProperty("effective").GetString();
        var wanted = enabled ? "True" : "False";
        if (!string.Equals(effective, wanted, StringComparison.OrdinalIgnoreCase))
        {
            return Fail($"The local {profile} profile setting was saved, but Group Policy keeps the firewall {(effective == "True" ? "on" : "off")} for this profile. Change it in the policy instead.");
        }

        return Ok($"Windows Firewall {profile} profile is now {(enabled ? "on" : "off")}. {(enabled ? string.Empty : "Traffic on networks of this type is no longer filtered by Windows Firewall.")}".Trim());
    }

    private static SystemControlOutcome FirewallRule(Func<string, string> get)
    {
        var op = get("op").ToLowerInvariant();
        var id = get("id");
        if (op is "enable" or "disable" or "remove" or "update")
        {
            if (id.Length is 0 or > 300 || !Printable.IsMatch(id))
            {
                return Fail("Choose the firewall rule.");
            }
        }

        var variables = new Dictionary<string, string> { ["ID"] = id, ["PROTECTED"] = WindowsFirewall.RuleName, ["GROUP"] = PortalRuleGroup };
        if (op is "add" or "update")
        {
            var problem = RuleSpec(get, variables);
            if (problem is not null)
            {
                return Fail(problem);
            }
        }

        const string Lookup = """
            $r = Get-NetFirewallRule -Name $env:UAGENT_ID -ErrorAction SilentlyContinue
            if (-not $r) { throw 'The rule was not found in the local firewall store. Rules applied by Group Policy are changed in the policy.' }
            """;
        const string PortalOnly = "if ($r.Group -ne $env:UAGENT_GROUP) { throw 'Only rules created from the uAgent portal can be modified or removed. Other rules can be enabled or disabled.' }\n";
        const string NotProtected = "if ($r.DisplayName -eq $env:UAGENT_PROTECTED) { throw 'This rule keeps the agent connected to the portal and cannot be changed from the portal.' }\n";
        const string Spec = """
            $a = @{ DisplayName = $env:UAGENT_NAME; Direction = $env:UAGENT_DIRECTION; Action = $env:UAGENT_ACTION; Protocol = $env:UAGENT_PROTOCOL; Profile = @($env:UAGENT_PROFILE -split ','); Description = $env:UAGENT_DESCRIPTION }
            if ($env:UAGENT_PORTS -eq 'true') { $a.LocalPort = @($env:UAGENT_LOCALPORT -split ','); $a.RemotePort = @($env:UAGENT_REMOTEPORT -split ',') }
            $a.RemoteAddress = @($env:UAGENT_REMOTEADDRESS -split ',')
            if ($env:UAGENT_PROGRAM) { $a.Program = $env:UAGENT_PROGRAM }
            """;
        const string Show = "$o = Get-NetFirewallRule -Name $id; [pscustomobject]@{ id = $o.Name; name = $o.DisplayName; enabled = \"$($o.Enabled)\" } | ConvertTo-Json -Compress";

        var script = op switch
        {
            "add" => Spec + "$r = New-NetFirewallRule @a -Group $env:UAGENT_GROUP -Enabled True; $id = $r.Name\n" + Show,
            // Set-NetFirewallRule takes the new name as -NewDisplayName; an empty program clears the program condition.
            "update" => Lookup + PortalOnly + Spec + "$a.Remove('DisplayName'); if (-not $a.Program) { $a.Program = 'Any' }; Set-NetFirewallRule -Name $env:UAGENT_ID @a -NewDisplayName $env:UAGENT_NAME; $id = $env:UAGENT_ID\n" + Show,
            "remove" => Lookup + PortalOnly + "Remove-NetFirewallRule -Name $env:UAGENT_ID; [pscustomobject]@{ id = $env:UAGENT_ID; name = $r.DisplayName; enabled = 'Removed' } | ConvertTo-Json -Compress",
            "enable" => Lookup + "Enable-NetFirewallRule -Name $env:UAGENT_ID; $id = $env:UAGENT_ID\n" + Show,
            "disable" => Lookup + NotProtected + "Disable-NetFirewallRule -Name $env:UAGENT_ID; $id = $env:UAGENT_ID\n" + Show,
            _ => null
        };
        if (script is null)
        {
            return Fail("The operation must be add, update, remove, enable or disable.");
        }

        var result = PowerShellRunner.RunJson(script, ShortTimeout, variables);
        var name = result.GetProperty("name").GetString();
        var state = result.GetProperty("enabled").GetString();
        return op switch
        {
            "add" => Ok($"Firewall rule \"{name}\" was created and is enabled."),
            "update" => Ok($"Firewall rule \"{name}\" was updated."),
            "remove" => Ok($"Firewall rule \"{name}\" was removed."),
            _ => Ok($"Firewall rule \"{name}\" is now {(state == "True" ? "enabled" : "disabled")}.")
        };
    }

    private static string? RuleSpec(Func<string, string> get, Dictionary<string, string> variables)
    {
        var name = get("name");
        var direction = get("direction");
        var action = get("action");
        var protocol = get("protocol");
        var profile = get("profile");
        var localPort = get("localPort");
        var remotePort = get("remotePort");
        var remoteAddress = get("remoteAddress");
        var program = get("program");
        if (name.Length is 0 or > 200 || !Printable.IsMatch(name))
        {
            return "Give the rule a name of up to 200 characters.";
        }

        if (direction is not ("Inbound" or "Outbound") || action is not ("Allow" or "Block"))
        {
            return "Direction must be Inbound or Outbound and action Allow or Block.";
        }

        if (protocol is not ("TCP" or "UDP" or "Any" or "ICMPv4" or "ICMPv6"))
        {
            return "Protocol must be TCP, UDP, ICMPv4, ICMPv6 or Any.";
        }

        var profiles = profile.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (profiles.Length == 0 || profiles.Any(p => p is not ("Any" or "Domain" or "Private" or "Public")) || (profiles.Contains("Any") && profiles.Length > 1))
        {
            return "Profile must be Any, or one or more of Domain, Private and Public.";
        }

        var ports = protocol is "TCP" or "UDP";
        localPort = localPort.Length == 0 ? "Any" : localPort.Replace(" ", string.Empty, StringComparison.Ordinal);
        remotePort = remotePort.Length == 0 ? "Any" : remotePort.Replace(" ", string.Empty, StringComparison.Ordinal);
        if (ports && (!ValidPorts(localPort) || !ValidPorts(remotePort)))
        {
            return "Ports must be Any, a port (443), a range (5000-5100) or a comma-separated list of those, between 1 and 65535.";
        }

        if (!ports && (localPort != "Any" || remotePort != "Any"))
        {
            return "Ports apply only to TCP and UDP rules.";
        }

        remoteAddress = remoteAddress.Length == 0 ? "Any" : remoteAddress.Replace(" ", string.Empty, StringComparison.Ordinal);
        if (!AddressList.IsMatch(remoteAddress))
        {
            return "Remote address must be Any, LocalSubnet, or IP addresses, ranges (10.0.0.1-10.0.0.9) or subnets (10.0.0.0/8), comma-separated.";
        }

        if (program.Length > 0 && (program.Length > 400 || !Printable.IsMatch(program) || !Path.IsPathFullyQualified(program)))
        {
            return "The program must be a full path, for example C:\\Program Files\\App\\app.exe.";
        }

        variables["NAME"] = name;
        variables["DIRECTION"] = direction;
        variables["ACTION"] = action;
        variables["PROTOCOL"] = protocol;
        variables["PROFILE"] = string.Join(",", profiles);
        variables["PORTS"] = ports ? "true" : "false";
        variables["LOCALPORT"] = localPort;
        variables["REMOTEPORT"] = remotePort;
        variables["REMOTEADDRESS"] = remoteAddress;
        variables["PROGRAM"] = program;
        variables["DESCRIPTION"] = "Created from the uAgent portal.";
        return null;
    }

    private static bool ValidPorts(string value)
    {
        if (!PortList.IsMatch(value))
        {
            return false;
        }

        if (value == "Any")
        {
            return true;
        }

        foreach (var part in value.Split(','))
        {
            var bounds = part.Split('-').Select(p => int.Parse(p, CultureInfo.InvariantCulture)).ToArray();
            if (bounds.Any(b => b is < 1 or > 65535) || (bounds.Length == 2 && bounds[0] > bounds[1]))
            {
                return false;
            }
        }

        return true;
    }

    private static SystemControlOutcome SetRemoteDesktop(bool enabled)
    {
        using (var version = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
        {
            if (enabled && (version?.GetValue("EditionID") as string ?? string.Empty).Contains("Core", StringComparison.OrdinalIgnoreCase))
            {
                return Fail("This Windows edition (Home) cannot accept Remote Desktop connections.");
            }
        }

        using (var policy = Registry.LocalMachine.OpenSubKey(TerminalServicesPolicyKey))
        {
            if (policy?.GetValue("fDenyTSConnections") is int deny && (deny == 0) != enabled)
            {
                return Fail($"Group Policy {(deny == 0 ? "allows" : "denies")} Remote Desktop connections on this computer, so a local change has no effect. Change the policy \"Allow users to connect remotely by using Remote Desktop Services\".");
            }
        }

        var lines = new List<string>();
        using (var key = Registry.LocalMachine.OpenSubKey(TerminalServerKey, writable: true) ?? throw new InvalidOperationException("The Terminal Server registry key is missing."))
        {
            key.SetValue("fDenyTSConnections", enabled ? 0 : 1, RegistryValueKind.DWord);
        }

        lines.Add(enabled ? "Remote Desktop connections are allowed." : "New Remote Desktop connections are refused; sessions that are already open continue until they sign out.");
        var rules = PowerShellRunner.Run(
            "if ($env:UAGENT_ENABLED -eq 'true') { Enable-NetFirewallRule -Group $env:UAGENT_GROUP } else { Disable-NetFirewallRule -Group $env:UAGENT_GROUP }",
            new Dictionary<string, string> { ["ENABLED"] = enabled ? "true" : "false", ["GROUP"] = RemoteDesktopRuleGroup }, ShortTimeout);
        lines.Add(rules.Success
            ? $"The built-in Remote Desktop firewall rules are {(enabled ? "enabled" : "disabled")}."
            : $"WARNING: the Remote Desktop firewall rules could not be changed: {rules.Error}");

        if (!enabled)
        {
            return Ok(string.Join(Environment.NewLine, lines));
        }

        using (var service = new ServiceController("TermService"))
        {
            if (service.StartType == ServiceStartMode.Disabled)
            {
                ServiceHardening.Run("sc.exe", "config", "TermService", "start=", "demand");
                lines.Add("Remote Desktop Services was disabled and is now set to start manually.");
            }

            service.Refresh();
            if (service.Status != ServiceControllerStatus.Running)
            {
                service.Start();
                service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(60));
            }

            lines.Add("Remote Desktop Services is running.");
        }

        using var rdp = Registry.LocalMachine.OpenSubKey(RdpTcpKey);
        var port = rdp?.GetValue("PortNumber") is int p && p > 0 ? p : 3389;
        var listening = false;
        for (var i = 0; i < 20 && !listening; i++)
        {
            listening = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Any(e => e.Port == port);
            if (!listening)
            {
                Thread.Sleep(1000);
            }
        }

        lines.Add(listening ? $"The computer is listening on TCP {port}." : $"WARNING: nothing is listening on TCP {port} yet. Check the Remote Desktop Services service.");
        return new SystemControlOutcome(listening, string.Join(Environment.NewLine, lines));
    }

    private static SystemControlOutcome SetNla(bool enabled)
    {
        using (var policy = Registry.LocalMachine.OpenSubKey(TerminalServicesPolicyKey))
        {
            if (policy?.GetValue("UserAuthentication") is int forced && (forced == 1) != enabled)
            {
                return Fail($"Group Policy {(forced == 1 ? "requires" : "does not require")} Network Level Authentication, so a local change has no effect. Change the policy \"Require user authentication for remote connections by using Network Level Authentication\".");
            }
        }

        using var key = Registry.LocalMachine.OpenSubKey(RdpTcpKey, writable: true) ?? throw new InvalidOperationException("The RDP-Tcp listener is not configured on this computer.");
        var lines = new List<string>();
        if (enabled && key.GetValue("SecurityLayer") is int layer && layer == 0)
        {
            key.SetValue("SecurityLayer", 1, RegistryValueKind.DWord);
            lines.Add("The security layer was RDP, which cannot carry Network Level Authentication; it is now Negotiate.");
        }

        key.SetValue("UserAuthentication", enabled ? 1 : 0, RegistryValueKind.DWord);
        var now = key.GetValue("UserAuthentication") as int? ?? -1;
        if (now != (enabled ? 1 : 0))
        {
            return Fail("The setting did not persist.");
        }

        lines.Insert(0, enabled
            ? "Network Level Authentication is required. Users authenticate before a session is created."
            : "Network Level Authentication is no longer required. The sign-in screen is shown before authentication, which exposes the computer to more risk.");
        lines.Add("The change applies to new connections.");
        return Ok(string.Join(Environment.NewLine, lines));
    }

    private static SystemControlOutcome SetHostname(string name, string dnsSuffix, string user, string secret, bool restart)
    {
        if (!NetBiosName.IsMatch(name))
        {
            return Fail("The computer name must be 1-15 letters, digits or hyphens, must not be only digits, and must not start or end with a hyphen.");
        }

        if (dnsSuffix.Length > 0 && !DnsSuffix.IsMatch(dnsSuffix))
        {
            return Fail("The DNS suffix must be a domain name such as corp.example.com.");
        }

        if (user.Length > 0 && (user.Length > 256 || !Printable.IsMatch(user) || secret.Length == 0))
        {
            return Fail("Enter the domain account and its password, or leave both empty.");
        }

        var lines = new List<string>();
        var current = Environment.MachineName;
        if (!string.Equals(name, current, StringComparison.OrdinalIgnoreCase))
        {
            var rename = PowerShellRunner.Run("""
                $a = @{ NewName = $env:UAGENT_NAME; Force = $true; WarningAction = 'SilentlyContinue' }
                if ($env:UAGENT_USER) { $s = ConvertTo-SecureString $env:UAGENT_SECRET -AsPlainText -Force; Remove-Item Env:\UAGENT_SECRET; $a.DomainCredential = New-Object System.Management.Automation.PSCredential($env:UAGENT_USER, $s) }
                Rename-Computer @a
                """, new Dictionary<string, string> { ["NAME"] = name, ["USER"] = user, ["SECRET"] = secret }, LongTimeout);
            if (!rename.Success)
            {
                return Fail($"The computer could not be renamed: {rename.Error}");
            }

            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName");
            var pending = key?.GetValue("ComputerName") as string;
            if (!string.Equals(pending, name, StringComparison.OrdinalIgnoreCase))
            {
                return Fail($"Windows accepted the rename but the pending name reads {pending ?? "nothing"}.");
            }

            lines.Add($"The computer will be named {name.ToUpperInvariant()} (now {current}) after it restarts.");
        }

        if (dnsSuffix.Length > 0)
        {
            using var tcp = Registry.LocalMachine.OpenSubKey(TcpipParametersKey, writable: true) ?? throw new InvalidOperationException("The TCP/IP parameters key is missing.");
            tcp.SetValue("NV Domain", dnsSuffix, RegistryValueKind.String);
            lines.Add($"The primary DNS suffix is set to {dnsSuffix}; the full name becomes {name.ToLowerInvariant()}.{dnsSuffix} after a restart. On a domain member the suffix normally follows the domain.");
        }

        if (lines.Count == 0)
        {
            return Ok($"The computer is already named {current}; nothing was changed.");
        }

        return Ok(string.Join(Environment.NewLine, lines) + ScheduleRestart(restart, "The new name"));
    }

    private static SystemControlOutcome SetDns(string interfaceIndex, string servers, bool setSearchList, string searchList, string testHost, string managerUrl)
    {
        if (!int.TryParse(interfaceIndex, NumberStyles.None, CultureInfo.InvariantCulture, out var index) || index <= 0)
        {
            return Fail("Choose the network adapter.");
        }

        var list = servers.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var dhcp = list.Length == 1 && string.Equals(list[0], "dhcp", StringComparison.OrdinalIgnoreCase);
        if (!dhcp && (list.Length is 0 or > 6 || list.Any(s => !IPAddress.TryParse(s, out _))))
        {
            return Fail("Enter one to six DNS server IP addresses separated by commas, or \"dhcp\" to obtain them automatically.");
        }

        var suffixes = searchList.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (setSearchList && (suffixes.Length > 20 || suffixes.Any(s => !DnsSuffix.IsMatch(s))))
        {
            return Fail("Search domains must be domain names such as corp.example.com, separated by commas.");
        }

        // The change is kept only if this computer can still resolve the manager (or the chosen test name).
        var probe = testHost;
        if (probe.Length == 0 && Uri.TryCreate(managerUrl, UriKind.Absolute, out var manager) && manager.HostNameType == UriHostNameType.Dns)
        {
            probe = manager.Host;
        }

        if (probe.Length > 0 && !DnsName.IsMatch(probe))
        {
            return Fail("The test name must be a DNS name such as uagent.corp.example.com.");
        }

        var result = PowerShellRunner.RunJson("""
            $i = [int]$env:UAGENT_INDEX
            $adapter = Get-NetAdapter -InterfaceIndex $i -ErrorAction Stop
            $ifKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($adapter.InterfaceGuid)"
            $static = "$((Get-ItemProperty $ifKey -ErrorAction SilentlyContinue).NameServer)"
            $tcp = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            $oldSearch = "$((Get-ItemProperty $tcp).SearchList)"
            $before = @((Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv4).ServerAddresses)
            if ($env:UAGENT_DHCP -eq 'true') { Set-DnsClientServerAddress -InterfaceIndex $i -ResetServerAddresses } else { Set-DnsClientServerAddress -InterfaceIndex $i -ServerAddresses @($env:UAGENT_SERVERS -split ',') }
            if ($env:UAGENT_SETSEARCH -eq 'true') { Set-ItemProperty $tcp -Name SearchList -Value $env:UAGENT_SEARCH }
            Clear-DnsClientCache
            $ok = $true; $detail = ''
            if ($env:UAGENT_PROBE) { try { Resolve-DnsName -Name $env:UAGENT_PROBE -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null } catch { $ok = $false; $detail = $_.Exception.Message } }
            if (-not $ok) {
              if ($static) { Set-DnsClientServerAddress -InterfaceIndex $i -ServerAddresses @($static -split '[, ]' | Where-Object { $_ }) } else { Set-DnsClientServerAddress -InterfaceIndex $i -ResetServerAddresses }
              if ($env:UAGENT_SETSEARCH -eq 'true') { Set-ItemProperty $tcp -Name SearchList -Value $oldSearch }
              Clear-DnsClientCache
            }
            [pscustomobject]@{ ok = $ok; detail = $detail; adapter = $adapter.Name; before = $before; after = @((Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv4).ServerAddresses); search = "$((Get-ItemProperty $tcp).SearchList)" } | ConvertTo-Json -Compress
            """, ShortTimeout, new Dictionary<string, string>
        {
            ["INDEX"] = index.ToString(CultureInfo.InvariantCulture),
            ["DHCP"] = dhcp ? "true" : "false",
            ["SERVERS"] = string.Join(",", list),
            ["SETSEARCH"] = setSearchList ? "true" : "false",
            ["SEARCH"] = string.Join(",", suffixes),
            ["PROBE"] = probe
        });

        string Join(string property) => result.GetProperty(property).ValueKind == JsonValueKind.Array
            ? string.Join(", ", result.GetProperty(property).EnumerateArray().Select(e => e.GetString()))
            : result.GetProperty(property).GetString() ?? string.Empty;
        var adapterName = result.GetProperty("adapter").GetString();
        if (!result.GetProperty("ok").GetBoolean())
        {
            return Fail($"With the new DNS settings {probe} could not be resolved ({result.GetProperty("detail").GetString()}), so the previous settings were restored on {adapterName}: {Join("after")}.");
        }

        var lines = new List<string>
        {
            $"DNS servers on {adapterName}: {(Join("after") is { Length: > 0 } after ? after : "none")} (were {(Join("before") is { Length: > 0 } before ? before : "none")}){(dhcp ? ", obtained automatically" : string.Empty)}."
        };
        if (setSearchList)
        {
            lines.Add($"Search domains: {(Join("search") is { Length: > 0 } search ? search : "none (the primary and connection suffixes are used)")}.");
        }

        if (probe.Length > 0)
        {
            lines.Add($"{probe} still resolves.");
        }

        return Ok(string.Join(Environment.NewLine, lines));
    }

    private static SystemControlOutcome JoinDomain(string domain, string user, string secret, string ouPath, bool restart)
    {
        if (!DnsName.IsMatch(domain))
        {
            return Fail("Enter the domain's DNS name, for example corp.example.com.");
        }

        if (user.Length is 0 or > 256 || !Printable.IsMatch(user) || secret.Length == 0)
        {
            return Fail("Enter an account allowed to join computers to the domain (DOMAIN\\user or user@domain) and its password.");
        }

        if (ouPath.Length > 0 && (ouPath.Length > 1024 || !Printable.IsMatch(ouPath) || !ouPath.Contains("DC=", StringComparison.OrdinalIgnoreCase)))
        {
            return Fail("The OU must be a distinguished name such as OU=Workstations,DC=corp,DC=example,DC=com.");
        }

        if (DomainJoined())
        {
            return Fail("This computer is already a domain member. Leave the current domain first.");
        }

        var join = PowerShellRunner.Run("""
            try { Resolve-DnsName -Name ('_ldap._tcp.dc._msdcs.' + $env:UAGENT_DOMAIN) -Type SRV -DnsOnly -ErrorAction Stop | Out-Null }
            catch { throw ('No domain controller for ' + $env:UAGENT_DOMAIN + ' is registered in DNS (' + $_.Exception.Message + '). Point this computer at the domain DNS servers first.') }
            $s = ConvertTo-SecureString $env:UAGENT_SECRET -AsPlainText -Force; Remove-Item Env:\UAGENT_SECRET
            $a = @{ DomainName = $env:UAGENT_DOMAIN; Credential = (New-Object System.Management.Automation.PSCredential($env:UAGENT_USER, $s)); Force = $true; WarningAction = 'SilentlyContinue' }
            if ($env:UAGENT_OU) { $a.OUPath = $env:UAGENT_OU }
            Add-Computer @a
            """, new Dictionary<string, string> { ["DOMAIN"] = domain, ["USER"] = user, ["SECRET"] = secret, ["OU"] = ouPath }, LongTimeout);
        if (!join.Success)
        {
            return Fail($"The computer did not join {domain}: {join.Error}");
        }

        return Ok($"The computer joined {domain}{(ouPath.Length > 0 ? $" in {ouPath}" : string.Empty)}. Domain sign-in and policies apply after a restart." + ScheduleRestart(restart, "The domain membership"));
    }

    private static SystemControlOutcome LeaveDomain(string user, string secret, string workgroup, bool restart)
    {
        workgroup = workgroup.Length == 0 ? "WORKGROUP" : workgroup;
        if (!Workgroup.IsMatch(workgroup))
        {
            return Fail("The workgroup name must be 1-15 letters, digits, hyphens or underscores.");
        }

        if (!DomainJoined())
        {
            return Fail("This computer is not a domain member.");
        }

        if (user.Length is 0 or > 256 || !Printable.IsMatch(user) || secret.Length == 0)
        {
            return Fail("Enter a domain account allowed to remove the computer from the domain and its password.");
        }

        // Without an enabled local administrator, nobody could sign in to manage the computer afterwards.
        var localAdmins = LocalAdministrators().Select(o => JsonSerializer.SerializeToElement(o))
            .Count(e => e.GetProperty("local").GetBoolean() && e.GetProperty("kind").GetString() == "User" &&
                        e.GetProperty("enabled").ValueKind == JsonValueKind.True);
        if (localAdmins == 0)
        {
            return Fail("No enabled local administrator account exists. Enable or create one first, so the computer can still be managed after it leaves the domain.");
        }

        var leave = PowerShellRunner.Run("""
            $s = ConvertTo-SecureString $env:UAGENT_SECRET -AsPlainText -Force; Remove-Item Env:\UAGENT_SECRET
            Remove-Computer -UnjoinDomainCredential (New-Object System.Management.Automation.PSCredential($env:UAGENT_USER, $s)) -WorkgroupName $env:UAGENT_WORKGROUP -Force -WarningAction SilentlyContinue
            """, new Dictionary<string, string> { ["USER"] = user, ["SECRET"] = secret, ["WORKGROUP"] = workgroup }, LongTimeout);
        if (!leave.Success)
        {
            return Fail($"The computer did not leave the domain: {leave.Error}");
        }

        return Ok($"The computer left the domain and joins workgroup {workgroup} after a restart. Domain accounts can no longer sign in; {localAdmins} enabled local administrator account(s) remain." + ScheduleRestart(restart, "The change"));
    }

    private static bool DomainJoined()
    {
        var status = NetGetJoinInformation(null, out var buffer, out var joinStatus);
        if (buffer != IntPtr.Zero)
        {
            NetApiBufferFree(buffer);
        }

        return status == 0 && joinStatus == 3; // NetSetupDomainName
    }

    private static string ScheduleRestart(bool restart, string subject)
    {
        if (!restart)
        {
            return $" {subject} takes effect at the next restart.";
        }

        var (code, output) = ServiceHardening.Run("shutdown.exe", "/r", "/t", RestartDelaySeconds.ToString(CultureInfo.InvariantCulture), "/d", "p:4:2", "/c", "Restart requested from the uAgent portal to apply a configuration change.");
        return code == 0
            ? $" A restart is scheduled in {RestartDelaySeconds} seconds (Cancel restart aborts it)."
            : $" The restart could not be scheduled (shutdown.exe exit {code}: {output}); restart the computer to apply it.";
    }

    // ----------------------------------------------------------------------------------------------------
    // Native interop

    private const int WtsUserName = 5;
    private const int WtsDomainName = 7;
    private const int WtsClientName = 10;
    private const int WtsClientAddress = 14;
    private const int WtsSessionInfoClass = 24;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WtsSessionInfo
    {
        public int SessionId;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? WinStationName;
        public int State;
    }

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSEnumerateSessionsW(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQuerySessionInformationW(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetGetJoinInformation(string? server, out IntPtr name, out int status);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);
}
