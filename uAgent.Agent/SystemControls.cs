using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using uAgent.Shared;

namespace uAgent.Agent;

internal readonly record struct SystemControlOutcome(
    bool Success,
    string Message,
    bool RestartAgentRequested = false,
    bool StopAgentRequested = false,
    string? UninstallerPath = null);

// Executes system-level remote controls on the local host and returns the real output.
internal static class SystemControls
{
    private const int RestartDelaySeconds = 60;
    private const int NoShutdownInProgress = 1116;

    public static SystemControlOutcome Execute(string commandType, MachineDetails machine, string managerUrl = "")
    {
        return commandType switch
        {
            CommandTypes.Ping => Ping(machine),
            CommandTypes.CollectDiagnostics => new SystemControlOutcome(true, Diagnostics(machine)),
            CommandTypes.RestartComputer => RestartComputer(),
            CommandTypes.CancelRestart => CancelRestart(),
            CommandTypes.RestartAgent => RestartAgent(),
            CommandTypes.StopAgent => StopAgent(),
            CommandTypes.UninstallAgent => PrepareUninstall(),
            CommandTypes.RepairAgent => RepairAgent(managerUrl),
            _ => new SystemControlOutcome(false, $"'{commandType}' is not a system control.")
        };
    }

    private static SystemControlOutcome Ping(MachineDetails machine)
    {
        var processUptime = DateTime.UtcNow - AgentRuntime.StartedUtc;
        var message = string.Create(
            CultureInfo.InvariantCulture,
            $"Pong from {machine.MachineName} ({machine.DnsName}) at {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC. " +
            $"Agent {AgentRuntime.Version} running as {AgentRuntime.ServiceMode} for {FormatDuration(processUptime)}.");
        return new SystemControlOutcome(true, message);
    }

    private static string Diagnostics(MachineDetails machine)
    {
        var builder = new StringBuilder();
        void Line(string label, string value) => builder.Append(label).Append(": ").AppendLine(value);

        Line("Hostname", machine.MachineName);
        Line("DNS name", machine.DnsName);
        Line("IPv4 addresses", machine.IpAddresses.Count > 0 ? string.Join(", ", machine.IpAddresses) : "none");
        Line("Domain", machine.IsDomainJoined ? machine.DomainName : "Workgroup");
        Line("Operating system", machine.OsVersion);
        Line("Architecture", RuntimeInformation.OSArchitecture.ToString());
        Line("Logical processors", Environment.ProcessorCount.ToString(CultureInfo.InvariantCulture));
        Line("System uptime", FormatDuration(machine.Uptime));
        Line(".NET runtime", RuntimeInformation.FrameworkDescription);
        Line("Agent version", AgentRuntime.Version);
        Line("Agent mode", AgentRuntime.ServiceMode);
        Line("Agent memory", $"{Environment.WorkingSet / (1024 * 1024)} MB working set");

        var systemRoot = Path.GetPathRoot(Environment.SystemDirectory);
        if (!string.IsNullOrEmpty(systemRoot))
        {
            try
            {
                var drive = new DriveInfo(systemRoot);
                Line(
                    $"System drive {drive.Name}",
                    $"{drive.AvailableFreeSpace / (1024 * 1024 * 1024)} GB free of {drive.TotalSize / (1024 * 1024 * 1024)} GB");
            }
            catch (IOException ex)
            {
                Line("System drive", $"unavailable ({ex.Message})");
            }
            catch (UnauthorizedAccessException ex)
            {
                Line("System drive", $"unavailable ({ex.Message})");
            }
        }

        return builder.ToString().TrimEnd();
    }

    private static SystemControlOutcome RestartComputer()
    {
        if (!OperatingSystem.IsWindows())
        {
            return new SystemControlOutcome(false, "Restart Computer is only supported on Windows.");
        }

        var (exitCode, output) = RunShutdown(
            $"/r /t {RestartDelaySeconds} /d p:4:1 /c \"Restart requested from the uAgent portal.\"");
        return exitCode == 0
            ? new SystemControlOutcome(true, $"Restart scheduled in {RestartDelaySeconds} seconds. Use Cancel Restart to abort.")
            : new SystemControlOutcome(false, $"shutdown.exe exited with code {exitCode}. {output}".Trim());
    }

    private static SystemControlOutcome CancelRestart()
    {
        if (!OperatingSystem.IsWindows())
        {
            return new SystemControlOutcome(false, "Cancel Restart is only supported on Windows.");
        }

        var (exitCode, output) = RunShutdown("/a");
        return exitCode switch
        {
            0 => new SystemControlOutcome(true, "The pending restart was cancelled."),
            NoShutdownInProgress => new SystemControlOutcome(false, "No restart was pending on this computer."),
            _ => new SystemControlOutcome(false, $"shutdown.exe exited with code {exitCode}. {output}".Trim())
        };
    }

    private static SystemControlOutcome RestartAgent()
    {
        if (!AgentRuntime.IsWindowsService)
        {
            return new SystemControlOutcome(false, "Restart Agent requires the agent to run as the uAgent Windows service.");
        }

        return new SystemControlOutcome(
            true,
            "The agent will exit now and Service Control Manager recovery restarts it in about 60 seconds.",
            RestartAgentRequested: true);
    }

    // A clean stop exits with code 0, so Service Control Manager recovery does not restart it.
    // The service stays stopped until it is started on the host or Windows restarts (start type Automatic).
    private static SystemControlOutcome StopAgent()
    {
        if (!AgentRuntime.IsWindowsService)
        {
            return new SystemControlOutcome(false, "Stop Agent requires the agent to run as the uAgent Windows service.");
        }

        return new SystemControlOutcome(
            true,
            "The uAgent service is stopping. It stays stopped until it is started on the host or Windows restarts.",
            StopAgentRequested: true);
    }

    // Re-applies the installer's service settings from inside the running service (start type, binary path,
    // failure recovery, service permissions, folder permissions, firewall rule) and reports every step.
    private static SystemControlOutcome RepairAgent(string managerUrl)
    {
        if (!OperatingSystem.IsWindows() || !AgentRuntime.IsWindowsService)
        {
            return new SystemControlOutcome(false, "Repair Agent requires the agent to run as the uAgent Windows service.");
        }

        var lines = new List<string>();
        var failed = 0;
        void Run(string label, string file, params string[] args)
        {
            var (code, output) = ServiceHardening.Run(file, args);
            if (code == 0)
            {
                lines.Add($"OK      {label}");
            }
            else
            {
                failed++;
                lines.Add($"FAILED  {label}: {output}");
            }
        }

        var exe = AgentPaths.InstalledExecutable;
        Run("Service start type Automatic and binary path", "sc.exe", "config", AgentPaths.ServiceName, "start=", "auto", "binPath=", $"\"{exe}\"");
        Run("Service failure recovery", "sc.exe", ServiceHardening.FailureArguments);
        Run("Recovery on non-crash failures", "sc.exe", "failureflag", AgentPaths.ServiceName, "1");
        Run("Service permissions (administrators only)", "sc.exe", "sdset", AgentPaths.ServiceName, ServiceHardening.ServiceSddl);
        Run($"Permissions on {AgentPaths.InstallDirectory}", "icacls.exe", ServiceHardening.DirectoryAclArguments(AgentPaths.InstallDirectory, true));
        Run($"Permissions on {AgentPaths.DataDirectory}", "icacls.exe", ServiceHardening.DirectoryAclArguments(AgentPaths.DataDirectory, false));
        if (Uri.TryCreate(managerUrl, UriKind.Absolute, out var manager))
        {
            var firewall = WindowsFirewall.Ensure(manager);
            if (!firewall.Ok)
            {
                failed++;
            }

            lines.Add($"{(firewall.Ok ? "OK     " : "FAILED ")} Windows Firewall ({firewall.Action}): {firewall.Detail}");
        }

        lines.Insert(0, failed == 0 ? "Repair finished; every setting was re-applied." : $"Repair finished with {failed} problem(s).");
        return new SystemControlOutcome(failed == 0, string.Join(Environment.NewLine, lines));
    }

    // The installed binary cannot remove itself while the service runs, so a copy in the system temp folder
    // runs the standard "/uninstall /quiet" path: deregister, stop and delete the service, remove files.
    private static SystemControlOutcome PrepareUninstall()
    {
        if (!OperatingSystem.IsWindows() || !AgentRuntime.IsWindowsService)
        {
            return new SystemControlOutcome(false, "Uninstall Agent requires the agent to run as the uAgent Windows service.");
        }

        var source = AgentPaths.InstalledExecutable;
        if (!File.Exists(source))
        {
            return new SystemControlOutcome(false, $"The installed agent binary {source} was not found.");
        }

        var target = Path.Combine(Path.GetTempPath(), $"uAgent-uninstall-{Guid.NewGuid():N}.exe");
        File.Copy(source, target, overwrite: true);
        return new SystemControlOutcome(
            true,
            "Uninstall started. The agent deregisters, then the service, program files and credentials are removed from this computer.",
            UninstallerPath: target);
    }

    public static void LaunchUninstaller(string path)
    {
        Process.Start(new ProcessStartInfo(path)
        {
            ArgumentList = { "/uninstall", "/quiet" },
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetTempPath()
        });
    }

    private static (int ExitCode, string Output) RunShutdown(string arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "shutdown.exe"),
            Arguments = arguments,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("shutdown.exe could not be started.");
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        if (!process.WaitForExit(30_000))
        {
            process.Kill();
            return (-1, "shutdown.exe did not finish within 30 seconds.");
        }

        return (process.ExitCode, output.Trim());
    }

    private static string FormatDuration(TimeSpan duration)
    {
        if (duration.TotalDays >= 1)
        {
            return string.Create(CultureInfo.InvariantCulture, $"{(int)duration.TotalDays}d {duration.Hours}h {duration.Minutes}m");
        }

        return duration.TotalHours >= 1
            ? string.Create(CultureInfo.InvariantCulture, $"{(int)duration.TotalHours}h {duration.Minutes}m")
            : string.Create(CultureInfo.InvariantCulture, $"{duration.Minutes}m {duration.Seconds}s");
    }
}
