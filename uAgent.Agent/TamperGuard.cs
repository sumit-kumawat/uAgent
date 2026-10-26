using System.Runtime.Versioning;
using System.ServiceProcess;
using Microsoft.Win32;
using uAgent.Shared;

namespace uAgent.Agent;

// Periodic self-check of the installed agent. It verifies the binary against the hash recorded at install,
// and that the service is still automatic-start, recoverable, administrator-only and pointing at the
// installed binary. Every finding is logged locally and reported to the manager's audit trail.
// Changes that hand control of a SYSTEM service to non-administrators (service binary path, service
// permissions, writable program folders) are restored, which never removes anything administrators can do.
// Choices an administrator may make on purpose (start type, failure recovery) are only reported; they are
// restored by "uAgent.exe /repair" or the portal's Repair action. Nothing is hidden from local administrators.
internal sealed class TamperGuard
{
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);

    private readonly AgentStateStore _state;
    private readonly ILogger<TamperGuard> _logger;
    private AgentIntegrity? _last;
    private DateTime _nextCheckUtc = DateTime.MinValue;

    public TamperGuard(AgentStateStore state, ILogger<TamperGuard> logger)
    {
        _state = state;
        _logger = logger;
    }

    public AgentIntegrity? Current => _last;

    // Returns the latest result and whether it contains something new worth reporting as an event.
    public (AgentIntegrity? Integrity, bool Changed) CheckIfDue(bool force = false)
    {
        if (!OperatingSystem.IsWindows() || !AgentRuntime.IsWindowsService)
        {
            return (null, false);
        }

        if (!force && DateTime.UtcNow < _nextCheckUtc)
        {
            return (_last, false);
        }

        _nextCheckUtc = DateTime.UtcNow + Interval;
        var previous = _last;
        try
        {
            _last = Check();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "The integrity check could not complete.");
            _last = new AgentIntegrity(false, string.Empty, string.Empty, false, "Unknown", false, false,
                [$"The integrity check could not complete: {ex.Message}"], [], DateTime.UtcNow);
        }

        var changed = _last.Repaired.Count > 0 ||
                      !(previous?.Issues ?? []).SequenceEqual(_last.Issues, StringComparer.Ordinal);
        if (_last.Repaired.Count > 0 || _last.Issues.Count > 0)
        {
            _logger.LogWarning(
                "Integrity check: {IssueCount} issue(s), {RepairCount} repaired. {Issues} {Repaired}",
                _last.Issues.Count,
                _last.Repaired.Count,
                string.Join(" ", _last.Issues),
                string.Join(" ", _last.Repaired));
        }

        return (_last, changed);
    }

    [SupportedOSPlatform("windows")]
    private AgentIntegrity Check()
    {
        var issues = new List<string>();
        var repaired = new List<string>();
        var exe = AgentPaths.InstalledExecutable;

        var hash = File.Exists(exe) ? ServiceHardening.Sha256(exe) : string.Empty;
        var expected = _state.Current.InstalledSha256;
        if (hash.Length == 0)
        {
            issues.Add($"The installed agent binary {exe} is missing.");
        }
        else if (expected.Length == 0)
        {
            _state.Update(s => s.InstalledSha256 = hash); // First check after an upgrade from a build that did not record it.
            expected = hash;
        }
        else if (!string.Equals(hash, expected, StringComparison.OrdinalIgnoreCase))
        {
            issues.Add($"uAgent.exe was modified after installation (expected SHA-256 {expected[..12]}…, found {hash[..12]}…). Reinstall the agent from the portal.");
        }

        var running = Environment.ProcessPath ?? string.Empty;
        if (!string.Equals(Path.GetFullPath(running), Path.GetFullPath(exe), StringComparison.OrdinalIgnoreCase))
        {
            issues.Add($"The service is running from {running} instead of {exe}.");
        }

        var signed = hash.Length > 0 && Authenticode.Inspect(exe).Signed;

        using (var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{AgentPaths.ServiceName}"))
        {
            var imagePath = (key?.GetValue("ImagePath") as string ?? string.Empty).Trim().Trim('"');
            if (!string.Equals(imagePath, exe, StringComparison.OrdinalIgnoreCase))
            {
                Repair(repaired, issues, $"The service binary path was changed to '{imagePath}'; restored to {exe}.",
                    "config", AgentPaths.ServiceName, "binPath=", $"\"{exe}\"");
            }
        }

        string startType;
        using (var controller = new ServiceController(AgentPaths.ServiceName))
        {
            startType = controller.StartType.ToString();
            if (controller.StartType != ServiceStartMode.Automatic)
            {
                issues.Add($"The service start type is {startType}, so the agent will not start with Windows. Run 'uAgent.exe /repair' or use Repair in the portal to restore Automatic.");
            }
        }

        var recovery = RecoveryConfigured();
        if (!recovery)
        {
            issues.Add("Service failure recovery is not configured, so the agent will not restart after a failure. Run 'uAgent.exe /repair' or use Repair in the portal to restore it.");
        }

        var (sdCode, sdOutput) = ServiceHardening.Run("sc.exe", "sdshow", AgentPaths.ServiceName);
        var locked = sdCode == 0 && string.Equals(Dacl(sdOutput), Dacl(ServiceHardening.ServiceSddl), StringComparison.OrdinalIgnoreCase);
        if (!locked)
        {
            locked = Repair(repaired, issues, "The service permissions were changed; restored to administrators only.",
                "sdset", AgentPaths.ServiceName, ServiceHardening.ServiceSddl);
        }

        foreach (var (folder, usersRead) in new[] { (AgentPaths.InstallDirectory, true), (AgentPaths.DataDirectory, false) })
        {
            var writers = ServiceHardening.UntrustedWriters(folder);
            if (writers.Count == 0)
            {
                continue;
            }

            var (code, output) = ServiceHardening.Run("icacls.exe", ServiceHardening.DirectoryAclArguments(folder, usersRead));
            if (code == 0)
            {
                repaired.Add($"{folder} was writable by {string.Join(", ", writers)}; permissions restored.");
            }
            else
            {
                issues.Add($"{folder} is writable by {string.Join(", ", writers)} and could not be repaired: {output}");
            }
        }

        return new AgentIntegrity(issues.Count == 0, hash, expected, signed, startType, locked, recovery, issues, repaired, DateTime.UtcNow);
    }

    [SupportedOSPlatform("windows")]
    private static bool Repair(List<string> repaired, List<string> issues, string message, params string[] scArguments)
    {
        var (code, output) = ServiceHardening.Run("sc.exe", scArguments);
        if (code == 0)
        {
            repaired.Add(message);
            return true;
        }

        issues.Add($"{message.Split(';')[0]} and could not be restored: {output}");
        return false;
    }

    // SERVICE_FAILURE_ACTIONS: reset period, two string pointers, action count, action pointer, then (type, delay) pairs.
    [SupportedOSPlatform("windows")]
    private static bool RecoveryConfigured()
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{AgentPaths.ServiceName}");
        if (key?.GetValue("FailureActions") is not byte[] data || data.Length < 28)
        {
            return false;
        }

        var count = BitConverter.ToInt32(data, 12);
        return count > 0 && BitConverter.ToInt32(data, 20) == 1; // SC_ACTION_RESTART
    }

    private static string Dacl(string sddl)
    {
        var text = sddl.Replace("\r", string.Empty).Replace("\n", string.Empty).Trim();
        var start = text.IndexOf("D:", StringComparison.Ordinal);
        if (start < 0)
        {
            return string.Empty;
        }

        var end = text.IndexOf("S:", start, StringComparison.Ordinal);
        return end < 0 ? text[start..] : text[start..end];
    }
}
