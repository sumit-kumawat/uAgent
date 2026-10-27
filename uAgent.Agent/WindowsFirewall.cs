using System.Net;
using System.Runtime.Versioning;

namespace uAgent.Agent;

internal sealed record FirewallResult(bool Ok, string Action, string Detail);

// The agent opens outbound HTTPS to the manager and never listens, so it needs no inbound rule. Windows
// allows outbound traffic by default; only when a profile's default outbound action is Block does the
// agent need one rule: outbound, TCP, the manager port, uAgent.exe only (and the manager IP when the
// manager is addressed by IP). The rule has a fixed name so repeated runs update it instead of adding copies.
[SupportedOSPlatform("windows")]
internal static class WindowsFirewall
{
    public const string RuleName = "uAgent - Manager connection (TCP-Out)";
    private const string Description = "Allows the uAgent service to reach its manager. Created by the uAgent installer; removed on uninstall.";

    public static FirewallResult Ensure(Uri manager)
    {
        var (policyCode, policy) = Netsh("advfirewall", "show", "allprofiles", "firewallpolicy");
        if (policyCode != 0)
        {
            return new FirewallResult(false, "Unknown", $"Windows Firewall policy could not be read (netsh exit {policyCode}): {Trim(policy)}");
        }

        var outboundBlocked = policy.Split('\n').Any(line =>
            line.TrimStart().StartsWith("Firewall Policy", StringComparison.OrdinalIgnoreCase) &&
            line.Contains("BlockOutbound", StringComparison.OrdinalIgnoreCase));
        var existing = ShowRule();

        if (!outboundBlocked)
        {
            if (existing is not null)
            {
                Netsh("advfirewall", "firewall", "delete", "rule", $"name={RuleName}");
                return new FirewallResult(true, "Removed", "Outbound traffic is allowed by default on every profile; the uAgent rule is not needed and was removed.");
            }

            return new FirewallResult(true, "NotNeeded", "Outbound traffic is allowed by default on every profile; no rule is needed. No inbound rule is ever required.");
        }

        var program = AgentPaths.InstalledExecutable;
        var port = manager.Port.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var remoteIp = IPAddress.TryParse(manager.Host, out var ip) ? ip.ToString() : "any";
        if (existing is not null && Matches(existing, program, port, remoteIp))
        {
            return new FirewallResult(true, "Unchanged", $"The outbound rule for TCP {port} to {remoteIp} already exists and is correct.");
        }

        if (existing is not null)
        {
            Netsh("advfirewall", "firewall", "delete", "rule", $"name={RuleName}");
        }

        var (code, output) = Netsh("advfirewall", "firewall", "add", "rule",
            $"name={RuleName}", "dir=out", "action=allow", "enable=yes", "profile=any",
            $"program={program}", "protocol=TCP", $"remoteport={port}", $"remoteip={remoteIp}",
            $"description={Description}");
        if (code != 0)
        {
            return new FirewallResult(false, "Failed",
                $"The outbound rule could not be created (netsh exit {code}): {Trim(output)}. If Windows Firewall is managed by Group Policy or Intune, allow {program} outbound to TCP {port} there.");
        }

        var created = ShowRule();
        if (created is null || !Matches(created, program, port, remoteIp))
        {
            return new FirewallResult(false, "Failed", "The outbound rule was added but is not visible. Group Policy may be ignoring local rules (\"Apply local firewall rules: No\"); add the rule in the policy instead.");
        }

        return new FirewallResult(true, existing is null ? "Created" : "Repaired", $"Outbound default is Block, so a rule allowing {Path.GetFileName(program)} to TCP {port} on {remoteIp} was {(existing is null ? "created" : "repaired")}.");
    }

    public static FirewallResult Remove()
    {
        if (ShowRule() is null)
        {
            return new FirewallResult(true, "NotPresent", "No uAgent firewall rule exists.");
        }

        var (code, output) = Netsh("advfirewall", "firewall", "delete", "rule", $"name={RuleName}");
        return code == 0
            ? new FirewallResult(true, "Removed", "The uAgent firewall rule was removed.")
            : new FirewallResult(false, "Failed", $"The uAgent firewall rule could not be removed (netsh exit {code}): {Trim(output)}");
    }

    public static bool Exists() => ShowRule() is not null;

    public static string Describe()
    {
        var rule = ShowRule();
        var (_, policy) = Netsh("advfirewall", "show", "allprofiles", "firewallpolicy");
        var blocked = policy.Contains("BlockOutbound", StringComparison.OrdinalIgnoreCase);
        return (blocked ? "Outbound default: Block on at least one profile. " : "Outbound default: Allow. ") +
               (rule is null ? "No uAgent rule." : "uAgent outbound rule present.");
    }

    private static string? ShowRule()
    {
        var (code, output) = Netsh("advfirewall", "firewall", "show", "rule", $"name={RuleName}", "verbose");
        return code == 0 && output.Contains(RuleName, StringComparison.OrdinalIgnoreCase) ? output : null;
    }

    private static bool Matches(string rule, string program, string port, string remoteIp)
    {
        var occurrences = rule.Split("Rule Name:", StringSplitOptions.None).Length - 1;
        return occurrences == 1 &&
               Field(rule, "Direction").Equals("Out", StringComparison.OrdinalIgnoreCase) &&
               Field(rule, "Action").Equals("Allow", StringComparison.OrdinalIgnoreCase) &&
               Field(rule, "Enabled").Equals("Yes", StringComparison.OrdinalIgnoreCase) &&
               Field(rule, "Program").Equals(program, StringComparison.OrdinalIgnoreCase) &&
               Field(rule, "RemotePort").Equals(port, StringComparison.OrdinalIgnoreCase) &&
               (remoteIp == "any"
                   ? Field(rule, "RemoteIP").Equals("Any", StringComparison.OrdinalIgnoreCase)
                   : Field(rule, "RemoteIP").StartsWith(remoteIp, StringComparison.OrdinalIgnoreCase));
    }

    private static string Field(string rule, string name)
    {
        foreach (var line in rule.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase))
            {
                return trimmed[(name.Length + 1)..].Trim();
            }
        }

        return string.Empty;
    }

    private static (int Code, string Output) Netsh(params string[] args) => ServiceHardening.Run("netsh.exe", args);

    private static string Trim(string text) => text.Length > 300 ? text[..300] + "…" : text;
}
