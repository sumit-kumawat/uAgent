using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace uAgent.Agent;

// Supported Windows service protection: a restricted service DACL, SCM failure recovery, automatic start
// and administrator-only program folders. The installer applies it and the running service re-checks it.
[SupportedOSPlatform("windows")]
internal static class ServiceHardening
{
    public const string Description =
        "Reports this computer to the uAgent manager and runs authorised remote actions. Developed by Sumit Kumawat. © 2026 Sumit Kumawat.";

    // SYSTEM: full control. Administrators: full control. Interactive, service and authenticated users:
    // query status only, so they cannot stop, reconfigure or delete the service. Every change is audited.
    public const string ServiceSddl =
        "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWLOCRRC;;;AU)" +
        "S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)";

    // Restart after 5 s, 10 s, then every 30 s; the failure counter resets after a day without failures.
    public static readonly string[] FailureArguments =
        ["failure", AgentPaths.ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/10000/restart/30000"];

    public const string SystemSid = "*S-1-5-18";
    public const string AdministratorsSid = "*S-1-5-32-544";
    public const string UsersSid = "*S-1-5-32-545";

    private static readonly HashSet<string> TrustedWriters = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-5-18",      // LocalSystem
        "S-1-5-32-544",  // Administrators
        "S-1-3-0",       // CREATOR OWNER (inherit-only)
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" // TrustedInstaller
    };

    public static string[] DirectoryAclArguments(string path, bool allowUsersRead)
    {
        var grants = new List<string> { path, "/inheritance:r", "/grant:r", $"{SystemSid}:(OI)(CI)F", "/grant:r", $"{AdministratorsSid}:(OI)(CI)F" };
        if (allowUsersRead)
        {
            grants.AddRange(["/grant:r", $"{UsersSid}:(OI)(CI)RX"]);
        }

        grants.AddRange(["/T", "/C", "/Q"]);
        return grants.ToArray();
    }

    // Returns the identities, other than SYSTEM/Administrators/TrustedInstaller, that can write to the folder.
    public static IReadOnlyList<string> UntrustedWriters(string path)
    {
        var writers = new List<string>();
        var directory = new DirectoryInfo(path);
        if (!directory.Exists)
        {
            return writers;
        }

        const FileSystemRights write = FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Delete |
                                       FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership | FileSystemRights.WriteAttributes |
                                       FileSystemRights.DeleteSubdirectoriesAndFiles;
        var rules = directory.GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.AccessControlType == AccessControlType.Allow && (rule.FileSystemRights & write) != 0 &&
                !TrustedWriters.Contains(rule.IdentityReference.Value))
            {
                writers.Add(Translate(rule.IdentityReference));
            }
        }

        return writers.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static string Sha256(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    public static (int Code, string Output) Run(string file, params string[] args)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, file))
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var arg in args)
        {
            start.ArgumentList.Add(arg);
        }

        using var process = Process.Start(start) ?? throw new InvalidOperationException($"{file} could not be started.");
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        if (!process.WaitForExit(30_000))
        {
            process.Kill();
            return (-1, $"{file} did not finish within 30 seconds.");
        }

        return (process.ExitCode, output.Trim());
    }

    private static string Translate(IdentityReference identity)
    {
        try
        {
            return identity.Translate(typeof(NTAccount)).Value;
        }
        catch (IdentityNotMappedException)
        {
            return identity.Value;
        }
    }
}
