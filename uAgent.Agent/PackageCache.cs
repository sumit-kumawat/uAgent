using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using uAgent.Shared;

namespace uAgent.Agent;

// %ProgramData%\uAgent\packages: installers downloaded for portal deployments, named <sha256>.<msi|exe>.
// Only SYSTEM and Administrators can read or write it, so a standard user cannot swap a verified installer.
[SupportedOSPlatform("windows")]
internal static class PackageCache
{
    public const long LimitBytes = 4L * 1024 * 1024 * 1024;
    private const int KeptInstallLogs = 50;

    public static string Directory => AgentPaths.PackageDirectory;

    public static string PathFor(DeploymentSpec spec)
    {
        var extension = string.Equals(spec.InstallerType, InstallerTypes.Msi, StringComparison.OrdinalIgnoreCase) ? ".msi" : ".exe";
        return Path.Combine(Directory, spec.Sha256.ToLowerInvariant() + extension);
    }

    public static void EnsureDirectory()
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
        {
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(sid, null),
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        var directory = new DirectoryInfo(Directory);
        if (directory.Exists)
        {
            directory.SetAccessControl(security);
        }
        else
        {
            directory.Create(security);
        }
    }

    public static bool IsVerified(string path, DeploymentSpec spec)
    {
        var file = new FileInfo(path);
        if (!file.Exists || file.Length != spec.Size)
        {
            return false;
        }

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return string.Equals(Convert.ToHexString(SHA256.HashData(stream)), spec.Sha256, StringComparison.OrdinalIgnoreCase);
    }

    // Deletes the oldest cached files until the cache fits in budget bytes; files in keep are never removed.
    public static void Prune(long budget, params string[] keep)
    {
        var directory = new DirectoryInfo(Directory);
        if (!directory.Exists)
        {
            return;
        }

        var files = directory.GetFiles().OrderBy(file => file.LastWriteTimeUtc).ToList();
        var total = files.Sum(file => file.Length);
        foreach (var file in files)
        {
            if (total <= Math.Max(0, budget))
            {
                break;
            }

            if (keep.Contains(file.FullName, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            if (TryDelete(file.FullName))
            {
                total -= file.Length;
            }
        }
    }

    public static string NewInstallLogPath(Guid commandId)
    {
        var directory = new DirectoryInfo(AgentPaths.InstallLogDirectory);
        directory.Create();
        foreach (var old in directory.GetFiles("*.log").OrderByDescending(file => file.LastWriteTimeUtc).Skip(KeptInstallLogs - 1))
        {
            TryDelete(old.FullName);
        }

        return Path.Combine(directory.FullName, $"{DateTime.UtcNow:yyyyMMdd-HHmmss}-{commandId:N}.log");
    }

    public static bool TryDelete(string path)
    {
        try
        {
            File.Delete(path);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}
