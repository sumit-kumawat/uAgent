using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using uAgent.Shared;

namespace uAgent.Agent;

internal readonly record struct DetectionResult(bool Installed, string Detail);

internal readonly record struct PrerequisiteFailure(string Outcome, string Message);

// Detection rules and prerequisites for portal software deployments. Read-only: nothing here changes the host.
[SupportedOSPlatform("windows")]
internal static partial class SoftwareDetection
{
    private const string UninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    private const int InstallStateDefault = 5;
    private const uint ErrorMoreData = 234;

    public static bool IsSupported(string? type) =>
        type is null ||
        string.Equals(type, DetectionTypes.None, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(type, DetectionTypes.MsiProductCode, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(type, DetectionTypes.Registry, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(type, DetectionTypes.File, StringComparison.OrdinalIgnoreCase);

    public static bool IsNone(DetectionRule rule) =>
        string.IsNullOrWhiteSpace(rule.Type) || string.Equals(rule.Type, DetectionTypes.None, StringComparison.OrdinalIgnoreCase);

    public static DetectionResult Detect(DetectionRule rule)
    {
        if (string.Equals(rule.Type, DetectionTypes.MsiProductCode, StringComparison.OrdinalIgnoreCase))
        {
            return DetectProductCode(rule.ProductCode?.Trim() ?? string.Empty, rule.MinVersion);
        }

        if (string.Equals(rule.Type, DetectionTypes.Registry, StringComparison.OrdinalIgnoreCase))
        {
            return DetectDisplayName(rule.DisplayName?.Trim() ?? string.Empty, rule.MinVersion);
        }

        if (string.Equals(rule.Type, DetectionTypes.File, StringComparison.OrdinalIgnoreCase))
        {
            return DetectFile(rule.Path?.Trim() ?? string.Empty, rule.MinVersion);
        }

        return new DetectionResult(false, "no detection rule is configured");
    }

    public static PrerequisiteFailure? Check(Prerequisites? prerequisites, long packageBytes)
    {
        var rules = prerequisites ?? new Prerequisites();

        var build = Environment.OSVersion.Version.Build;
        if (rules.MinOsBuild > 0 && build < rules.MinOsBuild)
        {
            return new PrerequisiteFailure(
                DeploymentOutcomes.Incompatible,
                $"This package requires Windows build {rules.MinOsBuild} or later; this computer runs build {build}.");
        }

        var architecture = RuntimeInformation.OSArchitecture;
        if (string.Equals(rules.Architecture, Architectures.X64, StringComparison.OrdinalIgnoreCase) && architecture != Architecture.X64)
        {
            return new PrerequisiteFailure(DeploymentOutcomes.Incompatible, $"This package requires 64-bit (x64) Windows; this computer runs {architecture} Windows.");
        }

        if (string.Equals(rules.Architecture, Architectures.X86, StringComparison.OrdinalIgnoreCase) && architecture != Architecture.X86)
        {
            return new PrerequisiteFailure(DeploymentOutcomes.Incompatible, $"This package requires 32-bit (x86) Windows; this computer runs {architecture} Windows.");
        }

        var root = Path.GetPathRoot(Environment.SystemDirectory);
        if (!string.IsNullOrEmpty(root))
        {
            var drive = new DriveInfo(root);
            var required = Math.Max(0, rules.MinFreeDiskMb) * 1024L * 1024L + Math.Max(0, packageBytes);
            if (drive.AvailableFreeSpace < required)
            {
                return new PrerequisiteFailure(
                    DeploymentOutcomes.PrerequisiteFailed,
                    $"The system drive {drive.Name} has {FormatBytes(drive.AvailableFreeSpace)} free, but this deployment needs {FormatBytes(required)} " +
                    $"({Math.Max(0, rules.MinFreeDiskMb)} MB free space plus {FormatBytes(packageBytes)} for the package).");
            }
        }

        if (rules.BlockOnPendingReboot)
        {
            var pending = PendingRebootSources();
            if (pending.Count > 0)
            {
                return new PrerequisiteFailure(
                    DeploymentOutcomes.PrerequisiteFailed,
                    $"This computer has a restart pending ({string.Join(", ", pending)}). Restart it before installing this package.");
            }
        }

        return null;
    }

    public static string FormatBytes(long bytes) => bytes switch
    {
        >= 1024L * 1024 * 1024 => string.Create(CultureInfo.InvariantCulture, $"{bytes / (1024d * 1024 * 1024):0.0} GB"),
        >= 1024L * 1024 => string.Create(CultureInfo.InvariantCulture, $"{bytes / (1024d * 1024):0.0} MB"),
        >= 1024L => string.Create(CultureInfo.InvariantCulture, $"{bytes / 1024d:0.0} KB"),
        _ => string.Create(CultureInfo.InvariantCulture, $"{bytes} bytes")
    };

    private static DetectionResult DetectProductCode(string productCode, string? minVersion)
    {
        if (productCode.Length == 0)
        {
            return new DetectionResult(false, "the detection rule has no MSI product code");
        }

        string? version = null;
        var installed = MsiQueryProductState(productCode) == InstallStateDefault;
        if (installed)
        {
            version = MsiProductVersion(productCode);
        }
        else
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                using var key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view).OpenSubKey($@"{UninstallPath}\{productCode}");
                if (key is not null)
                {
                    installed = true;
                    version = key.GetValue("DisplayVersion") as string;
                    break;
                }
            }
        }

        if (!installed)
        {
            return new DetectionResult(false, $"MSI product {productCode} is not installed");
        }

        return MeetsVersion(version, minVersion)
            ? new DetectionResult(true, $"MSI product {productCode} is installed{VersionSuffix(version)}")
            : new DetectionResult(false, $"MSI product {productCode} is installed{VersionSuffix(version)}, which is older than the required {minVersion}");
    }

    private static DetectionResult DetectDisplayName(string displayName, string? minVersion)
    {
        if (displayName.Length == 0)
        {
            return new DetectionResult(false, "the detection rule has no display name");
        }

        string? olderMatch = null;
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var uninstall = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view).OpenSubKey(UninstallPath);
            if (uninstall is null)
            {
                continue;
            }

            foreach (var name in uninstall.GetSubKeyNames())
            {
                using var entry = uninstall.OpenSubKey(name);
                if (entry?.GetValue("DisplayName") is not string found || !found.Contains(displayName, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var version = entry.GetValue("DisplayVersion") as string;
                if (MeetsVersion(version, minVersion))
                {
                    return new DetectionResult(true, $"'{found}' is installed{VersionSuffix(version)}");
                }

                olderMatch ??= $"'{found}'{VersionSuffix(version)}";
            }
        }

        return olderMatch is null
            ? new DetectionResult(false, $"no installed program has a name containing '{displayName}'")
            : new DetectionResult(false, $"{olderMatch} is installed, which is older than the required {minVersion}");
    }

    private static DetectionResult DetectFile(string path, string? minVersion)
    {
        if (path.Length == 0)
        {
            return new DetectionResult(false, "the detection rule has no file path");
        }

        var expanded = Environment.ExpandEnvironmentVariables(path);
        if (!File.Exists(expanded))
        {
            return new DetectionResult(false, $"the file {expanded} does not exist");
        }

        if (string.IsNullOrWhiteSpace(minVersion))
        {
            return new DetectionResult(true, $"{expanded} exists");
        }

        var info = FileVersionInfo.GetVersionInfo(expanded);
        var version = info.FileMajorPart + info.FileMinorPart + info.FileBuildPart + info.FilePrivatePart > 0
            ? string.Create(CultureInfo.InvariantCulture, $"{info.FileMajorPart}.{info.FileMinorPart}.{info.FileBuildPart}.{info.FilePrivatePart}")
            : info.ProductVersion;
        return MeetsVersion(version, minVersion)
            ? new DetectionResult(true, $"{expanded} exists{VersionSuffix(version)}")
            : new DetectionResult(false, $"{expanded}{VersionSuffix(version)} is older than the required {minVersion}");
    }

    // Uses System.Version when both sides parse; otherwise falls back to an ordinal comparison of the text.
    public static bool MeetsVersion(string? installed, string? minimum)
    {
        if (string.IsNullOrWhiteSpace(minimum))
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(installed))
        {
            return false;
        }

        var have = ParseVersion(installed);
        var need = ParseVersion(minimum);
        return have is not null && need is not null
            ? have >= need
            : string.Compare(installed.Trim(), minimum.Trim(), StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static Version? ParseVersion(string text)
    {
        var match = VersionPattern().Match(text);
        if (!match.Success)
        {
            return null;
        }

        var parts = match.Value.Split('.');
        var numbers = new int[4];
        for (var i = 0; i < parts.Length; i++)
        {
            if (!int.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out numbers[i]))
            {
                return null;
            }
        }

        return new Version(numbers[0], numbers[1], numbers[2], numbers[3]);
    }

    private static string VersionSuffix(string? version) => string.IsNullOrWhiteSpace(version) ? string.Empty : $" (version {version.Trim()})";

    private static List<string> PendingRebootSources()
    {
        var sources = new List<string>();
        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using (var cbs = machine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"))
        {
            if (cbs is not null)
            {
                sources.Add("Windows component servicing");
            }
        }

        using (var update = machine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"))
        {
            if (update is not null)
            {
                sources.Add("Windows Update");
            }
        }

        using (var session = machine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager"))
        {
            if (session?.GetValue("PendingFileRenameOperations") is string[] { Length: > 0 } renames && renames.Any(r => r.Length > 0))
            {
                sources.Add("pending file rename operations");
            }
        }

        return sources;
    }

    private static string? MsiProductVersion(string productCode)
    {
        var buffer = new StringBuilder(64);
        var length = buffer.Capacity;
        var status = MsiGetProductInfo(productCode, "VersionString", buffer, ref length);
        if (status == ErrorMoreData)
        {
            buffer.Capacity = ++length;
            status = MsiGetProductInfo(productCode, "VersionString", buffer, ref length);
        }

        return status == 0 ? buffer.ToString() : null;
    }

    [GeneratedRegex(@"\d+(\.\d+){0,3}", RegexOptions.CultureInvariant)]
    private static partial Regex VersionPattern();

    [DllImport("msi.dll", CharSet = CharSet.Unicode, EntryPoint = "MsiQueryProductStateW")]
    private static extern int MsiQueryProductState(string product);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, EntryPoint = "MsiGetProductInfoW")]
    private static extern uint MsiGetProductInfo(string product, string property, StringBuilder value, ref int length);
}
