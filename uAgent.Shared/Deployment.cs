namespace uAgent.Shared;

// Carried by an InstallSoftware command. Secret values referenced by Arguments are resolved by the portal at
// dispatch time and listed in Redactions so the agent never stores or returns them.
public sealed record DeploymentSpec
{
    public string DeploymentId { get; init; } = string.Empty;
    public string PackageId { get; init; } = string.Empty;
    public string PackageName { get; init; } = string.Empty;
    public string PackageVersion { get; init; } = string.Empty;
    public string InstallerType { get; init; } = string.Empty;
    public string FileName { get; init; } = string.Empty;
    public string Sha256 { get; init; } = string.Empty;
    public long Size { get; init; }
    public string DownloadUrl { get; init; } = string.Empty;
    public string Arguments { get; init; } = string.Empty;
    public int TimeoutSeconds { get; init; }
    public int[]? SuccessExitCodes { get; init; }
    public int[]? RebootExitCodes { get; init; }
    public int[]? RetryExitCodes { get; init; }
    public bool RequireSignature { get; init; }
    public string? ExpectedSigner { get; init; }
    public bool ScanWithDefender { get; init; }
    public DetectionRule? Detection { get; init; }
    public Prerequisites? Prerequisites { get; init; }
    public string RestartBehavior { get; init; } = RestartBehaviors.Never;
    public int RestartDelayMinutes { get; init; }
    public int Attempt { get; init; }
    public bool Force { get; init; }
    public string[]? Redactions { get; init; }
}

public sealed record DetectionRule
{
    public string Type { get; init; } = DetectionTypes.None;
    public string? ProductCode { get; init; }
    public string? DisplayName { get; init; }
    public string? MinVersion { get; init; }
    public string? Path { get; init; }
}

public sealed record Prerequisites
{
    public int MinOsBuild { get; init; }
    public string Architecture { get; init; } = Architectures.Any;
    public int MinFreeDiskMb { get; init; }
    public bool BlockOnPendingReboot { get; init; }
}

// Posted to api/agents/{agentId}/deployments/progress; Percent is set only while downloading.
public sealed record DeploymentProgress(Guid CommandId, string Stage, int? Percent, string? Message);

public static class InstallerTypes
{
    public const string Msi = "msi";
    public const string Exe = "exe";
}

public static class DetectionTypes
{
    public const string None = "none";
    public const string MsiProductCode = "msiProductCode";
    public const string Registry = "registry";
    public const string File = "file";
}

public static class Architectures
{
    public const string Any = "any";
    public const string X64 = "x64";
    public const string X86 = "x86";
}

public static class RestartBehaviors
{
    public const string Never = "never";
    public const string IfRequired = "ifRequired";
}

public static class DeploymentStages
{
    public const string Queued = "Queued";
    public const string Checking = "Checking";
    public const string Downloading = "Downloading";
    public const string Verifying = "Verifying";
    public const string Scanning = "Scanning";
    public const string Installing = "Installing";
    public const string Confirming = "Confirming";
}

public static class DeploymentOutcomes
{
    public const string Installed = "Installed";
    public const string AlreadyInstalled = "AlreadyInstalled";
    public const string Failed = "Failed";
    public const string PrerequisiteFailed = "PrerequisiteFailed";
    public const string Incompatible = "Incompatible";
    public const string VerificationFailed = "VerificationFailed";
    public const string DownloadFailed = "DownloadFailed";
    public const string IntegrityFailed = "IntegrityFailed";
    public const string SignatureFailed = "SignatureFailed";
    public const string ThreatDetected = "ThreatDetected";
    public const string TimedOut = "TimedOut";
    public const string Busy = "Busy";
}
