namespace uAgent.Shared;

public static class InventorySections
{
    public const string System = "system";
    public const string Processes = "processes";
    public const string Services = "services";
    public const string Applications = "applications";
    public const string Files = "files";

    public static IReadOnlyList<string> All { get; } = [System, Processes, Services, Applications, Files];

    public static bool IsKnown(string? section) => section is not null && All.Contains(section);
}

// Non-command abilities reported with the capabilities so the portal only shows views the agent can serve.
public static class AgentFeatures
{
    public const string LongPoll = "LongPoll";
    public const string Inventory = "Inventory";
    public const string FileBrowse = "FileBrowse";
    public const string Integrity = "Integrity";
}

// Returned by the long-poll endpoint. The request stays open until there is work or the wait expires,
// so queued actions reach the agent within milliseconds instead of on the next poll interval.
public sealed record AgentPollResponse(
    List<AgentCommand> Commands,
    List<InventoryRequest> Requests,
    string Status,
    int? HeartbeatSeconds = null);

public sealed record InventoryRequest(string RequestId, string Section, string? Path = null);

public sealed record InventoryUpload(
    string Section,
    string? RequestId,
    DateTime CollectedUtc,
    object Data,
    string? Error = null);

public sealed record SystemMetrics(
    double CpuPercent,
    long MemoryTotalBytes,
    long MemoryAvailableBytes,
    int ProcessCount,
    int ThreadCount,
    int HandleCount,
    TimeSpan Uptime,
    IReadOnlyList<DiskUsage> Disks,
    DateTime CollectedUtc,
    int LogicalProcessors = 0,
    string? Architecture = null,
    string? OsVersion = null,
    string? Manufacturer = null,
    string? Model = null);

public sealed record DiskUsage(string Name, string Label, string Format, long TotalBytes, long FreeBytes);

public sealed record ProcessInfo(
    int Pid,
    string Name,
    double CpuPercent,
    long WorkingSetBytes,
    long PrivateBytes,
    int Threads,
    int Handles,
    int SessionId,
    DateTime? StartedUtc,
    string? Path);

public sealed record ServiceInfo(
    string Name,
    string DisplayName,
    string Status,
    string StartType,
    string ServiceType,
    bool CanStop);

public sealed record ApplicationInfo(
    string Name,
    string? Version,
    string? Publisher,
    string? InstallDate,
    long? SizeBytes,
    string Scope,
    string? InstallLocation);

public sealed record FileEntry(
    string Name,
    bool IsDirectory,
    long? SizeBytes,
    DateTime? ModifiedUtc,
    string Attributes);

public sealed record DirectoryListing(
    string Path,
    string? Parent,
    IReadOnlyList<FileEntry> Entries,
    bool Truncated,
    IReadOnlyList<string> Roots);

// Lifecycle events the agent reports outside the normal sync (for example a local service stop).
public sealed record AgentEvent(string Kind, string Detail, DateTime TimestampUtc);

public static class AgentEventKinds
{
    public const string ServiceStopping = "ServiceStopping";
    public const string ServiceStarted = "ServiceStarted";
    public const string TamperDetected = "TamperDetected";
    public const string Uninstalling = "Uninstalling";
    public const string ManagerAddressChanged = "ManagerAddressChanged";
}
