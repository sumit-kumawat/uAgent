namespace uAgent.Shared;

// Sent once with the enrollment key in X-Api-Key. The portal answers with a unique per-agent credential.
public sealed record EnrollmentRequest(
    string MachineName,
    string OsVersion,
    string DomainName,
    string DnsName,
    IReadOnlyList<string> IpAddresses,
    string AgentVersion,
    string ServiceMode,
    IReadOnlyList<string> Capabilities);

public sealed record EnrollmentResponse(
    string AgentId,
    int AgentNumber,
    string DisplayId,
    string ApiKey,
    string Status,
    string? DashboardUrl,
    string? ManagerUrl = null);

// Returned for every heartbeat. NewApiKey is present while a credential rotation is in progress.
public sealed record HeartbeatResponse(
    string Status,
    string DisplayId,
    string? NewApiKey,
    string? DashboardUrl,
    string? ManagerUrl = null);

// Confirms that an address belongs to the manager that issued this agent's credential.
public sealed record AgentIdentity(string AgentId, string DisplayId);

public sealed record UpdateManifest(
    string Version,
    string Sha256,
    long Size,
    bool Signed,
    string PackageUrl);

public static class AgentStatuses
{
    public const string Active = "Active";
    public const string PendingApproval = "PendingApproval";
    public const string Revoked = "Revoked";
}

public static class AgentErrorCodes
{
    public const string UnknownAgent = "unknown_agent";
    public const string InvalidKey = "invalid_key";
    public const string Revoked = "revoked";
    public const string EnrollmentDenied = "enrollment_denied";
}
