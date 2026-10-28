namespace uAgent.Shared;

public sealed record Heartbeat(
    string AgentId,
    string MachineName,
    string OsVersion,
    string DomainName,
    TimeSpan Uptime,
    DateTime TimestampUtc,
    string DnsName,
    IReadOnlyList<string> IpAddresses,
    string AgentVersion,
    string ServiceMode,
    IReadOnlyList<string> Capabilities,
    int PollIntervalSeconds,
    int CommandPollSeconds,
    AgentIntegrity? Integrity = null,
    SystemMetrics? Metrics = null,
    int HeartbeatSeconds = 0,
    // The address this agent is actually contacting. It can differ from the one the portal advertises,
    // so the portal can tell which agents a certificate or host change would cut off.
    string ManagerUrl = "",
    string InstallId = "");

// Result of the agent's self-check: binary hash, service configuration and permissions.
public sealed record AgentIntegrity(
    bool Healthy,
    string ExecutableSha256,
    string ExpectedSha256,
    bool Signed,
    string StartType,
    bool PermissionsLocked,
    bool RecoveryConfigured,
    IReadOnlyList<string> Issues,
    IReadOnlyList<string> Repaired,
    DateTime CheckedUtc);
