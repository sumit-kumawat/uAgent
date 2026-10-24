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
    int CommandPollSeconds);
