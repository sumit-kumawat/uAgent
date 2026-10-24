namespace uAgent.Shared;

public sealed record AccountStatusReport(
    string AgentId,
    string MachineName,
    bool IsDomainJoined,
    DateTime TimestampUtc,
    List<AccountStatus> Accounts);
