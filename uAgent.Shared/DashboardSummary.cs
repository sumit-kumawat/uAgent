namespace uAgent.Shared;

public sealed record DashboardSummary(
    int TotalAgents,
    int OnlineAgents,
    int TotalAccounts,
    int CriticalAccounts);
