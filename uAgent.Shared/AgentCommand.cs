namespace uAgent.Shared;

// AccountSource ("Local" or "Domain") tells the agent which account database the action targets.
// Agents treat a missing source as the pre-1.3 behaviour: domain when joined, otherwise local.
public sealed record AgentCommand(
    Guid CommandId,
    string SamAccountName,
    string CommandType,
    string? NewPassword,
    DateTime CreatedUtc,
    string? AccountSource = null);
