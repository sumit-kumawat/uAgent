namespace uAgent.Shared;

public sealed record AgentCommand(
    Guid CommandId,
    string SamAccountName,
    string CommandType,
    string? NewPassword,
    DateTime CreatedUtc,
    string? AccountSource = null);
