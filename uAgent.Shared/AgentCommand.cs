namespace uAgent.Shared;

// Value is the desired setting for PasswordNeverExpires and CannotChangePassword (null means true, for older portals).
public sealed record AgentCommand(
    Guid CommandId,
    string SamAccountName,
    string CommandType,
    string? NewPassword,
    DateTime CreatedUtc,
    string? AccountSource = null,
    DeploymentSpec? Deployment = null,
    bool? Value = null);
