namespace uAgent.Shared;

public sealed record CommandResult(
    Guid CommandId,
    bool Success,
    string? ErrorMessage,
    DateTime ExecutedUtc,
    string? Message = null);
