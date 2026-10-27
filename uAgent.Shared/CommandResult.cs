namespace uAgent.Shared;

public sealed record CommandResult(
    Guid CommandId,
    bool Success,
    string? ErrorMessage,
    DateTime ExecutedUtc,
    string? Message = null,
    string? Outcome = null,
    int? ExitCode = null,
    bool? RebootRequired = null,
    string? Log = null,
    int? DurationSeconds = null);
