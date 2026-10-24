namespace uAgent.Shared;

public sealed record AuditEntry(
    Guid Id,
    DateTime TimestampUtc,
    string User,
    string AgentId,
    string? SamAccountName,
    string Action,
    string Result,
    string? Details);
