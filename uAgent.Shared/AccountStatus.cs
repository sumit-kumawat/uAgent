namespace uAgent.Shared;

public sealed record AccountStatus(
    string SamAccountName,
    string DisplayName,
    bool Enabled,
    bool LockedOut,
    DateTime? AccountExpirationDate,
    DateTime? LastPasswordSet,
    DateTime? LastLogon,
    int BadLogonCount,
    string Source,
    DateTime? PasswordExpiresUtc = null,
    bool PasswordNeverExpires = false);
