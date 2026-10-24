namespace uAgent.Shared;

public static class CommandTypes
{
    public const string UnlockAccount = "UnlockAccount";
    public const string ResetPassword = "ResetPassword";
    public const string EnableAccount = "EnableAccount";
    public const string DisableAccount = "DisableAccount";
    public const string PasswordNeverExpires = "PasswordNeverExpires";
    public const string CannotChangePassword = "CannotChangePassword";

    public const string Ping = "Ping";
    public const string RefreshInventory = "RefreshInventory";
    public const string CollectDiagnostics = "CollectDiagnostics";
    public const string RestartAgent = "RestartAgent";
    public const string RestartComputer = "RestartComputer";
    public const string CancelRestart = "CancelRestart";
    public const string UpdateAgent = "UpdateAgent";

    public static IReadOnlyList<string> AccountCommands { get; } =
    [
        UnlockAccount,
        ResetPassword,
        EnableAccount,
        DisableAccount,
        PasswordNeverExpires,
        CannotChangePassword
    ];

    public static IReadOnlyList<string> SystemCommands { get; } =
    [
        Ping,
        RefreshInventory,
        CollectDiagnostics,
        RestartAgent,
        RestartComputer,
        CancelRestart,
        UpdateAgent
    ];

    public static bool IsKnown(string? commandType) => IsAccountCommand(commandType) || IsSystemCommand(commandType);

    public static bool IsAccountCommand(string? commandType) =>
        commandType is not null && AccountCommands.Contains(commandType);

    public static bool IsSystemCommand(string? commandType) =>
        commandType is not null && SystemCommands.Contains(commandType);

    public static bool RequiresNewPassword(string? commandType) =>
        commandType is ResetPassword;
}
