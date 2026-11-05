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
    public const string StopAgent = "StopAgent";
    public const string UninstallAgent = "UninstallAgent";
    public const string RepairAgent = "RepairAgent";

    // Runs on the agent's background deployment worker, never inline with the other system controls.
    public const string InstallSoftware = "InstallSoftware";

    // System administration. Settings travel in AgentCommand.Parameters; a domain password travels in
    // AgentCommand.NewPassword, which the portal never stores or returns.
    public const string ServiceControl = "ServiceControl";
    public const string ShutdownComputer = "ShutdownComputer";
    public const string SetFirewallProfile = "SetFirewallProfile";
    public const string FirewallRule = "FirewallRule";
    public const string SetRemoteDesktop = "SetRemoteDesktop";
    public const string SetNla = "SetNla";
    public const string SetHostname = "SetHostname";
    public const string SetDns = "SetDns";
    public const string JoinDomain = "JoinDomain";
    public const string LeaveDomain = "LeaveDomain";

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
        UpdateAgent,
        StopAgent,
        UninstallAgent,
        RepairAgent
    ];

    public static IReadOnlyList<string> AdminCommands { get; } =
    [
        ServiceControl,
        ShutdownComputer,
        SetFirewallProfile,
        FirewallRule,
        SetRemoteDesktop,
        SetNla,
        SetHostname,
        SetDns,
        JoinDomain,
        LeaveDomain
    ];

    public static bool IsKnown(string? commandType) =>
        IsAccountCommand(commandType) || IsSystemCommand(commandType) || IsDeploymentCommand(commandType) || IsAdminCommand(commandType);

    public static bool IsAdminCommand(string? commandType) =>
        commandType is not null && AdminCommands.Contains(commandType);

    public static bool IsDeploymentCommand(string? commandType) =>
        commandType is InstallSoftware;

    public static bool IsAccountCommand(string? commandType) =>
        commandType is not null && AccountCommands.Contains(commandType);

    public static bool IsSystemCommand(string? commandType) =>
        commandType is not null && SystemCommands.Contains(commandType);

    public static bool RequiresNewPassword(string? commandType) =>
        commandType is ResetPassword;
}
