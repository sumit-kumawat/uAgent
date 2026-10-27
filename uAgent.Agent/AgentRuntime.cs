using System.Reflection;
using Microsoft.Extensions.Hosting.WindowsServices;
using uAgent.Shared;

namespace uAgent.Agent;

internal static class AgentRuntime
{
    public const string WindowsServiceMode = "WindowsService";
    public const string ConsoleMode = "Console";

    public static string Version { get; } = ReadVersion();

    public static bool IsWindowsService { get; } = OperatingSystem.IsWindows() && WindowsServiceHelpers.IsWindowsService();

    public static string ServiceMode => IsWindowsService ? WindowsServiceMode : ConsoleMode;

    public static DateTime StartedUtc { get; } = DateTime.UtcNow;

    // The portal only offers controls listed here, so an action the host cannot perform
    // is shown as unavailable instead of being queued and failing later.
    public static IReadOnlyList<string> Capabilities(bool allowFileBrowsing = false)
    {
        var capabilities = new List<string>
        {
            CommandTypes.Ping,
            CommandTypes.RefreshInventory,
            CommandTypes.CollectDiagnostics,
            AgentFeatures.LongPoll
        };

        if (OperatingSystem.IsWindows())
        {
            capabilities.AddRange(CommandTypes.AccountCommands);
            capabilities.Add(AgentFeatures.AccountToggles);
            capabilities.Add(CommandTypes.RestartComputer);
            capabilities.Add(CommandTypes.CancelRestart);
            capabilities.Add(AgentFeatures.Inventory);
            if (allowFileBrowsing)
            {
                capabilities.Add(AgentFeatures.FileBrowse);
            }
        }

        if (IsWindowsService)
        {
            capabilities.Add(CommandTypes.RestartAgent);
            capabilities.Add(CommandTypes.UpdateAgent);
            capabilities.Add(CommandTypes.StopAgent);
            capabilities.Add(CommandTypes.UninstallAgent);
            capabilities.Add(AgentFeatures.VerifiedUninstall);
            capabilities.Add(CommandTypes.RepairAgent);
            capabilities.Add(CommandTypes.InstallSoftware);
            capabilities.Add(AgentFeatures.Integrity);
        }

        return capabilities;
    }

    private static string ReadVersion()
    {
        var assembly = Assembly.GetEntryAssembly() ?? typeof(AgentRuntime).Assembly;
        var informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(informational))
        {
            var plus = informational.IndexOf('+', StringComparison.Ordinal);
            return plus > 0 ? informational[..plus] : informational;
        }

        return assembly.GetName().Version?.ToString(3) ?? "0.0.0";
    }
}
