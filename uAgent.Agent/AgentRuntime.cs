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
    public static IReadOnlyList<string> Capabilities()
    {
        var capabilities = new List<string>
        {
            CommandTypes.Ping,
            CommandTypes.RefreshInventory,
            CommandTypes.CollectDiagnostics
        };

        if (OperatingSystem.IsWindows())
        {
            capabilities.AddRange(CommandTypes.AccountCommands);
            capabilities.Add(CommandTypes.RestartComputer);
            capabilities.Add(CommandTypes.CancelRestart);
        }

        if (IsWindowsService)
        {
            capabilities.Add(CommandTypes.RestartAgent);
            capabilities.Add(CommandTypes.UpdateAgent);
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
