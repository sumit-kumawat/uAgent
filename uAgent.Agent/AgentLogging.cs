using Serilog;
using Serilog.Events;

namespace uAgent.Agent;

internal static class AgentLogging
{
    public static string LogDirectory { get; } = AgentPaths.LogDirectory;

    public static string LogFilePath { get; } = Path.Combine(LogDirectory, "uAgent-.log");

    public static void Configure(LoggerConfiguration configuration)
    {
        Directory.CreateDirectory(LogDirectory);
        configuration
            .MinimumLevel.Information()
            .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
            .MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
            .MinimumLevel.Override("System.Net.Http.HttpClient", LogEventLevel.Warning)
            .Enrich.FromLogContext()
            .WriteTo.Console()
            .WriteTo.File(
                LogFilePath,
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 14,
                shared: true);
    }
}
