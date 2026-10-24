namespace uAgent.Agent;

internal static class AgentPaths
{
    public const string ServiceName = "uAgent";
    public const string ServiceDisplayName = "uAgent Endpoint Agent";
    public const string ExecutableName = "uAgent.exe";

    // Installed binaries. Writable only by SYSTEM and Administrators.
    public static string InstallDirectory { get; } = OperatingSystem.IsWindows()
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "uAgent")
        : AppContext.BaseDirectory;

    public static string InstalledExecutable => Path.Combine(InstallDirectory, ExecutableName);

    // Credentials, status and logs. Readable only by SYSTEM and Administrators on Windows.
    public static string DataDirectory { get; } = OperatingSystem.IsWindows()
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "uAgent")
        : Path.Combine(AppContext.BaseDirectory, "data");

    public static string StatePath => Path.Combine(DataDirectory, "agent-state.json");

    public static string StatusPath => Path.Combine(DataDirectory, "status.json");

    public static string SettingsPath => Path.Combine(DataDirectory, "appsettings.json");

    public static string LogDirectory => Path.Combine(DataDirectory, "logs");

    public static string UpdateDirectory => Path.Combine(DataDirectory, "updates");
}
