using System.Text.Json;

namespace uAgent.Agent;

// The service's view of its own health, written after every cycle. The installer and "uAgent.exe /status"
// read it to show whether registration and the connection to the manager are working.
internal sealed record AgentStatusSnapshot(
    string State,
    string Message,
    string ManagerUrl,
    string DisplayId,
    string DashboardUrl,
    string Version,
    DateTime? LastSuccessUtc,
    DateTime? LastErrorUtc,
    string LastError,
    int ConsecutiveFailures,
    DateTime UpdatedUtc);

internal static class ConnectionStates
{
    public const string Starting = "Starting";
    public const string Connected = "Connected";
    public const string PendingApproval = "PendingApproval";
    public const string Disconnected = "Disconnected";
    public const string NotConfigured = "NotConfigured";
    public const string EnrollmentFailed = "EnrollmentFailed";
    public const string Revoked = "Revoked";
}

internal static class AgentStatusFile
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static void Write(AgentStatusSnapshot snapshot)
    {
        try
        {
            Directory.CreateDirectory(AgentPaths.DataDirectory);
            var temp = AgentPaths.StatusPath + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(snapshot, JsonOptions));
            File.Move(temp, AgentPaths.StatusPath, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Serilog.Log.Debug(ex, "Status file could not be written.");
        }
    }

    public static AgentStatusSnapshot? Read()
    {
        try
        {
            return File.Exists(AgentPaths.StatusPath)
                ? JsonSerializer.Deserialize<AgentStatusSnapshot>(File.ReadAllText(AgentPaths.StatusPath), JsonOptions)
                : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }
}
