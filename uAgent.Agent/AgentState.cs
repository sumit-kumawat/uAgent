using System.Text.Json;

namespace uAgent.Agent;

// Registration and connection details that must survive restarts and upgrades.
internal sealed class AgentState
{
    public string ManagerUrl { get; set; } = string.Empty;

    public string CertificatePin { get; set; } = string.Empty;

    public string ProtectedEnrollmentKey { get; set; } = string.Empty;

    public string AgentId { get; set; } = string.Empty;

    public int AgentNumber { get; set; }

    public string DisplayId { get; set; } = string.Empty;

    public string ProtectedApiKey { get; set; } = string.Empty;

    public string Status { get; set; } = string.Empty;

    public string DashboardUrl { get; set; } = string.Empty;

    public DateTime? EnrolledUtc { get; set; }

    public bool IsEnrolled => AgentId.Length > 0 && ProtectedApiKey.Length > 0;

    public AgentState Clone() => (AgentState)MemberwiseClone();
}

internal sealed class AgentStateStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private readonly object _gate = new();
    private readonly string _path;
    private AgentState _state;

    public AgentStateStore()
        : this(AgentPaths.StatePath)
    {
    }

    public AgentStateStore(string path)
    {
        _path = path;
        _state = Load(path);
    }

    public AgentState Current
    {
        get
        {
            lock (_gate)
            {
                return _state.Clone();
            }
        }
    }

    public string ApiKey => SecretProtector.Unprotect(Current.ProtectedApiKey);

    public string EnrollmentKey => SecretProtector.Unprotect(Current.ProtectedEnrollmentKey);

    public void Update(Action<AgentState> change)
    {
        lock (_gate)
        {
            var next = _state.Clone();
            change(next);
            Save(_path, next);
            _state = next;
        }
    }

    public static AgentState Load(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                return JsonSerializer.Deserialize<AgentState>(File.ReadAllText(path), JsonOptions) ?? new AgentState();
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            Serilog.Log.Warning(ex, "Agent state at {Path} could not be read. Starting unregistered.", path);
        }

        return new AgentState();
    }

    private static void Save(string path, AgentState state)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(state, JsonOptions));
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        File.Move(temp, path, overwrite: true);
    }
}
