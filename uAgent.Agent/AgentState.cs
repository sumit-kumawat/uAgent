using System.Text.Json;

namespace uAgent.Agent;

// Registration and connection details that must survive restarts and upgrades.
internal sealed class AgentState
{
    public string ManagerUrl { get; set; } = string.Empty;

    public string CertificatePin { get; set; } = string.Empty;

    // SHA-256 of the certificate public key; survives certificate reissues that keep the key.
    public string SpkiPin { get; set; } = string.Empty;

    // PEM of the private root CA that issues the manager certificate.
    public string CaCertificate { get; set; } = string.Empty;

    public string ProtectedEnrollmentKey { get; set; } = string.Empty;

    public string AgentId { get; set; } = string.Empty;

    public int AgentNumber { get; set; }

    public string DisplayId { get; set; } = string.Empty;

    public string ProtectedApiKey { get; set; } = string.Empty;

    public string Status { get; set; } = string.Empty;

    public string DashboardUrl { get; set; } = string.Empty;

    public DateTime? EnrolledUtc { get; set; }

    // Random per installation and kept across upgrades and repairs. It lets the manager tell this
    // installation apart from another computer with the same host name (for example one built from the
    // same image before the agent was installed), so one can never take over the other's registration.
    // A computer cloned after the agent was installed copies this file, ID included, and cannot be told apart.
    public string InstallId { get; set; } = string.Empty;

    // The registration this installation held before the manager stopped accepting it, sent with the
    // next enrollment so the manager can restore the same record instead of creating another.
    public string PreviousAgentId { get; set; } = string.Empty;

    // SHA-256 of the installed uAgent.exe, written by the installer and checked by the tamper guard.
    public string InstalledSha256 { get; set; } = string.Empty;

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

    // Created on first use, so an agent upgraded from a version without one gets it on its first start.
    public string InstallId
    {
        get
        {
            var current = Current.InstallId;
            if (current.Length > 0)
            {
                return current;
            }

            Update(state =>
            {
                if (state.InstallId.Length == 0)
                {
                    state.InstallId = Guid.NewGuid().ToString("N");
                }
            });
            return Current.InstallId;
        }
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
