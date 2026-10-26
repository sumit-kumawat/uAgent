namespace uAgent.Agent;

internal enum AgentVerb
{
    Run,
    Install,
    Upgrade,
    Uninstall,
    Status,
    Configure,
    Diagnose,
    Repair,
    Help
}

// Parses installer switches. Accepts /switch, -switch and --switch, with values as /name=value.
internal sealed record CommandLine(
    AgentVerb Verb,
    bool Quiet,
    bool KeepData,
    bool ReEnroll,
    string? ManagerUrl,
    string? EnrollmentKey,
    string? CertificatePin,
    string[] HostArgs,
    string? CaCertificateFile = null)
{
    public static CommandLine Parse(string[] args, bool defaultToInstall)
    {
        var verb = (AgentVerb?)null;
        bool quiet = false, keepData = false, reEnroll = false;
        string? manager = null, key = null, pin = null, caFile = null;
        var hostArgs = new List<string>();

        foreach (var raw in args)
        {
            var trimmed = raw.TrimStart('/', '-');
            if (trimmed.Length == raw.Length)
            {
                hostArgs.Add(raw);
                continue;
            }

            var equals = trimmed.IndexOf('=');
            var name = (equals >= 0 ? trimmed[..equals] : trimmed).ToLowerInvariant();
            var value = equals >= 0 ? trimmed[(equals + 1)..].Trim().Trim('"') : null;

            switch (name)
            {
                case "install": verb = AgentVerb.Install; break;
                case "upgrade": verb = AgentVerb.Upgrade; break;
                case "uninstall": verb = AgentVerb.Uninstall; break;
                case "status": verb = AgentVerb.Status; break;
                case "configure": verb = AgentVerb.Configure; break;
                case "diagnose" or "diag" or "test": verb = AgentVerb.Diagnose; break;
                case "repair": verb = AgentVerb.Repair; break;
                case "run" or "console": verb = AgentVerb.Run; break;
                case "help" or "?" or "h": verb = AgentVerb.Help; break;
                case "quiet" or "q" or "silent": quiet = true; break;
                case "keepdata": keepData = true; break;
                case "reenroll": reEnroll = true; break;
                case "manager": manager = value; break;
                case "enrollkey" or "key": key = value; break;
                case "pin": pin = value; break;
                case "cacert": caFile = value; break;
                default: hostArgs.Add(raw); break;
            }
        }

        return new CommandLine(
            verb ?? (defaultToInstall ? AgentVerb.Install : AgentVerb.Run),
            quiet,
            keepData,
            reEnroll,
            manager,
            key,
            pin,
            hostArgs.ToArray(),
            caFile);
    }

    public const string Usage = """
        uAgent Endpoint Agent · Developed by Sumit Kumawat · © 2026 Sumit Kumawat

          uAgent.exe                       Install (or repair) the agent with the manager settings built into this installer.
          uAgent.exe /install [/quiet]     Same as above; /quiet runs without prompts.
          uAgent.exe /status               Show service, registration and connection status.
          uAgent.exe /diagnose             Test DNS, proxy, TCP, TLS and the manager API step by step.
          uAgent.exe /repair               Re-apply service settings, folder permissions and the firewall rule, then reconnect.
          uAgent.exe /configure /manager=URL [/enrollkey=KEY] [/pin=SHA256] [/reenroll]
                                           Change the manager connection and restart the service.
          uAgent.exe /uninstall [/quiet] [/keepdata]
                                           Stop and remove the service, files and registration.
          uAgent.exe /run                  Run the agent in this console (troubleshooting).

        Installer options: /manager=URL /enrollkey=KEY /cacert=FILE /pin=SHA256 override the built-in settings.
        A signed installer reads its settings from uagent-install.json in the same folder.
        All commands require an elevated (administrator) session.
        """;
}
