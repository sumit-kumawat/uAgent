namespace uAgent.Agent;

internal enum AgentVerb
{
    Run,
    Install,
    Upgrade,
    Uninstall,
    Status,
    Configure,
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
    string[] HostArgs)
{
    public static CommandLine Parse(string[] args, bool defaultToInstall)
    {
        var verb = (AgentVerb?)null;
        bool quiet = false, keepData = false, reEnroll = false;
        string? manager = null, key = null, pin = null;
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
                case "run" or "console": verb = AgentVerb.Run; break;
                case "help" or "?" or "h": verb = AgentVerb.Help; break;
                case "quiet" or "q" or "silent": quiet = true; break;
                case "keepdata": keepData = true; break;
                case "reenroll": reEnroll = true; break;
                case "manager": manager = value; break;
                case "enrollkey" or "key": key = value; break;
                case "pin": pin = value; break;
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
            hostArgs.ToArray());
    }

    public const string Usage = """
        uAgent Endpoint Agent

          uAgent.exe                       Install (or repair) the agent with the manager settings built into this installer.
          uAgent.exe /install [/quiet]     Same as above; /quiet runs without prompts.
          uAgent.exe /status               Show service, registration and connection status.
          uAgent.exe /configure /manager=URL [/enrollkey=KEY] [/pin=SHA256] [/reenroll]
                                           Change the manager connection and restart the service.
          uAgent.exe /uninstall [/quiet] [/keepdata]
                                           Stop and remove the service, files and registration.
          uAgent.exe /run                  Run the agent in this console (troubleshooting).

        Installer options: /manager=URL /enrollkey=KEY /pin=SHA256 override the built-in settings.
        All commands require an elevated (administrator) session.
        """;
}
