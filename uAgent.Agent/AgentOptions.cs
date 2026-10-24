namespace uAgent.Agent;

public sealed class AgentOptions
{
    public const string SectionName = "Agent";

    public int PollIntervalSeconds { get; set; } = 60;

    public int CommandPollSeconds { get; set; } = 10;

    public string[] ProtectedAccounts { get; set; } =
    [
        "administrator",
        "rdsroot",
        "rdsmon",
        "infosec"
    ];

    public bool AutoRemediate { get; set; }
}
