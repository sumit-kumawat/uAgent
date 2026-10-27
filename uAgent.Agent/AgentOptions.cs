namespace uAgent.Agent;

public sealed class AgentOptions
{
    public const string SectionName = "Agent";

    // Full account inventory upload.
    public int PollIntervalSeconds { get; set; } = 60;

    // Lightweight heartbeat (status, metrics, integrity). Actions do not wait for it: they arrive over the long poll.
    public int HeartbeatSeconds { get; set; } = 15;

    // Fallback action check for managers that do not support the long poll.
    public int CommandPollSeconds { get; set; } = 5;

    // Upper bound for one long-poll request; the manager answers earlier as soon as there is work.
    public int LongPollSeconds { get; set; } = 25;

    public int ServicesRefreshSeconds { get; set; } = 120;

    public int ApplicationsRefreshMinutes { get; set; } = 30;

    // Names that are always looked up and flagged as protected, in addition to the enumerated accounts.
    public string[] ProtectedAccounts { get; set; } = [];

    // "All": every local account, plus domain users that are members of local groups when domain joined.
    // "Protected": only the names in ProtectedAccounts.
    public string AccountScope { get; set; } = "All";

    public int MaxAccounts { get; set; } = 5000;

    // Lets administrators list folders (names, sizes, dates; never file contents) from the portal.
    public bool AllowFileBrowsing { get; set; } = true;

    // Folders that may be listed. Empty means every fixed local drive.
    public string[] BrowseRoots { get; set; } = [];

    public bool AutoRemediate { get; set; }
}
