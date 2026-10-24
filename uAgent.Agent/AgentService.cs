using Microsoft.Extensions.Options;
using uAgent.Shared;

namespace uAgent.Agent;

internal sealed class AgentService : BackgroundService
{
    private const int MaxBackoffSeconds = 300;
    private const int RevokedRetrySeconds = 600;
    private const int NotConfiguredRetrySeconds = 60;
    private const int EnrollmentRejectedRetrySeconds = 300;

    private enum CycleOutcome
    {
        Ok,
        Retry,
        ReEnroll,
        Rejected,
        NotConfigured,
        Revoked
    }

    private readonly ManagerClient _client;
    private readonly AgentStateStore _state;
    private readonly ConnectionSettings _connection;
    private readonly AgentUpdater _updater;
    private readonly IOptionsMonitor<AgentOptions> _agentOptions;
    private readonly ILogger<AgentService> _logger;

    private DateTime? _lastSuccessUtc;
    private DateTime? _lastErrorUtc;
    private string _lastError = string.Empty;
    private int _failures;

    public AgentService(
        ManagerClient client,
        AgentStateStore state,
        ConnectionSettings connection,
        AgentUpdater updater,
        IOptionsMonitor<AgentOptions> agentOptions,
        ILogger<AgentService> logger)
    {
        _client = client;
        _state = state;
        _connection = connection;
        _updater = updater;
        _agentOptions = agentOptions;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var current = _state.Current;
        _logger.LogInformation(
            "uAgent {Version} started as {ServiceMode}. Manager {ManagerUrl}. Agent {DisplayId}. Full sync {PollIntervalSeconds}s, action check {CommandPollSeconds}s.",
            AgentRuntime.Version,
            AgentRuntime.ServiceMode,
            _connection.ManagerUrl,
            current.IsEnrolled ? current.DisplayId : "not registered",
            PollIntervalSeconds(),
            CommandPollSeconds());
        WriteStatus(ConnectionStates.Starting, "The agent is starting.");

        var nextFullSync = DateTime.MinValue;
        while (!stoppingToken.IsCancellationRequested)
        {
            var delaySeconds = CommandPollSeconds();
            try
            {
                var fullSync = DateTime.UtcNow >= nextFullSync;
                switch (await RunCycleAsync(fullSync, stoppingToken))
                {
                    case CycleOutcome.Ok:
                        if (_failures > 0)
                        {
                            _logger.LogInformation("Connection to the manager restored after {Failures} failed attempt(s).", _failures);
                        }

                        _failures = 0;
                        _lastSuccessUtc = DateTime.UtcNow;
                        if (fullSync)
                        {
                            nextFullSync = DateTime.UtcNow.AddSeconds(PollIntervalSeconds());
                        }

                        break;
                    case CycleOutcome.ReEnroll:
                        delaySeconds = 2;
                        nextFullSync = DateTime.MinValue;
                        break;
                    case CycleOutcome.Retry:
                        _failures++;
                        delaySeconds = BackoffSeconds();
                        nextFullSync = DateTime.MinValue;
                        break;
                    case CycleOutcome.Rejected:
                        delaySeconds = EnrollmentRejectedRetrySeconds;
                        break;
                    case CycleOutcome.NotConfigured:
                        delaySeconds = NotConfiguredRetrySeconds;
                        break;
                    case CycleOutcome.Revoked:
                        delaySeconds = RevokedRetrySeconds;
                        nextFullSync = DateTime.MinValue;
                        break;
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _failures++;
                delaySeconds = BackoffSeconds();
                RecordError(ConnectionStates.Disconnected, $"Unexpected error: {ex.Message}");
                _logger.LogWarning(ex, "Agent cycle failed. The agent will keep running.");
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(delaySeconds), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }

        _logger.LogInformation("uAgent stopped.");
    }

    private async Task<CycleOutcome> RunCycleAsync(bool fullSync, CancellationToken token)
    {
        if (!_state.Current.IsEnrolled)
        {
            var enrollment = await EnrollAsync(token);
            if (enrollment != CycleOutcome.Ok)
            {
                return enrollment;
            }

            fullSync = true;
        }

        var agentId = _state.Current.AgentId;
        MachineDetails? machine = null;
        IReadOnlyList<AccountStatus>? accounts = null;

        if (fullSync)
        {
            var captured = CaptureMachine();
            machine = captured;
            accounts = CollectAccounts(captured.IsDomainJoined);

            var heartbeat = await _client.HeartbeatAsync(agentId, _state.ApiKey, BuildHeartbeat(agentId, captured), token);
            if (!heartbeat.Success)
            {
                return HandleFailure(heartbeat, "heartbeat");
            }

            ApplyHeartbeatResponse(heartbeat.Value);

            var report = await _client.PostReportAsync(agentId, _state.ApiKey, BuildReport(agentId, captured, accounts), token);
            if (!report.Success)
            {
                return HandleFailure(report, "inventory report");
            }
        }

        var commandOutcome = await ProcessCommandsAsync(agentId, machine, accounts, token);
        if (commandOutcome != CycleOutcome.Ok)
        {
            return commandOutcome;
        }

        var state = _state.Current;
        if (state.Status == AgentStatuses.PendingApproval)
        {
            WriteStatus(ConnectionStates.PendingApproval, $"Registered as agent {state.DisplayId}; waiting for an administrator to approve it in the portal.");
        }
        else
        {
            WriteStatus(ConnectionStates.Connected, $"Connected to the manager as agent {state.DisplayId}.");
        }

        if (fullSync)
        {
            _logger.LogInformation(
                "Sync complete for {MachineName} as agent {DisplayId} ({Status}). Accounts {AccountCount}.",
                machine?.MachineName,
                state.DisplayId,
                state.Status,
                accounts?.Count ?? 0);
        }

        return CycleOutcome.Ok;
    }

    private async Task<CycleOutcome> EnrollAsync(CancellationToken token)
    {
        var enrollmentKey = _connection.EnrollmentKey;
        if (enrollmentKey.Length == 0)
        {
            RecordError(
                ConnectionStates.NotConfigured,
                "No enrollment key is configured. Install with the installer downloaded from the portal, or run 'uAgent.exe /configure /enrollkey=KEY' as an administrator.");
            return CycleOutcome.NotConfigured;
        }

        var machine = CaptureMachine();
        _logger.LogInformation("Registering {MachineName} with the manager at {ManagerUrl}.", machine.MachineName, _connection.ManagerUrl);
        var result = await _client.EnrollAsync(
            enrollmentKey,
            new EnrollmentRequest(
                machine.MachineName,
                machine.OsVersion,
                machine.DomainName,
                machine.DnsName,
                machine.IpAddresses,
                AgentRuntime.Version,
                AgentRuntime.ServiceMode,
                AgentRuntime.Capabilities()),
            token);

        if (result.Success && result.Value is { } enrolled && enrolled.ApiKey.Length > 0)
        {
            var managerUrl = _connection.ManagerUrl;
            var pin = _connection.CertificatePin;
            _state.Update(state =>
            {
                state.AgentId = enrolled.AgentId;
                state.AgentNumber = enrolled.AgentNumber;
                state.DisplayId = enrolled.DisplayId;
                state.ProtectedApiKey = SecretProtector.Protect(enrolled.ApiKey);
                state.Status = enrolled.Status;
                state.DashboardUrl = enrolled.DashboardUrl ?? string.Empty;
                state.EnrolledUtc = DateTime.UtcNow;
                state.ManagerUrl = managerUrl;
                state.CertificatePin = pin;
                state.ProtectedEnrollmentKey = SecretProtector.Protect(enrollmentKey);
            });
            _logger.LogInformation("Registered as agent {DisplayId} ({Status}).", enrolled.DisplayId, enrolled.Status);
            return CycleOutcome.Ok;
        }

        if (result.IsNetworkError || result.StatusCode >= 500)
        {
            RecordError(ConnectionStates.Disconnected, $"Registration could not reach the manager: {result.Error}");
            return CycleOutcome.Retry;
        }

        RecordError(ConnectionStates.EnrollmentFailed, $"The manager rejected the registration: {result.Error}");
        return CycleOutcome.Rejected;
    }

    private CycleOutcome HandleFailure<T>(ApiResult<T> result, string operation)
    {
        switch (result.ErrorCode)
        {
            case AgentErrorCodes.UnknownAgent:
            case AgentErrorCodes.InvalidKey:
                _logger.LogWarning("The manager did not accept this agent's credential during {Operation} ({Code}). Registering again.", operation, result.ErrorCode);
                _state.Update(state =>
                {
                    state.AgentId = string.Empty;
                    state.ProtectedApiKey = string.Empty;
                    state.DisplayId = string.Empty;
                    state.Status = string.Empty;
                });
                RecordError(ConnectionStates.Disconnected, "The manager no longer recognised this agent; registering again.");
                return CycleOutcome.ReEnroll;
            case AgentErrorCodes.Revoked:
                RecordError(ConnectionStates.Revoked, "An administrator revoked this agent's credential. Reinstall the agent to register it again.");
                return CycleOutcome.Revoked;
        }

        RecordError(ConnectionStates.Disconnected, $"The {operation} failed: {result.Error}");
        _logger.LogWarning("Manager {Operation} failed: {Error}", operation, result.Error);
        return CycleOutcome.Retry;
    }

    private void ApplyHeartbeatResponse(HeartbeatResponse? response)
    {
        if (response is null)
        {
            return;
        }

        _state.Update(state =>
        {
            if (!string.IsNullOrEmpty(response.NewApiKey))
            {
                state.ProtectedApiKey = SecretProtector.Protect(response.NewApiKey);
            }

            state.Status = response.Status;
            state.DisplayId = string.IsNullOrEmpty(response.DisplayId) ? state.DisplayId : response.DisplayId;
            state.DashboardUrl = response.DashboardUrl ?? state.DashboardUrl;
        });

        if (!string.IsNullOrEmpty(response.NewApiKey))
        {
            _logger.LogInformation("The manager rotated this agent's credential. The new credential is stored and in use.");
        }
    }

    // Fetches queued actions, runs them on the host, and posts the real results.
    private async Task<CycleOutcome> ProcessCommandsAsync(
        string agentId,
        MachineDetails? knownMachine,
        IReadOnlyList<AccountStatus>? knownAccounts,
        CancellationToken token)
    {
        var fetched = await _client.GetCommandsAsync(agentId, _state.ApiKey, token);
        if (!fetched.Success)
        {
            return HandleFailure(fetched, "action check");
        }

        var commands = fetched.Value ?? [];
        var autoRemediate = _agentOptions.CurrentValue.AutoRemediate && knownAccounts is not null;
        if (commands.Count == 0 && !autoRemediate)
        {
            return CycleOutcome.Ok;
        }

        var machine = knownMachine ?? CaptureMachine();
        var results = new List<CommandResult>(commands.Count);
        var accountsChanged = false;
        var restartAgent = false;
        string? updateInstaller = null;

        foreach (var command in commands)
        {
            token.ThrowIfCancellationRequested();
            if (command.CommandType == CommandTypes.RefreshInventory)
            {
                results.Add(await RefreshInventoryAsync(agentId, command, machine, token));
                continue;
            }

            if (command.CommandType == CommandTypes.UpdateAgent)
            {
                var plan = await _updater.PrepareAsync(agentId, _state.ApiKey, command, token);
                results.Add(plan.Result);
                updateInstaller ??= plan.InstallerPath;
                continue;
            }

            if (CommandTypes.IsSystemCommand(command.CommandType))
            {
                var (result, restart) = ExecuteSystem(command, machine);
                results.Add(result);
                restartAgent |= restart;
                continue;
            }

            var accountResult = ExecuteAccount(command, machine.IsDomainJoined, "portal");
            accountsChanged |= accountResult.Success;
            results.Add(accountResult);
        }

        if (autoRemediate && knownAccounts is not null)
        {
            foreach (var account in knownAccounts.Where(account => account.LockedOut))
            {
                var alreadyQueued = commands.Any(command =>
                    command.CommandType == CommandTypes.UnlockAccount &&
                    string.Equals(command.SamAccountName, account.SamAccountName, StringComparison.OrdinalIgnoreCase));
                if (alreadyQueued)
                {
                    continue;
                }

                var unlock = new AgentCommand(Guid.NewGuid(), account.SamAccountName, CommandTypes.UnlockAccount, null, DateTime.UtcNow);
                _logger.LogInformation("Auto-remediate will unlock {SamAccountName}", account.SamAccountName);
                var autoResult = ExecuteAccount(unlock, machine.IsDomainJoined, "auto-remediate");
                accountsChanged |= autoResult.Success;
                results.Add(autoResult);
            }
        }

        if (results.Count > 0)
        {
            var posted = await _client.PostResultsAsync(agentId, _state.ApiKey, results, token);
            if (!posted.Success)
            {
                _logger.LogWarning("Action results could not be delivered: {Error}", posted.Error);
            }
        }

        if (accountsChanged)
        {
            await _client.PostReportAsync(agentId, _state.ApiKey, BuildReport(agentId, machine, CollectAccounts(machine.IsDomainJoined)), token);
        }

        if (updateInstaller is not null)
        {
            _updater.Launch(updateInstaller);
        }

        if (restartAgent)
        {
            _logger.LogWarning("Restart Agent was requested from the portal. Exiting so service recovery restarts the agent.");
            Serilog.Log.CloseAndFlush();
            Environment.Exit(1);
        }

        return CycleOutcome.Ok;
    }

    private async Task<CommandResult> RefreshInventoryAsync(string agentId, AgentCommand command, MachineDetails machine, CancellationToken token)
    {
        var accounts = CollectAccounts(machine.IsDomainJoined);
        var heartbeat = await _client.HeartbeatAsync(agentId, _state.ApiKey, BuildHeartbeat(agentId, machine), token);
        if (heartbeat.Success)
        {
            ApplyHeartbeatResponse(heartbeat.Value);
        }

        var report = await _client.PostReportAsync(agentId, _state.ApiKey, BuildReport(agentId, machine, accounts), token);
        return heartbeat.Success && report.Success
            ? new CommandResult(command.CommandId, true, null, DateTime.UtcNow, $"Inventory refreshed: {accounts.Count} account(s) and system details reported.")
            : new CommandResult(command.CommandId, false, "Inventory was collected but the manager did not accept the upload.", DateTime.UtcNow);
    }

    private (CommandResult Result, bool RestartAgent) ExecuteSystem(AgentCommand command, MachineDetails machine)
    {
        try
        {
            var outcome = SystemControls.Execute(command.CommandType, machine);
            _logger.LogInformation(
                "System control {CommandType} ({CommandId}) finished. Success {Success}.",
                command.CommandType,
                command.CommandId,
                outcome.Success);
            var result = outcome.Success
                ? new CommandResult(command.CommandId, true, null, DateTime.UtcNow, Trim(outcome.Message, 4000))
                : new CommandResult(command.CommandId, false, Trim(outcome.Message, 500), DateTime.UtcNow);
            return (result, outcome.Success && outcome.RestartAgentRequested);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "System control {CommandType} ({CommandId}) failed.", command.CommandType, command.CommandId);
            return (new CommandResult(command.CommandId, false, Trim(ex.Message, 500), DateTime.UtcNow), false);
        }
    }

    private CommandResult ExecuteAccount(AgentCommand command, bool isDomainJoined, string origin)
    {
        if (string.IsNullOrWhiteSpace(command.SamAccountName))
        {
            return new CommandResult(command.CommandId, false, "SamAccountName is required.", DateTime.UtcNow);
        }

        if (!OperatingSystem.IsWindows())
        {
            const string message = "Account management requires Windows account APIs and was not executed.";
            _logger.LogWarning(
                "{Message} Origin {Origin}. Command {CommandId} {CommandType} for {SamAccountName}.",
                message,
                origin,
                command.CommandId,
                command.CommandType,
                command.SamAccountName);
            return new CommandResult(command.CommandId, false, message, DateTime.UtcNow);
        }

        try
        {
            WindowsAccountDirectory.Apply(command, isDomainJoined);
            _logger.LogInformation(
                "Executed {CommandType} for {SamAccountName}. Origin {Origin}. Command {CommandId} succeeded.",
                command.CommandType,
                command.SamAccountName,
                origin,
                command.CommandId);
            return new CommandResult(
                command.CommandId,
                true,
                null,
                DateTime.UtcNow,
                $"{command.CommandType} completed for {command.SamAccountName} ({(isDomainJoined ? "domain" : "local")} account).");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex,
                "Command {CommandId} {CommandType} for {SamAccountName} failed. Origin {Origin}.",
                command.CommandId,
                command.CommandType,
                command.SamAccountName,
                origin);
            return new CommandResult(command.CommandId, false, Trim(ex.Message, 500), DateTime.UtcNow);
        }
    }

    private static AccountStatusReport BuildReport(string agentId, MachineDetails machine, IReadOnlyList<AccountStatus> accounts) =>
        new(agentId, machine.MachineName, machine.IsDomainJoined, DateTime.UtcNow, accounts.ToList());

    private Heartbeat BuildHeartbeat(string agentId, MachineDetails machine) =>
        new(
            agentId,
            machine.MachineName,
            machine.OsVersion,
            machine.DomainName,
            machine.Uptime,
            DateTime.UtcNow,
            machine.DnsName,
            machine.IpAddresses,
            AgentRuntime.Version,
            AgentRuntime.ServiceMode,
            AgentRuntime.Capabilities(),
            PollIntervalSeconds(),
            CommandPollSeconds());

    private void RecordError(string state, string message)
    {
        _lastErrorUtc = DateTime.UtcNow;
        _lastError = message;
        WriteStatus(state, message);
    }

    private void WriteStatus(string state, string message)
    {
        var current = _state.Current;
        AgentStatusFile.Write(new AgentStatusSnapshot(
            state,
            message,
            _connection.ManagerUrl,
            current.DisplayId,
            current.DashboardUrl,
            AgentRuntime.Version,
            _lastSuccessUtc,
            _lastErrorUtc,
            _lastError,
            _failures,
            DateTime.UtcNow));
    }

    private int BackoffSeconds()
    {
        var exponent = Math.Min(_failures, 6);
        return (int)Math.Min(CommandPollSeconds() * Math.Pow(2, exponent - 1), MaxBackoffSeconds);
    }

    private MachineDetails CaptureMachine()
    {
        try
        {
            return MachineInfo.Capture();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Machine details could not be read. Using fallback values.");
            return MachineInfo.Fallback();
        }
    }

    private IReadOnlyList<AccountStatus> CollectAccounts(bool isDomainJoined)
    {
        if (!OperatingSystem.IsWindows())
        {
            return [];
        }

        try
        {
            return WindowsAccountDirectory.Collect(ProtectedAccounts(), isDomainJoined, _logger);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Account enumeration failed. Reporting an empty account list.");
            return [];
        }
    }

    private IReadOnlyList<string> ProtectedAccounts()
    {
        var configured = _agentOptions.CurrentValue.ProtectedAccounts ?? [];
        return configured
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Select(name => name.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private int PollIntervalSeconds()
    {
        var seconds = _agentOptions.CurrentValue.PollIntervalSeconds;
        return seconds > 0 ? seconds : 60;
    }

    private int CommandPollSeconds()
    {
        var seconds = _agentOptions.CurrentValue.CommandPollSeconds;
        if (seconds < 2)
        {
            seconds = 10;
        }

        return Math.Min(seconds, PollIntervalSeconds());
    }

    private static string? Trim(string? message, int max)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return null;
        }

        var trimmed = message.Trim();
        return trimmed.Length <= max ? trimmed : trimmed[..max];
    }
}
