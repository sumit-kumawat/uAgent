using System.Diagnostics;
using Microsoft.Extensions.Options;
using uAgent.Shared;

namespace uAgent.Agent;

// Connection model:
//   heartbeat   every HeartbeatSeconds: status, resource metrics and integrity (small payload);
//   report      every PollIntervalSeconds: full account inventory;
//   long poll   held open between them; the manager answers the moment an action or inventory request is queued,
//               so remote actions start within milliseconds of being confirmed in the portal.
// Failures back off exponentially (1 s doubling to 5 min) and every recovery is logged.
internal sealed class AgentService : BackgroundService
{
    private const int MaxBackoffSeconds = 300;
    private const int RevokedRetrySeconds = 600;
    private const int NotConfiguredRetrySeconds = 60;
    private const int EnrollmentRejectedRetrySeconds = 300;
    private static readonly TimeSpan MachineRefresh = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan StatusWriteInterval = TimeSpan.FromSeconds(30);

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
    private readonly TamperGuard _guard;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly IOptionsMonitor<AgentOptions> _agentOptions;
    private readonly ILogger<AgentService> _logger;
    private readonly SystemInventory? _inventory;

    private DateTime? _lastSuccessUtc;
    private DateTime? _lastErrorUtc;
    private string _lastError = string.Empty;
    private int _failures;
    private DiagnosticReport? _diagnosis;
    private DateTime _nextAddressCheckUtc = DateTime.MinValue;
    private static readonly TimeSpan AddressRetryInterval = TimeSpan.FromMinutes(10);
    private DateTime? _nextAttemptUtc;
    private bool _longPollSupported = true;
    private string? _stopReason;

    private DateTime _nextHeartbeat = DateTime.MinValue;
    private DateTime _nextReport = DateTime.MinValue;
    private DateTime _nextServices = DateTime.MinValue;
    private DateTime _nextApplications = DateTime.MinValue;

    private MachineDetails? _machine;
    private DateTime _machineCapturedUtc;
    private string _lastStatusState = string.Empty;
    private DateTime _lastStatusWriteUtc;

    public AgentService(
        ManagerClient client,
        AgentStateStore state,
        ConnectionSettings connection,
        AgentUpdater updater,
        TamperGuard guard,
        IHostApplicationLifetime lifetime,
        IOptionsMonitor<AgentOptions> agentOptions,
        ILogger<AgentService> logger)
    {
        _client = client;
        _state = state;
        _connection = connection;
        _updater = updater;
        _guard = guard;
        _lifetime = lifetime;
        _agentOptions = agentOptions;
        _logger = logger;
        _inventory = OperatingSystem.IsWindows() ? new SystemInventory() : null;
    }

    private AgentOptions Options => _agentOptions.CurrentValue;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var current = _state.Current;
        _logger.LogInformation(
            "uAgent {Version} started as {ServiceMode}. Manager {ManagerUrl}. Agent {DisplayId}. Heartbeat {Heartbeat}s, inventory {Report}s, actions via long poll.",
            AgentRuntime.Version,
            AgentRuntime.ServiceMode,
            _connection.ManagerUrl,
            current.IsEnrolled ? current.DisplayId : "not registered",
            HeartbeatSeconds(),
            PollIntervalSeconds());
        WriteStatus(ConnectionStates.Starting, "The agent is starting.", force: true);

        while (!stoppingToken.IsCancellationRequested)
        {
            TimeSpan delay;
            try
            {
                var (outcome, next) = await RunCycleAsync(stoppingToken);
                delay = next;
                switch (outcome)
                {
                    case CycleOutcome.Ok:
                        if (_failures > 0)
                        {
                            _logger.LogInformation("Connection to the manager restored after {Failures} failed attempt(s).", _failures);
                            ResetSchedule(); // Resend status and inventory right after a reconnect.
                        }

                        _failures = 0;
                        _diagnosis = null;
                        _nextAttemptUtc = null;
                        _lastSuccessUtc = DateTime.UtcNow;
                        break;
                    case CycleOutcome.ReEnroll:
                        delay = TimeSpan.FromSeconds(2);
                        ResetSchedule();
                        break;
                    case CycleOutcome.Retry:
                        _failures++;
                        delay = Backoff();
                        ResetSchedule();
                        await DiagnoseIfDueAsync(delay, stoppingToken);
                        break;
                    case CycleOutcome.Rejected:
                        delay = TimeSpan.FromSeconds(EnrollmentRejectedRetrySeconds);
                        break;
                    case CycleOutcome.NotConfigured:
                        delay = TimeSpan.FromSeconds(NotConfiguredRetrySeconds);
                        break;
                    case CycleOutcome.Revoked:
                        delay = TimeSpan.FromSeconds(RevokedRetrySeconds);
                        ResetSchedule();
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
                delay = Backoff();
                RecordError(ConnectionStates.Disconnected, $"Unexpected error: {ex.Message}");
                _logger.LogWarning(ex, "Agent cycle failed. The agent will keep running.");
            }

            if (delay <= TimeSpan.Zero)
            {
                continue;
            }

            try
            {
                await Task.Delay(delay, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }

        _logger.LogInformation("uAgent stopped.");
    }

    // Reports a local stop (Service Control Manager, shutdown, or the portal) so the dashboard shows it immediately.
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        var state = _state.Current;
        if (state.IsEnrolled)
        {
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(3));
                await _client.PostEventAsync(
                    state.AgentId,
                    _state.ApiKey,
                    new AgentEvent(
                        AgentEventKinds.ServiceStopping,
                        _stopReason ?? "The uAgent service was stopped on the host (Service Control Manager or Windows shutdown).",
                        DateTime.UtcNow),
                    timeout.Token);
            }
            catch (Exception ex) when (ex is OperationCanceledException or HttpRequestException)
            {
                // Best effort: the manager also notices the missing heartbeat.
            }
        }

        await base.StopAsync(cancellationToken);
    }

    private async Task<(CycleOutcome Outcome, TimeSpan Delay)> RunCycleAsync(CancellationToken token)
    {
        if (!_state.Current.IsEnrolled)
        {
            var enrollment = await EnrollAsync(token);
            if (enrollment != CycleOutcome.Ok)
            {
                return (enrollment, TimeSpan.Zero);
            }

            ResetSchedule();
        }

        var agentId = _state.Current.AgentId;
        var now = DateTime.UtcNow;

        if (now >= _nextHeartbeat)
        {
            var outcome = await SendHeartbeatAsync(agentId, token);
            if (outcome != CycleOutcome.Ok)
            {
                return (outcome, TimeSpan.Zero);
            }

            _nextHeartbeat = DateTime.UtcNow.AddSeconds(HeartbeatSeconds());
        }

        if (now >= _nextReport)
        {
            var outcome = await SendReportAsync(agentId, token);
            if (outcome != CycleOutcome.Ok)
            {
                return (outcome, TimeSpan.Zero);
            }

            _nextReport = DateTime.UtcNow.AddSeconds(PollIntervalSeconds());
        }

        if (_inventory is not null && now >= _nextServices)
        {
            await UploadAsync(agentId, InventorySections.Services, null, null, token);
            _nextServices = DateTime.UtcNow.AddSeconds(Math.Max(30, Options.ServicesRefreshSeconds));
        }

        if (_inventory is not null && now >= _nextApplications)
        {
            await UploadAsync(agentId, InventorySections.Applications, null, null, token);
            _nextApplications = DateTime.UtcNow.AddMinutes(Math.Max(5, Options.ApplicationsRefreshMinutes));
        }

        UpdateConnectedStatus();

        if (_longPollSupported)
        {
            var due = new[] { _nextHeartbeat, _nextReport, _inventory is null ? DateTime.MaxValue : _nextServices, _inventory is null ? DateTime.MaxValue : _nextApplications }.Min();
            var wait = (int)Math.Clamp(Math.Ceiling((due - DateTime.UtcNow).TotalSeconds), 1, Math.Clamp(Options.LongPollSeconds, 5, 55));
            var started = Stopwatch.GetTimestamp();
            var poll = await _client.PollAsync(agentId, _state.ApiKey, wait, token);
            if (poll.Success && poll.Value is { } response)
            {
                ApplyStatus(response.Status);
                var commands = response.Commands ?? [];
                var requests = response.Requests ?? [];
                var work = commands.Count + requests.Count;
                if (work > 0)
                {
                    await ProcessRequestsAsync(agentId, requests, token);
                    var commandOutcome = await ExecuteCommandsAsync(agentId, commands, token);
                    return (commandOutcome, TimeSpan.Zero);
                }

                // A manager that answers instantly with no work must not turn this into a busy loop.
                return (CycleOutcome.Ok, Stopwatch.GetElapsedTime(started) < TimeSpan.FromMilliseconds(500) ? TimeSpan.FromSeconds(2) : TimeSpan.Zero);
            }

            if (poll.StatusCode == 404 && poll.ErrorCode is null)
            {
                _longPollSupported = false;
                _logger.LogInformation("The manager does not support the long poll. Checking for actions every {Seconds}s instead.", CommandPollSeconds());
            }
            else
            {
                return (HandleFailure(poll, "action channel"), TimeSpan.Zero);
            }
        }

        var fetched = await _client.GetCommandsAsync(agentId, _state.ApiKey, token);
        if (!fetched.Success)
        {
            return (HandleFailure(fetched, "action check"), TimeSpan.Zero);
        }

        var outcomeLegacy = await ExecuteCommandsAsync(agentId, fetched.Value ?? [], token);
        return (outcomeLegacy, TimeSpan.FromSeconds(CommandPollSeconds()));
    }

    private async Task<CycleOutcome> SendHeartbeatAsync(string agentId, CancellationToken token)
    {
        var machine = Machine();
        var (integrity, changed) = _guard.CheckIfDue();
        SystemMetrics? metrics = null;
        if (_inventory is not null && OperatingSystem.IsWindows())
        {
            try
            {
                metrics = _inventory.Metrics(machine);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Resource metrics could not be read.");
            }
        }

        var heartbeat = await _client.HeartbeatAsync(agentId, _state.ApiKey, BuildHeartbeat(agentId, machine, integrity, metrics), token);
        if (!heartbeat.Success)
        {
            return HandleFailure(heartbeat, "heartbeat");
        }

        ApplyHeartbeatResponse(heartbeat.Value);
        await FollowManagerAddressAsync(agentId, heartbeat.Value?.ManagerUrl, token);

        if (changed && integrity is not null && (integrity.Issues.Count > 0 || integrity.Repaired.Count > 0))
        {
            var detail = string.Join(" ", integrity.Issues.Concat(integrity.Repaired));
            await _client.PostEventAsync(agentId, _state.ApiKey, new AgentEvent(AgentEventKinds.TamperDetected, Trim(detail, 2000) ?? string.Empty, DateTime.UtcNow), token);
        }

        return CycleOutcome.Ok;
    }

    private async Task<CycleOutcome> SendReportAsync(string agentId, CancellationToken token)
    {
        var machine = Machine();
        var accounts = await Task.Run(() => CollectAccounts(machine.IsDomainJoined), token);
        var report = await _client.PostReportAsync(agentId, _state.ApiKey, BuildReport(agentId, machine, accounts), token);
        if (!report.Success)
        {
            return HandleFailure(report, "inventory report");
        }

        _logger.LogInformation(
            "Inventory sent for {MachineName} as agent {DisplayId} ({Status}): {AccountCount} account(s).",
            machine.MachineName,
            _state.Current.DisplayId,
            _state.Current.Status,
            accounts.Count);

        if (Options.AutoRemediate)
        {
            var results = new List<CommandResult>();
            foreach (var account in accounts.Where(account => account.LockedOut))
            {
                var unlock = new AgentCommand(Guid.NewGuid(), account.SamAccountName, CommandTypes.UnlockAccount, null, DateTime.UtcNow, account.Source);
                _logger.LogInformation("Auto-remediate will unlock {SamAccountName}", account.SamAccountName);
                results.Add(ExecuteAccount(unlock, machine.IsDomainJoined, "auto-remediate"));
            }

            if (results.Count > 0)
            {
                await _client.PostResultsAsync(agentId, _state.ApiKey, results, token);
            }
        }

        return CycleOutcome.Ok;
    }

    private async Task ProcessRequestsAsync(string agentId, IReadOnlyList<InventoryRequest> requests, CancellationToken token)
    {
        foreach (var request in requests.DistinctBy(r => (r.Section, r.Path)))
        {
            token.ThrowIfCancellationRequested();
            await UploadAsync(agentId, request.Section, request.RequestId, request.Path, token);
        }
    }

    private async Task UploadAsync(string agentId, string section, string? requestId, string? path, CancellationToken token)
    {
        object data;
        string? error = null;
        var started = Stopwatch.GetTimestamp();
        try
        {
            data = await Task.Run(() => Collect(section, path), token);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            data = new { };
            error = Trim(ex.Message, 500);
        }

        var upload = new InventoryUpload(section, requestId, DateTime.UtcNow, data, error);
        var posted = await _client.PostInventoryAsync(agentId, _state.ApiKey, upload, token);
        if (!posted.Success)
        {
            _logger.LogWarning("The {Section} inventory could not be delivered: {Error}", section, posted.Error);
            return;
        }

        _logger.LogDebug("{Section} inventory sent in {Elapsed} ms.", section, (int)Stopwatch.GetElapsedTime(started).TotalMilliseconds);
    }

    private object Collect(string section, string? path)
    {
        if (_inventory is null || !OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Inventory is collected only on Windows.");
        }

        return section switch
        {
            InventorySections.System => _inventory.Metrics(Machine()),
            InventorySections.Processes => _inventory.Processes(),
            InventorySections.Services => SystemInventory.Services(),
            InventorySections.Applications => SystemInventory.Applications(),
            InventorySections.Files => Options.AllowFileBrowsing
                ? SystemInventory.ListDirectory(path, Options.BrowseRoots ?? [])
                : throw new UnauthorizedAccessException("Folder browsing is disabled in this agent's configuration (Agent:AllowFileBrowsing)."),
            _ => throw new InvalidOperationException($"Unknown inventory section '{section}'.")
        };
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

        var machine = Machine();
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
                AgentRuntime.Capabilities(Options.AllowFileBrowsing)),
            token);

        if (result.Success && result.Value is { } enrolled && enrolled.ApiKey.Length > 0)
        {
            var managerUrl = _connection.ManagerUrl;
            var trust = _connection.Trust;
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
                state.CertificatePin = trust.CertificatePin;
                state.SpkiPin = trust.SpkiPin;
                state.CaCertificate = trust.CaCertificatePem;
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

    // An administrator changed the address agents contact (for example from the server IP to its FQDN).
    // Switch only after the new address passes DNS, TCP and TLS validation and accepts this agent's own
    // credential, so a typo or a missing DNS record cannot strand the agent. HTTPS is never downgraded.
    private async Task FollowManagerAddressAsync(string agentId, string? advertised, CancellationToken token)
    {
        var current = _connection.ManagerUrl.TrimEnd('/');
        var target = (advertised ?? string.Empty).Trim().TrimEnd('/');
        if (target.Length == 0 || string.Equals(target, current, StringComparison.OrdinalIgnoreCase) || DateTime.UtcNow < _nextAddressCheckUtc)
        {
            return;
        }

        _nextAddressCheckUtc = DateTime.UtcNow + AddressRetryInterval;
        if (!Uri.TryCreate(target, UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http") ||
            (uri.Scheme == "http" && current.StartsWith("https:", StringComparison.OrdinalIgnoreCase)))
        {
            _logger.LogWarning("The manager advertised the address {Target}, which is not an acceptable HTTPS URL. Staying on {Current}.", target, current);
            return;
        }

        var trust = _connection.Trust;
        var report = await ConnectivityDiagnostics.RunAsync(target, trust, token);
        var problem = report.Ok ? await _client.VerifyAddressAsync(target, agentId, _state.ApiKey, trust, token) : report.Summary;
        if (problem is not null)
        {
            _logger.LogWarning("The manager moved to {Target}, but this computer cannot use it yet: {Problem} Staying on {Current}; retrying in {Minutes} minutes.",
                target, problem, current, AddressRetryInterval.TotalMinutes);
            return;
        }

        _state.Update(state => state.ManagerUrl = target);
        _logger.LogInformation("Manager address changed from {Current} to {Target} as configured in the portal.", current, target);
        await _client.PostEventAsync(agentId, _state.ApiKey,
            new AgentEvent(AgentEventKinds.ManagerAddressChanged, $"Switched from {current} to {target}.", DateTime.UtcNow), token);
    }

    private void ApplyStatus(string? status)
    {
        if (!string.IsNullOrEmpty(status) && !string.Equals(status, _state.Current.Status, StringComparison.Ordinal))
        {
            _state.Update(state => state.Status = status);
        }
    }

    // Runs queued actions on the host and posts the real results.
    private async Task<CycleOutcome> ExecuteCommandsAsync(string agentId, IReadOnlyList<AgentCommand> commands, CancellationToken token)
    {
        if (commands.Count == 0)
        {
            return CycleOutcome.Ok;
        }

        var machine = Machine();
        var results = new List<CommandResult>(commands.Count);
        var accountsChanged = false;
        var restartAgent = false;
        var stopAgent = false;
        string? uninstaller = null;
        string? updateInstaller = null;

        foreach (var command in commands)
        {
            token.ThrowIfCancellationRequested();
            _logger.LogInformation("Received {CommandType} ({CommandId}) from the manager.", command.CommandType, command.CommandId);
            if (command.CommandType == CommandTypes.RefreshInventory)
            {
                results.Add(await RefreshInventoryAsync(agentId, command, token));
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
                var (result, outcome) = ExecuteSystem(command, machine);
                results.Add(result);
                restartAgent |= outcome.RestartAgentRequested;
                stopAgent |= outcome.StopAgentRequested;
                uninstaller ??= outcome.UninstallerPath;
                continue;
            }

            var accountResult = ExecuteAccount(command, machine.IsDomainJoined, "portal");
            accountsChanged |= accountResult.Success;
            results.Add(accountResult);
        }

        var posted = await _client.PostResultsAsync(agentId, _state.ApiKey, results, token);
        if (!posted.Success)
        {
            _logger.LogWarning("Action results could not be delivered: {Error}", posted.Error);
        }

        if (accountsChanged)
        {
            _nextReport = DateTime.MinValue; // Report the changed accounts on the next cycle, right away.
        }

        if (uninstaller is not null && OperatingSystem.IsWindows())
        {
            _logger.LogWarning("Uninstall was requested from the portal. Starting the uninstaller {Path}.", uninstaller);
            _stopReason = "The agent is being uninstalled from the portal.";
            await _client.PostEventAsync(agentId, _state.ApiKey, new AgentEvent(AgentEventKinds.Uninstalling, _stopReason, DateTime.UtcNow), token);
            SystemControls.LaunchUninstaller(uninstaller);
            return CycleOutcome.Ok;
        }

        if (updateInstaller is not null)
        {
            _updater.Launch(updateInstaller);
        }

        if (stopAgent)
        {
            _logger.LogWarning("Stop Agent was requested from the portal. Stopping the service.");
            _stopReason = "The uAgent service was stopped from the portal by an administrator.";
            _lifetime.StopApplication();
            return CycleOutcome.Ok;
        }

        if (restartAgent)
        {
            _logger.LogWarning("Restart Agent was requested from the portal. Exiting so service recovery restarts the agent.");
            Serilog.Log.CloseAndFlush();
            Environment.Exit(1);
        }

        return CycleOutcome.Ok;
    }

    private async Task<CommandResult> RefreshInventoryAsync(string agentId, AgentCommand command, CancellationToken token)
    {
        _machine = null; // Re-read DNS name, addresses and domain.
        var heartbeat = await SendHeartbeatAsync(agentId, token);
        var machine = Machine();
        var accounts = await Task.Run(() => CollectAccounts(machine.IsDomainJoined), token);
        var report = await _client.PostReportAsync(agentId, _state.ApiKey, BuildReport(agentId, machine, accounts), token);
        _nextReport = DateTime.UtcNow.AddSeconds(PollIntervalSeconds());
        if (_inventory is not null)
        {
            await UploadAsync(agentId, InventorySections.Services, null, null, token);
            await UploadAsync(agentId, InventorySections.Applications, null, null, token);
            _nextServices = DateTime.UtcNow.AddSeconds(Math.Max(30, Options.ServicesRefreshSeconds));
            _nextApplications = DateTime.UtcNow.AddMinutes(Math.Max(5, Options.ApplicationsRefreshMinutes));
        }

        return heartbeat == CycleOutcome.Ok && report.Success
            ? new CommandResult(command.CommandId, true, null, DateTime.UtcNow, $"Inventory refreshed: {accounts.Count} account(s), system details, services and applications reported.")
            : new CommandResult(command.CommandId, false, "Inventory was collected but the manager did not accept the upload.", DateTime.UtcNow);
    }

    private (CommandResult Result, SystemControlOutcome Outcome) ExecuteSystem(AgentCommand command, MachineDetails machine)
    {
        try
        {
            var outcome = SystemControls.Execute(command.CommandType, machine, _connection.ManagerUrl);
            _logger.LogInformation(
                "System control {CommandType} ({CommandId}) finished. Success {Success}.",
                command.CommandType,
                command.CommandId,
                outcome.Success);
            var result = outcome.Success
                ? new CommandResult(command.CommandId, true, null, DateTime.UtcNow, Trim(outcome.Message, 4000))
                : new CommandResult(command.CommandId, false, Trim(outcome.Message, 500), DateTime.UtcNow);
            return (result, outcome.Success ? outcome : default);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "System control {CommandType} ({CommandId}) failed.", command.CommandType, command.CommandId);
            return (new CommandResult(command.CommandId, false, Trim(ex.Message, 500), DateTime.UtcNow), default);
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

        var scope = command.AccountSource ?? (isDomainJoined ? AccountSources.Domain : AccountSources.Local);
        try
        {
            WindowsAccountDirectory.Apply(command, isDomainJoined);
            _logger.LogInformation(
                "Executed {CommandType} for {SamAccountName} ({Scope}). Origin {Origin}. Command {CommandId} succeeded.",
                command.CommandType,
                command.SamAccountName,
                scope,
                origin,
                command.CommandId);
            return new CommandResult(
                command.CommandId,
                true,
                null,
                DateTime.UtcNow,
                $"{command.CommandType} completed for {command.SamAccountName} ({scope.ToLowerInvariant()} account).");
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

    private Heartbeat BuildHeartbeat(string agentId, MachineDetails machine, AgentIntegrity? integrity, SystemMetrics? metrics) =>
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
            AgentRuntime.Capabilities(Options.AllowFileBrowsing),
            PollIntervalSeconds(),
            _longPollSupported ? 0 : CommandPollSeconds(),
            integrity,
            metrics,
            HeartbeatSeconds());

    private void ResetSchedule()
    {
        _nextHeartbeat = DateTime.MinValue;
        _nextReport = DateTime.MinValue;
        _nextServices = DateTime.MinValue;
        _nextApplications = DateTime.MinValue;
    }

    private void UpdateConnectedStatus()
    {
        var state = _state.Current;
        if (state.Status == AgentStatuses.PendingApproval)
        {
            WriteStatus(ConnectionStates.PendingApproval, $"Registered as agent {state.DisplayId}; waiting for an administrator to approve it in the portal.");
        }
        else
        {
            WriteStatus(ConnectionStates.Connected, $"Connected to the manager as agent {state.DisplayId}.");
        }
    }

    // A failed cycle only says that the manager was unreachable. On the 1st, 3rd and every 10th failure in a
    // row, walk DNS, TCP, TLS and the API so the status file and log name the layer that is failing.
    private async Task DiagnoseIfDueAsync(TimeSpan delay, CancellationToken token)
    {
        _nextAttemptUtc = DateTime.UtcNow + delay;
        if (_failures is not (1 or 3) && _failures % 10 != 0)
        {
            WriteStatus(_lastStatusState, _lastError, force: true);
            return;
        }

        try
        {
            _diagnosis = await ConnectivityDiagnostics.RunAsync(_connection.ManagerUrl, _connection.Trust, token);
            foreach (var step in _diagnosis.Steps)
            {
                _logger.Log(step.Ok ? LogLevel.Information : LogLevel.Warning, "Diagnostics {Step}: {Result} {Detail}", step.Name, step.Ok ? "OK" : "FAILED", step.Detail);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Connectivity diagnostics could not run.");
        }

        WriteStatus(_lastStatusState, _lastError, force: true);
    }

    private void RecordError(string state, string message)
    {
        _lastErrorUtc = DateTime.UtcNow;
        _lastError = message;
        WriteStatus(state, message, force: true);
    }

    // Written on every state change and at most every 30 s otherwise; "/status" and the installer read it.
    private void WriteStatus(string state, string message, bool force = false)
    {
        if (!force && state == _lastStatusState && DateTime.UtcNow - _lastStatusWriteUtc < StatusWriteInterval)
        {
            return;
        }

        _lastStatusState = state;
        _lastStatusWriteUtc = DateTime.UtcNow;
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
            DateTime.UtcNow,
            _diagnosis?.Summary ?? string.Empty,
            _diagnosis?.CheckedUtc,
            _nextAttemptUtc,
            AgentRuntime.IsWindowsService ? "LocalSystem (Windows service)" : Environment.UserName));
    }

    // 1 s, 2 s, 4 s ... capped at 5 minutes, with jitter so a fleet does not reconnect in lockstep.
    private TimeSpan Backoff()
    {
        var exponent = Math.Min(_failures - 1, 9);
        var seconds = Math.Min(Math.Pow(2, Math.Max(0, exponent)), MaxBackoffSeconds);
        return TimeSpan.FromSeconds(seconds * (0.8 + Random.Shared.NextDouble() * 0.4));
    }

    private MachineDetails Machine()
    {
        var uptime = TimeSpan.FromMilliseconds(Math.Max(0, Environment.TickCount64));
        if (_machine is { } cached && DateTime.UtcNow - _machineCapturedUtc < MachineRefresh)
        {
            return cached with { Uptime = uptime };
        }

        try
        {
            _machine = MachineInfo.Capture();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Machine details could not be read. Using fallback values.");
            _machine = MachineInfo.Fallback();
        }

        _machineCapturedUtc = DateTime.UtcNow;
        return _machine.Value;
    }

    private IReadOnlyList<AccountStatus> CollectAccounts(bool isDomainJoined)
    {
        if (!OperatingSystem.IsWindows())
        {
            return [];
        }

        try
        {
            var options = Options;
            var protectedNames = (options.ProtectedAccounts ?? [])
                .Where(name => !string.IsNullOrWhiteSpace(name))
                .Select(name => name.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            var enumerateAll = !string.Equals(options.AccountScope, "Protected", StringComparison.OrdinalIgnoreCase);
            return WindowsAccountDirectory.Collect(
                new AccountCollection(protectedNames, enumerateAll, options.MaxAccounts > 0 ? options.MaxAccounts : 5000, isDomainJoined),
                _logger);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Account enumeration failed. Reporting an empty account list.");
            return [];
        }
    }

    private int PollIntervalSeconds()
    {
        var seconds = Options.PollIntervalSeconds;
        return seconds >= 15 ? seconds : 60;
    }

    private int HeartbeatSeconds()
    {
        var seconds = Options.HeartbeatSeconds;
        return Math.Clamp(seconds >= 5 ? seconds : 15, 5, PollIntervalSeconds());
    }

    private int CommandPollSeconds()
    {
        var seconds = Options.CommandPollSeconds;
        return Math.Clamp(seconds >= 2 ? seconds : 5, 2, PollIntervalSeconds());
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
