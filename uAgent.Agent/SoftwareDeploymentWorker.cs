using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.Versioning;
using System.Threading.Channels;
using uAgent.Shared;

namespace uAgent.Agent;

// Runs InstallSoftware commands one at a time, off the poll loop. The queue lives in memory only so resolved
// secrets are never written to disk; after a service restart the portal dispatches the deployment again.
internal sealed class SoftwareDeploymentWorker : BackgroundService
{
    private static readonly TimeSpan ProgressInterval = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan ProgressTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan DefaultInstallTimeout = TimeSpan.FromHours(1);
    private static readonly TimeSpan MaxInstallTimeout = TimeSpan.FromHours(24);
    private static readonly TimeSpan ScanTimeout = TimeSpan.FromMinutes(15);
    private static readonly int[] DefaultSuccessCodes = [0];
    private static readonly int[] DefaultRebootCodes = [3010, 1641];
    private static readonly int[] DefaultRetryCodes = [1618];
    private const int ThreatFoundExitCode = 2;
    private const int ShutdownAlreadyScheduled = 1190;
    private const int MaxRestartDelayMinutes = 315_360_000 / 60;
    private const int ResultAttempts = 4;

    private readonly Channel<AgentCommand> _queue = Channel.CreateUnbounded<AgentCommand>(new UnboundedChannelOptions { SingleReader = true });
    private readonly ConcurrentDictionary<Guid, byte> _pending = new();
    private readonly ManagerClient _client;
    private readonly AgentStateStore _state;
    private readonly ILogger<SoftwareDeploymentWorker> _logger;

    public SoftwareDeploymentWorker(ManagerClient client, AgentStateStore state, ILogger<SoftwareDeploymentWorker> logger)
    {
        _client = client;
        _state = state;
        _logger = logger;
    }

    // Returns as soon as the command is queued; a CommandId that is already queued or running is ignored.
    public async Task EnqueueAsync(AgentCommand command, CancellationToken token)
    {
        if (!_pending.TryAdd(command.CommandId, 0))
        {
            _logger.LogInformation("Deployment {CommandId} is already queued or running; the repeated delivery was ignored.", command.CommandId);
            return;
        }

        if (!_queue.Writer.TryWrite(command))
        {
            _pending.TryRemove(command.CommandId, out _);
            return;
        }

        var redactor = new Redactor(command.Deployment?.Redactions);
        var label = Label(command.Deployment);
        var ahead = _pending.Count - 1;
        _logger.LogInformation("Queued deployment {CommandId} of {Package}.", command.CommandId, redactor.Apply(label));
        await ProgressAsync(
            command.CommandId,
            DeploymentStages.Queued,
            null,
            ahead > 0 ? $"Queued behind {ahead} other installation(s) on this computer." : "Queued for installation.",
            redactor,
            token);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await foreach (var command in _queue.Reader.ReadAllAsync(stoppingToken))
            {
                try
                {
                    await RunAsync(command, stoppingToken);
                }
                finally
                {
                    _pending.TryRemove(command.CommandId, out _);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Queued deployments are dropped on shutdown; the portal dispatches them again.
        }
    }

    private async Task RunAsync(AgentCommand command, CancellationToken token)
    {
        var started = Stopwatch.GetTimestamp();
        var spec = command.Deployment;
        var redactor = new Redactor(spec?.Redactions);
        Outcome outcome;
        try
        {
            if (OperatingSystem.IsWindows() && AgentRuntime.IsWindowsService)
            {
                outcome = await InstallAsync(command.CommandId, spec, redactor, token);
            }
            else
            {
                outcome = Outcome.Fail(DeploymentOutcomes.Failed, "Software installation requires the uAgent Windows service.");
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            _logger.LogWarning("The service is stopping; deployment {CommandId} was interrupted and the portal will retry it.", command.CommandId);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Deployment {CommandId} failed with {ErrorType}: {Error}", command.CommandId, ex.GetType().Name, redactor.Apply(ex.Message));
            outcome = Outcome.Fail(DeploymentOutcomes.Failed, $"The deployment stopped because of an unexpected error: {ex.Message}");
        }

        var duration = (int)Math.Round(Stopwatch.GetElapsedTime(started).TotalSeconds);
        var message = Trim(redactor.Apply(outcome.Message), 4000);
        var result = new CommandResult(
            command.CommandId,
            outcome.Success,
            outcome.Success ? null : Trim(message, 1000),
            DateTime.UtcNow,
            message,
            outcome.Code,
            outcome.ExitCode,
            outcome.RebootRequired,
            TrimTail(redactor.Apply(outcome.Log)),
            duration);

        _logger.Log(
            outcome.Success ? LogLevel.Information : LogLevel.Warning,
            "Deployment {CommandId} of {Package} finished in {Seconds}s: {Outcome}. {Message}",
            command.CommandId,
            redactor.Apply(Label(spec)),
            duration,
            outcome.Code,
            message);
        await PostResultAsync(result, token);
    }

    [SupportedOSPlatform("windows")]
    private async Task<Outcome> InstallAsync(Guid commandId, DeploymentSpec? spec, Redactor redactor, CancellationToken token)
    {
        if (spec is null)
        {
            return Outcome.Fail(DeploymentOutcomes.Failed, "The InstallSoftware command did not include a deployment specification.");
        }

        if (Validate(spec) is { } invalid)
        {
            return Outcome.Fail(DeploymentOutcomes.Failed, invalid);
        }

        var label = Label(spec);
        var detection = spec.Detection ?? new DetectionRule();
        var checkDetection = !SoftwareDetection.IsNone(detection);
        var notes = new List<string>();
        Task Progress(string stage, int? percent, string message) => ProgressAsync(commandId, stage, percent, message, redactor, token);

        await Progress(DeploymentStages.Checking, null, $"Checking whether {label} is already installed and the prerequisites are met.");
        if (checkDetection)
        {
            var existing = SoftwareDetection.Detect(detection);
            if (existing.Installed && !spec.Force)
            {
                return new Outcome(true, DeploymentOutcomes.AlreadyInstalled, $"{label} is already installed: {existing.Detail}. Nothing was changed.");
            }

            if (existing.Installed)
            {
                notes.Add($"{label} was already installed ({existing.Detail}); reinstalling because the deployment requested it.");
            }
        }

        if (SoftwareDetection.Check(spec.Prerequisites, spec.Size) is { } unmet)
        {
            return Outcome.Fail(unmet.Outcome, unmet.Message);
        }

        PackageCache.EnsureDirectory();
        var package = PackageCache.PathFor(spec);
        var partial = package + ".part";
        string? hash;
        if (PackageCache.IsVerified(package, spec))
        {
            hash = spec.Sha256;
            _logger.LogInformation("Deployment {CommandId}: using the verified cached package {Path}.", commandId, package);
        }
        else
        {
            PackageCache.TryDelete(package);
            if (File.Exists(partial) && new FileInfo(partial).Length > spec.Size)
            {
                PackageCache.TryDelete(partial);
            }

            PackageCache.Prune(PackageCache.LimitBytes - spec.Size, package, partial);
            var (failure, downloadedHash) = await DownloadAsync(commandId, spec, package, label, redactor, token);
            if (failure is not null)
            {
                return failure;
            }

            hash = downloadedHash;
        }

        await Progress(DeploymentStages.Verifying, null, "Verifying the package size, SHA-256 hash and digital signature.");
        var length = new FileInfo(package).Length;
        if (length != spec.Size)
        {
            PackageCache.TryDelete(package);
            return Outcome.Fail(
                DeploymentOutcomes.IntegrityFailed,
                $"The package is {length:N0} bytes but the portal expects {spec.Size:N0} bytes. It was deleted and not installed.");
        }

        if (!string.Equals(hash, spec.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            PackageCache.TryDelete(package);
            return Outcome.Fail(
                DeploymentOutcomes.IntegrityFailed,
                "The package's SHA-256 hash does not match the approved package. It was deleted and not installed.");
        }

        if (CheckSignature(spec, package) is { } signatureProblem)
        {
            PackageCache.TryDelete(package);
            return Outcome.Fail(DeploymentOutcomes.SignatureFailed, signatureProblem);
        }

        if (spec.ScanWithDefender)
        {
            await Progress(DeploymentStages.Scanning, null, "Scanning the package with Microsoft Defender.");
            var (threat, note) = await ScanAsync(package, token);
            if (threat)
            {
                PackageCache.TryDelete(package);
                return Outcome.Fail(DeploymentOutcomes.ThreatDetected, "Microsoft Defender reported a threat in the package. It was deleted and not installed.");
            }

            if (note is not null)
            {
                notes.Add(note);
            }
        }

        await Progress(DeploymentStages.Installing, null, $"Installing {label}.");
        var isMsi = string.Equals(spec.InstallerType, InstallerTypes.Msi, StringComparison.OrdinalIgnoreCase);
        var logPath = isMsi ? PackageCache.NewInstallLogPath(commandId) : null;
        var start = isMsi
            ? new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "msiexec.exe"), $"/i \"{package}\" /qn /norestart /l*v \"{logPath}\" {spec.Arguments}".TrimEnd())
            : new ProcessStartInfo(package, spec.Arguments) { RedirectStandardOutput = true, RedirectStandardError = true };
        start.WorkingDirectory = PackageCache.Directory;
        var timeout = spec.TimeoutSeconds > 0 ? TimeSpan.FromSeconds(Math.Min(spec.TimeoutSeconds, MaxInstallTimeout.TotalSeconds)) : DefaultInstallTimeout;

        _logger.LogInformation("Deployment {CommandId}: starting the {Type} installer for {Package} (timeout {Minutes} min).",
            commandId, isMsi ? "MSI" : "EXE", redactor.Apply(label), (int)timeout.TotalMinutes);
        var run = await InstallerProcess.RunAsync(start, timeout, token);
        var log = logPath is not null ? InstallerProcess.ReadLogTail(logPath) : run.Output;

        if (run.TimedOut || run.ExitCode is not { } exitCode)
        {
            return Outcome.Fail(
                DeploymentOutcomes.TimedOut,
                $"The installer did not finish within {FormatMinutes(timeout)}; it was stopped together with its child processes.",
                log: log);
        }

        var reason = isMsi ? InstallerProcess.DescribeWindowsError(exitCode) : string.Empty;
        var codeText = reason.Length > 0 ? $"exit code {exitCode}: {reason.TrimEnd('.')}" : $"exit code {exitCode}";
        bool rebootRequired;
        if ((spec.SuccessExitCodes is { Length: > 0 } success ? success : DefaultSuccessCodes).Contains(exitCode))
        {
            rebootRequired = false;
        }
        else if ((spec.RebootExitCodes ?? DefaultRebootCodes).Contains(exitCode))
        {
            rebootRequired = true;
        }
        else if ((spec.RetryExitCodes ?? DefaultRetryCodes).Contains(exitCode))
        {
            return Outcome.Fail(
                DeploymentOutcomes.Busy,
                $"The installer could not run because another installation is in progress ({codeText}). The portal will retry later.",
                exitCode,
                log);
        }
        else
        {
            return Outcome.Fail(DeploymentOutcomes.Failed, $"The installer failed ({codeText}).", exitCode, log);
        }

        if (checkDetection)
        {
            await Progress(DeploymentStages.Confirming, null, $"Confirming that {label} is installed.");
            var installed = SoftwareDetection.Detect(detection);
            if (!installed.Installed)
            {
                return new Outcome(
                    false,
                    DeploymentOutcomes.VerificationFailed,
                    $"The installer reported success ({codeText}), but the detection rule did not find {label} afterwards: {installed.Detail}.",
                    exitCode,
                    rebootRequired,
                    log);
            }
        }

        PackageCache.TryDelete(package);
        PackageCache.Prune(PackageCache.LimitBytes);

        var message = $"{label} was installed ({codeText}).";
        if (rebootRequired)
        {
            message += string.Equals(spec.RestartBehavior, RestartBehaviors.IfRequired, StringComparison.OrdinalIgnoreCase)
                ? " " + ScheduleRestart(label, spec.RestartDelayMinutes)
                : " A restart is required to finish; it was not scheduled because the deployment's restart behavior is Never.";
        }

        if (notes.Count > 0)
        {
            message += " " + string.Join(" ", notes);
        }

        return new Outcome(true, DeploymentOutcomes.Installed, message, exitCode, rebootRequired, log);
    }

    [SupportedOSPlatform("windows")]
    private async Task<(Outcome? Failure, string? Sha256)> DownloadAsync(Guid commandId, DeploymentSpec spec, string package, string label, Redactor redactor, CancellationToken token)
    {
        var state = _state.Current;
        if (!state.IsEnrolled)
        {
            return (Outcome.Fail(DeploymentOutcomes.DownloadFailed, "The agent is not registered with the manager, so the package could not be downloaded."), null);
        }

        var resumeFrom = File.Exists(package + ".part") ? new FileInfo(package + ".part").Length : 0;
        await ProgressAsync(
            commandId,
            DeploymentStages.Downloading,
            spec.Size > 0 ? (int)(resumeFrom * 100 / spec.Size) : null,
            resumeFrom > 0
                ? $"Resuming the download of {label} at {SoftwareDetection.FormatBytes(resumeFrom)} of {SoftwareDetection.FormatBytes(spec.Size)}."
                : $"Downloading {label} ({SoftwareDetection.FormatBytes(spec.Size)}).",
            redactor,
            token);

        var lastReport = Stopwatch.GetTimestamp();
        var download = await _client.DownloadPackageAsync(
            state.AgentId,
            _state.ApiKey,
            spec.DownloadUrl,
            package,
            async (received, total) =>
            {
                if (Stopwatch.GetElapsedTime(lastReport) < ProgressInterval)
                {
                    return;
                }

                lastReport = Stopwatch.GetTimestamp();
                var size = total is > 0 ? total.Value : spec.Size;
                await ProgressAsync(
                    commandId,
                    DeploymentStages.Downloading,
                    size > 0 ? (int)Math.Clamp(received * 100 / size, 0, 100) : null,
                    $"Downloaded {SoftwareDetection.FormatBytes(received)} of {SoftwareDetection.FormatBytes(size)}.",
                    redactor,
                    token);
            },
            token);

        return download.Success
            ? (null, download.Value)
            : (Outcome.Fail(DeploymentOutcomes.DownloadFailed, $"The package could not be downloaded: {download.Error}"), null);
    }

    [SupportedOSPlatform("windows")]
    private static string? CheckSignature(DeploymentSpec spec, string package)
    {
        var expected = spec.ExpectedSigner?.Trim() ?? string.Empty;
        if (!spec.RequireSignature && expected.Length == 0)
        {
            return null;
        }

        var signature = Authenticode.Inspect(package);
        if (!signature.Valid)
        {
            return $"The package must carry a valid digital signature, but it is {signature.Describe()}. It was deleted and not installed.";
        }

        var thumbprint = expected.Replace(" ", string.Empty, StringComparison.Ordinal);
        if (expected.Length > 0 &&
            !signature.Subject.Contains(expected, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(signature.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase))
        {
            return $"The package is signed by {signature.Subject} (thumbprint {signature.Thumbprint}), not by the expected signer {expected}. It was deleted and not installed.";
        }

        return null;
    }

    // Returns whether Defender found a threat, plus a note when no verdict was available.
    private static async Task<(bool Threat, string? Note)> ScanAsync(string package, CancellationToken token)
    {
        var scanner = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
        if (!File.Exists(scanner))
        {
            return (false, "The Microsoft Defender command-line scanner (MpCmdRun.exe) is not present on this computer, so the on-host scan was skipped.");
        }

        var start = new ProcessStartInfo(scanner)
        {
            ArgumentList = { "-Scan", "-ScanType", "3", "-File", package, "-DisableRemediation" },
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(package)!
        };
        var run = await InstallerProcess.RunAsync(start, ScanTimeout, token);
        return run switch
        {
            { TimedOut: true } => (false, $"The Microsoft Defender scan did not finish within {FormatMinutes(ScanTimeout)}, so no verdict was available; installation continued."),
            { ExitCode: 0 } => (false, null),
            { ExitCode: ThreatFoundExitCode } => (true, null),
            _ => (false, $"The Microsoft Defender scan ended with exit code {run.ExitCode}, so no verdict was available; installation continued.")
        };
    }

    [SupportedOSPlatform("windows")]
    private static string ScheduleRestart(string label, int delayMinutes)
    {
        var minutes = Math.Clamp(delayMinutes, 0, MaxRestartDelayMinutes);
        var when = minutes == 0 ? "now" : $"in {FormatMinutes(TimeSpan.FromMinutes(minutes))}";
        var comment = $"{label} was installed by uAgent and needs a restart. Windows will restart this computer {when}. Save your work.";
        var (code, _) = ServiceHardening.Run(
            "shutdown.exe",
            "/r",
            "/t",
            (minutes * 60).ToString(CultureInfo.InvariantCulture),
            "/d",
            "p:4:2",
            "/c",
            comment.Length <= 512 ? comment : comment[..512]);
        return code switch
        {
            0 => $"A restart is required and is scheduled {when}.",
            ShutdownAlreadyScheduled => "A restart is required; another restart or shutdown is already scheduled on this computer.",
            _ => $"A restart is required, but it could not be scheduled (shutdown.exe exited with code {code})."
        };
    }

    [SupportedOSPlatform("windows")]
    private static string? Validate(DeploymentSpec spec)
    {
        if (spec.Sha256 is not { Length: 64 } || !spec.Sha256.All(Uri.IsHexDigit))
        {
            return "The deployment specification does not contain a valid SHA-256 hash.";
        }

        if (spec.Size <= 0)
        {
            return "The deployment specification does not contain the package size.";
        }

        if (string.IsNullOrWhiteSpace(spec.DownloadUrl))
        {
            return "The deployment specification does not contain a download URL.";
        }

        var isMsi = string.Equals(spec.InstallerType, InstallerTypes.Msi, StringComparison.OrdinalIgnoreCase);
        if (!isMsi && !string.Equals(spec.InstallerType, InstallerTypes.Exe, StringComparison.OrdinalIgnoreCase))
        {
            return $"The installer type '{spec.InstallerType}' is not supported; expected msi or exe.";
        }

        if (!isMsi && string.IsNullOrWhiteSpace(spec.Arguments))
        {
            return "EXE packages need silent-install arguments, and none were provided.";
        }

        if (!SoftwareDetection.IsSupported(spec.Detection?.Type))
        {
            return $"The detection rule type '{spec.Detection?.Type}' is not supported.";
        }

        return null;
    }

    private async Task ProgressAsync(Guid commandId, string stage, int? percent, string message, Redactor redactor, CancellationToken token)
    {
        var state = _state.Current;
        if (!state.IsEnrolled)
        {
            return;
        }

        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(ProgressTimeout);
            await _client.PostDeploymentProgressAsync(
                state.AgentId,
                _state.ApiKey,
                new DeploymentProgress(commandId, stage, percent, redactor.Apply(message)),
                timeout.Token);
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        {
            // Progress is best effort; the final result is what counts.
        }
    }

    private async Task PostResultAsync(CommandResult result, CancellationToken token)
    {
        for (var attempt = 1; attempt <= ResultAttempts; attempt++)
        {
            var state = _state.Current;
            if (state.IsEnrolled)
            {
                var posted = await _client.PostResultsAsync(state.AgentId, _state.ApiKey, [result], token);
                if (posted.Success)
                {
                    return;
                }

                _logger.LogWarning("The result of deployment {CommandId} could not be delivered (attempt {Attempt} of {Attempts}): {Error}",
                    result.CommandId, attempt, ResultAttempts, posted.Error);
            }

            if (attempt < ResultAttempts)
            {
                await Task.Delay(TimeSpan.FromSeconds(10 * attempt), token);
            }
        }
    }

    private static string Label(DeploymentSpec? spec)
    {
        if (spec is null)
        {
            return "the package";
        }

        var label = $"{spec.PackageName} {spec.PackageVersion}".Trim();
        return label.Length > 0 ? label : string.IsNullOrWhiteSpace(spec.FileName) ? "the package" : spec.FileName;
    }

    private static string FormatMinutes(TimeSpan span)
    {
        var minutes = (int)Math.Round(span.TotalMinutes);
        if (minutes < 1)
        {
            var seconds = (int)Math.Ceiling(span.TotalSeconds);
            return seconds == 1 ? "1 second" : $"{seconds} seconds";
        }

        return minutes == 1 ? "1 minute" : $"{minutes} minutes";
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

    private static string? TrimTail(string? log)
    {
        if (string.IsNullOrWhiteSpace(log))
        {
            return null;
        }

        return log.Length <= InstallerProcess.TailLength ? log : log[^InstallerProcess.TailLength..];
    }

    private sealed record Outcome(bool Success, string Code, string Message, int? ExitCode = null, bool? RebootRequired = null, string? Log = null)
    {
        public static Outcome Fail(string code, string message, int? exitCode = null, string? log = null) =>
            new(false, code, message, exitCode, null, log);
    }
}

// Replaces every secret value the portal resolved into the command with a fixed mask.
internal sealed class Redactor
{
    public const string Mask = "********";

    private readonly string[] _values;

    public Redactor(IEnumerable<string>? values)
    {
        _values = (values ?? [])
            .Where(value => !string.IsNullOrEmpty(value))
            .Distinct(StringComparer.Ordinal)
            .OrderByDescending(value => value.Length)
            .ToArray();
    }

    [return: NotNullIfNotNull(nameof(text))]
    public string? Apply(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return text;
        }

        foreach (var value in _values)
        {
            text = text.Replace(value, Mask, StringComparison.Ordinal);
        }

        return text;
    }
}
