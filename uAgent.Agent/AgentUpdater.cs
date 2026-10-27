using System.Diagnostics;
using uAgent.Shared;

namespace uAgent.Agent;

internal sealed record UpdatePlan(CommandResult Result, string? InstallerPath);

// Downloads the manager's current agent build and only hands it to the installer after validating it:
// the version must be newer, the SHA-256 must match the manifest fetched over the authenticated channel,
// and when the running build is Authenticode-signed the update must carry a valid signature from the same signer.
internal sealed class AgentUpdater
{
    private readonly ManagerClient _client;
    private readonly ILogger<AgentUpdater> _logger;

    public AgentUpdater(ManagerClient client, ILogger<AgentUpdater> logger)
    {
        _client = client;
        _logger = logger;
    }

    public async Task<UpdatePlan> PrepareAsync(string agentId, string apiKey, AgentCommand command, CancellationToken token)
    {
        if (!OperatingSystem.IsWindows() || !AgentRuntime.IsWindowsService)
        {
            return Fail(command, "Updates are installed only by the uAgent Windows service.");
        }

        var manifest = await _client.GetUpdateManifestAsync(agentId, apiKey, token);
        if (!manifest.Success || manifest.Value is null)
        {
            return Fail(command, $"The update manifest could not be retrieved: {manifest.Error}");
        }

        var offered = manifest.Value;
        if (!Version.TryParse(offered.Version, out var offeredVersion) || !Version.TryParse(AgentRuntime.Version, out var currentVersion))
        {
            return Fail(command, $"The offered version '{offered.Version}' could not be compared with {AgentRuntime.Version}.");
        }

        if (offeredVersion <= currentVersion)
        {
            return new UpdatePlan(
                new CommandResult(command.CommandId, true, null, DateTime.UtcNow, $"Already up to date: running {AgentRuntime.Version}; the manager offers {offered.Version}."),
                null);
        }

        var destination = Path.Combine(AgentPaths.UpdateDirectory, $"uAgent-{offeredVersion}.exe");
        var download = await _client.DownloadUpdateAsync(agentId, apiKey, offered.PackageUrl, destination, token);
        if (!download.Success || download.Value is null)
        {
            return Fail(command, $"The update could not be downloaded: {download.Error}");
        }

        if (!string.Equals(download.Value, offered.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            TryDelete(destination);
            return Fail(command, $"Integrity check failed: the downloaded file's SHA-256 {download.Value[..12]}… does not match the manifest. The update was discarded.");
        }

        var running = Authenticode.Inspect(Environment.ProcessPath ?? AgentPaths.InstalledExecutable);
        var update = Authenticode.Inspect(destination);
        if (running.Signed && !(update.Valid && string.Equals(update.Thumbprint, running.Thumbprint, StringComparison.OrdinalIgnoreCase)))
        {
            TryDelete(destination);
            return Fail(command, $"Signature check failed: the running agent is signed by {running.Subject} but the update is {update.Describe()}. The update was discarded.");
        }

        if (offered.Signed && !update.Valid)
        {
            TryDelete(destination);
            return Fail(command, $"Signature check failed: the manifest says the build is signed but the file is {update.Describe()}. The update was discarded.");
        }

        _logger.LogInformation("Update {Version} validated (SHA-256 {Sha}, {Signature}).", offered.Version, download.Value, update.Describe());
        return new UpdatePlan(
            new CommandResult(
                command.CommandId,
                true,
                null,
                DateTime.UtcNow,
                $"Update {AgentRuntime.Version} → {offered.Version} validated (SHA-256 {download.Value[..16]}…, {update.Describe()}). Installing now; the agent reconnects in about a minute."),
            destination);
    }

    public void Launch(string installerPath)
    {
        _logger.LogWarning("Starting the validated installer {Path} to upgrade the agent.", installerPath);
        using var process = Process.Start(new ProcessStartInfo(installerPath)
        {
            ArgumentList = { "/upgrade", "/quiet" },
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = AgentPaths.UpdateDirectory
        }) ?? throw new InvalidOperationException("The validated update installer could not be started.");
    }

    private static UpdatePlan Fail(AgentCommand command, string message) =>
        new(new CommandResult(command.CommandId, false, message, DateTime.UtcNow), null);

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Left in the ACL-protected updates folder; replaced by the next download.
        }
    }
}
