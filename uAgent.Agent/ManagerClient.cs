using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using uAgent.Shared;

namespace uAgent.Agent;

internal sealed record ApiResult<T>(bool Success, int StatusCode, string? ErrorCode, string? Error, T? Value)
{
    public bool IsNetworkError => StatusCode == 0;

    public static ApiResult<T> Ok(int statusCode, T? value) => new(true, statusCode, null, null, value);
}

// Talks to the uAgent manager. Every agent request carries the agent's own credential in X-Api-Key;
// only enrollment uses the enrollment key.
internal sealed class ManagerClient
{
    public const string HttpClientName = "Manager";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly TimeSpan DownloadStallTimeout = TimeSpan.FromSeconds(120);

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ConnectionSettings _connection;

    public ManagerClient(IHttpClientFactory httpClientFactory, ConnectionSettings connection)
    {
        _httpClientFactory = httpClientFactory;
        _connection = connection;
    }

    public Task<ApiResult<EnrollmentResponse>> EnrollAsync(string enrollmentKey, EnrollmentRequest request, CancellationToken token) =>
        SendAsync<EnrollmentResponse>(HttpMethod.Post, "api/agents/enroll", enrollmentKey, request, token);

    public Task<ApiResult<HeartbeatResponse>> HeartbeatAsync(string agentId, string apiKey, Heartbeat heartbeat, CancellationToken token) =>
        SendAsync<HeartbeatResponse>(HttpMethod.Post, AgentPath(agentId, "heartbeat"), apiKey, heartbeat, token);

    public Task<ApiResult<JsonElement>> PostReportAsync(string agentId, string apiKey, AccountStatusReport report, CancellationToken token) =>
        SendAsync<JsonElement>(HttpMethod.Post, AgentPath(agentId, "report"), apiKey, report, token);

    public Task<ApiResult<List<AgentCommand>>> GetCommandsAsync(string agentId, string apiKey, CancellationToken token) =>
        SendAsync<List<AgentCommand>>(HttpMethod.Get, AgentPath(agentId, "commands"), apiKey, null, token);

    public Task<ApiResult<AgentPollResponse>> PollAsync(string agentId, string apiKey, int waitSeconds, CancellationToken token) =>
        SendAsync<AgentPollResponse>(HttpMethod.Get, AgentPath(agentId, $"poll?wait={waitSeconds}"), apiKey, null, token);

    public Task<ApiResult<JsonElement>> PostInventoryAsync(string agentId, string apiKey, InventoryUpload upload, CancellationToken token) =>
        SendAsync<JsonElement>(HttpMethod.Post, AgentPath(agentId, "inventory"), apiKey, upload, token);

    public Task<ApiResult<JsonElement>> PostEventAsync(string agentId, string apiKey, AgentEvent agentEvent, CancellationToken token) =>
        SendAsync<JsonElement>(HttpMethod.Post, AgentPath(agentId, "events"), apiKey, agentEvent, token);

    public Task<ApiResult<JsonElement>> PostResultsAsync(string agentId, string apiKey, IReadOnlyList<CommandResult> results, CancellationToken token) =>
        SendAsync<JsonElement>(HttpMethod.Post, AgentPath(agentId, "command-results"), apiKey, results, token);

    public Task<ApiResult<JsonElement>> PostDeploymentProgressAsync(string agentId, string apiKey, DeploymentProgress progress, CancellationToken token) =>
        SendAsync<JsonElement>(HttpMethod.Post, AgentPath(agentId, "deployments/progress"), apiKey, progress, token);

    public Task<ApiResult<UpdateManifest>> GetUpdateManifestAsync(string agentId, string apiKey, CancellationToken token) =>
        SendAsync<UpdateManifest>(HttpMethod.Get, AgentPath(agentId, "update/manifest"), apiKey, null, token);

    // Asks a candidate manager address whether it accepts this agent's credential, before switching to it.
    public async Task<string?> VerifyAddressAsync(string candidateUrl, string agentId, string apiKey, TrustMaterial trust, CancellationToken token)
    {
        try
        {
            using var handler = CertificateTrust.CreateHandler(() => trust);
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };
            using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(new Uri(WithTrailingSlash(candidateUrl)), AgentPath(agentId, "whoami").TrimStart('/')));
            request.Headers.TryAddWithoutValidation(ApiHeaders.ApiKey, apiKey);
            using var response = await http.SendAsync(request, token);
            return response.IsSuccessStatusCode ? null : $"{candidateUrl} answered HTTP {(int)response.StatusCode} for this agent's credential.";
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !token.IsCancellationRequested)
        {
            return Describe(ex);
        }
    }

    public Task<ApiResult<JsonElement>> DeregisterAsync(string agentId, string apiKey, CancellationToken token) =>
        SendAsync<JsonElement>(HttpMethod.Post, AgentPath(agentId, "deregister"), apiKey, new { reason = "Uninstalled by an administrator" }, token);

    public async Task<ApiResult<JsonElement>> ProbeAsync(CancellationToken token)
    {
        return await SendAsync<JsonElement>(HttpMethod.Get, "healthz", null, null, token);
    }

    // Streams the update package to disk and returns its SHA-256 (hex).
    public async Task<ApiResult<string>> DownloadUpdateAsync(string agentId, string apiKey, string packageUrl, string destination, CancellationToken token)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, Resolve(packageUrl));
            request.Headers.TryAddWithoutValidation(ApiHeaders.ApiKey, apiKey);
            var client = _httpClientFactory.CreateClient(HttpClientName);
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token);
            if (!response.IsSuccessStatusCode)
            {
                return await FailureAsync<string>(response, token);
            }

            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            await using (var source = await response.Content.ReadAsStreamAsync(token))
            await using (var target = new FileStream(destination, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                await source.CopyToAsync(target, token);
            }

            await using var verify = File.OpenRead(destination);
            var hash = Convert.ToHexString(await SHA256.HashDataAsync(verify, token));
            return ApiResult<string>.Ok((int)response.StatusCode, hash);
        }
        catch (Exception ex) when (!token.IsCancellationRequested &&
                                   ex is HttpRequestException or TaskCanceledException or IOException)
        {
            return new ApiResult<string>(false, 0, null, Describe(ex), null);
        }
    }

    // Downloads into "<destination>.part", resuming from its current length with a Range request, then moves the
    // completed file to destination and returns its SHA-256 (lowercase hex). An interrupted or cancelled
    // download leaves the .part file in place for the next attempt.
    public async Task<ApiResult<string>> DownloadPackageAsync(
        string agentId,
        string apiKey,
        string packageUrl,
        string destination,
        Func<long, long?, Task>? progress,
        CancellationToken token)
    {
        var partial = destination + ".part";
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            for (var attempt = 0; ; attempt++)
            {
                var offset = File.Exists(partial) ? new FileInfo(partial).Length : 0;
                using var request = new HttpRequestMessage(HttpMethod.Get, Resolve(packageUrl));
                request.Headers.TryAddWithoutValidation(ApiHeaders.ApiKey, apiKey);
                if (offset > 0)
                {
                    request.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(offset, null);
                }

                var client = _httpClientFactory.CreateClient(HttpClientName);
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token);
                if (response.StatusCode == System.Net.HttpStatusCode.RequestedRangeNotSatisfiable && attempt == 0)
                {
                    File.Delete(partial);
                    continue;
                }

                if (!response.IsSuccessStatusCode)
                {
                    return await FailureAsync<string>(response, token);
                }

                var resumed = response.StatusCode == System.Net.HttpStatusCode.PartialContent;
                if (resumed && response.Content.Headers.ContentRange?.From != offset)
                {
                    if (attempt > 0)
                    {
                        return new ApiResult<string>(false, (int)response.StatusCode, null, "The manager answered the resume request with an unexpected byte range.", null);
                    }

                    File.Delete(partial);
                    continue;
                }

                var start = resumed ? offset : 0;
                var total = resumed
                    ? response.Content.Headers.ContentRange?.Length
                    : response.Content.Headers.ContentLength;
                await using (var source = await response.Content.ReadAsStreamAsync(token))
                await using (var target = new FileStream(partial, resumed ? FileMode.Append : FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    await CopyWithProgressAsync(source, target, start, total, progress, token);
                }

                File.Move(partial, destination, overwrite: true);
                await using var verify = File.OpenRead(destination);
                var hash = Convert.ToHexString(await SHA256.HashDataAsync(verify, token)).ToLowerInvariant();
                return ApiResult<string>.Ok((int)response.StatusCode, hash);
            }
        }
        catch (TimeoutException ex)
        {
            return new ApiResult<string>(false, 0, null, ex.Message, null);
        }
        catch (Exception ex) when (!token.IsCancellationRequested &&
                                   ex is HttpRequestException or TaskCanceledException or IOException or UnauthorizedAccessException)
        {
            return new ApiResult<string>(false, 0, null, Describe(ex), null);
        }
    }

    // HttpClient.Timeout does not cover the body of a streamed response, so a stalled transfer is bounded here.
    private static async Task CopyWithProgressAsync(
        Stream source,
        Stream target,
        long received,
        long? total,
        Func<long, long?, Task>? progress,
        CancellationToken token)
    {
        var buffer = new byte[81920];
        using var stall = CancellationTokenSource.CreateLinkedTokenSource(token);
        while (true)
        {
            stall.CancelAfter(DownloadStallTimeout);
            int read;
            try
            {
                read = await source.ReadAsync(buffer, stall.Token);
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested)
            {
                throw new TimeoutException($"The download stalled: no data arrived for {DownloadStallTimeout.TotalSeconds:0} seconds.");
            }

            if (read == 0)
            {
                break;
            }

            await target.WriteAsync(buffer.AsMemory(0, read), token);
            received += read;
            if (progress is not null)
            {
                await progress(received, total);
            }
        }
    }

    private async Task<ApiResult<T>> SendAsync<T>(HttpMethod method, string relative, string? apiKey, object? body, CancellationToken token)
    {
        if (!Uri.TryCreate(WithTrailingSlash(_connection.ManagerUrl), UriKind.Absolute, out _))
        {
            return new ApiResult<T>(false, 0, null, $"The manager URL '{_connection.ManagerUrl}' is not valid.", default);
        }

        try
        {
            using var request = new HttpRequestMessage(method, Resolve(relative));
            if (!string.IsNullOrEmpty(apiKey))
            {
                request.Headers.TryAddWithoutValidation(ApiHeaders.ApiKey, apiKey);
            }

            if (body is not null)
            {
                request.Content = JsonContent.Create(body, body.GetType(), options: JsonOptions);
            }

            var client = _httpClientFactory.CreateClient(HttpClientName);
            using var response = await client.SendAsync(request, token);
            if (!response.IsSuccessStatusCode)
            {
                return await FailureAsync<T>(response, token);
            }

            if (response.Content.Headers.ContentLength == 0 || response.StatusCode == System.Net.HttpStatusCode.NoContent)
            {
                return ApiResult<T>.Ok((int)response.StatusCode, default);
            }

            var value = await response.Content.ReadFromJsonAsync<T>(JsonOptions, token);
            return ApiResult<T>.Ok((int)response.StatusCode, value);
        }
        catch (Exception ex) when (!token.IsCancellationRequested &&
                                   ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            return new ApiResult<T>(false, 0, null, Describe(ex), default);
        }
    }

    private static async Task<ApiResult<T>> FailureAsync<T>(HttpResponseMessage response, CancellationToken token)
    {
        string? code = null;
        string? message = null;
        try
        {
            var error = await response.Content.ReadFromJsonAsync<JsonElement>(JsonOptions, token);
            if (error.ValueKind == JsonValueKind.Object)
            {
                code = error.TryGetProperty("code", out var c) ? c.GetString() : null;
                message = error.TryGetProperty("error", out var e) ? e.GetString() : null;
            }
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException or InvalidOperationException)
        {
            // Not a JSON error body; fall back to the status code.
        }

        return new ApiResult<T>(false, (int)response.StatusCode, code, message ?? $"The manager returned HTTP {(int)response.StatusCode}.", default);
    }

    private Uri Resolve(string relative) =>
        Uri.TryCreate(relative, UriKind.Absolute, out var absolute) && absolute.Scheme is "https" or "http"
            ? absolute
            : new Uri(new Uri(WithTrailingSlash(_connection.ManagerUrl)), relative.TrimStart('/'));

    private static string AgentPath(string agentId, string action) => $"api/agents/{Uri.EscapeDataString(agentId)}/{action}";

    private static string WithTrailingSlash(string url) => url.EndsWith('/') ? url : url + "/";

    public static string Describe(Exception ex)
    {
        var root = ex;
        while (root.InnerException is not null)
        {
            root = root.InnerException;
        }

        return root switch
        {
            System.Security.Authentication.AuthenticationException => CertificateTrust.LastFailure.Length > 0
                ? $"The manager's TLS certificate was refused: {CertificateTrust.LastFailure}"
                : $"The TLS handshake with the manager failed: {root.Message}",
            System.Net.Sockets.SocketException socket when socket.SocketErrorCode == System.Net.Sockets.SocketError.HostNotFound => $"The manager host name could not be resolved ({root.Message}). Check DNS.",
            System.Net.Sockets.SocketException => $"The manager could not be reached: {root.Message}.",
            TimeoutException or TaskCanceledException => "The manager did not respond in time.",
            _ => root.Message
        };
    }
}
