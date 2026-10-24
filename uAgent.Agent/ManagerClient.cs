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

    public Task<ApiResult<JsonElement>> PostResultsAsync(string agentId, string apiKey, IReadOnlyList<CommandResult> results, CancellationToken token) =>
        SendAsync<JsonElement>(HttpMethod.Post, AgentPath(agentId, "command-results"), apiKey, results, token);

    public Task<ApiResult<UpdateManifest>> GetUpdateManifestAsync(string agentId, string apiKey, CancellationToken token) =>
        SendAsync<UpdateManifest>(HttpMethod.Get, AgentPath(agentId, "update/manifest"), apiKey, null, token);

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
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException && !token.IsCancellationRequested)
        {
            return new ApiResult<string>(false, 0, null, Describe(ex), null);
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
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException && !token.IsCancellationRequested)
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
        Uri.TryCreate(relative, UriKind.Absolute, out var absolute) && absolute.Scheme.StartsWith("http", StringComparison.Ordinal)
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
            System.Security.Authentication.AuthenticationException => "The manager's TLS certificate is not trusted. Use a publicly trusted certificate or set the certificate pin.",
            System.Net.Sockets.SocketException socket when socket.SocketErrorCode == System.Net.Sockets.SocketError.HostNotFound => $"The manager host name could not be resolved ({root.Message}). Check DNS.",
            System.Net.Sockets.SocketException => $"The manager could not be reached: {root.Message}.",
            TimeoutException or TaskCanceledException => "The manager did not respond in time.",
            _ => root.Message
        };
    }
}
