using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace uAgent.Agent;

internal sealed record DiagnosticStep(string Name, bool Ok, string Detail, long Milliseconds);

internal sealed record DiagnosticReport(IReadOnlyList<DiagnosticStep> Steps, DateTime CheckedUtc)
{
    public bool Ok => Steps.All(s => s.Ok);

    public DiagnosticStep? FirstFailure => Steps.FirstOrDefault(s => !s.Ok);

    public string Summary => FirstFailure is { } failed ? $"{failed.Name}: {failed.Detail}" : "All connectivity checks passed.";
}

// Walks the path from this computer to the manager one layer at a time, so a failure names its layer:
// URL, DNS, proxy, TCP (routing/firewall), TLS (trust/host name), the health endpoint, then the agent API.
internal static class ConnectivityDiagnostics
{
    private static readonly TimeSpan StepTimeout = TimeSpan.FromSeconds(10);

    public static async Task<DiagnosticReport> RunAsync(string managerUrl, TrustMaterial trust, CancellationToken token)
    {
        var steps = new List<DiagnosticStep>();
        var clock = Stopwatch.StartNew();

        void Add(string name, bool ok, string detail)
        {
            steps.Add(new DiagnosticStep(name, ok, detail, clock.ElapsedMilliseconds));
            clock.Restart();
        }

        if (!Uri.TryCreate(managerUrl, UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http"))
        {
            Add("Manager URL", false, $"'{managerUrl}' is not an http(s) URL. Run 'uAgent.exe /configure /manager=https://HOST'.");
            return new DiagnosticReport(steps, DateTime.UtcNow);
        }

        Add("Manager URL", true, uri.Scheme == "https" ? uri.GetLeftPart(UriPartial.Authority) : $"{uri.GetLeftPart(UriPartial.Authority)} (plain HTTP: credentials are not encrypted)");

        IPAddress[] addresses;
        if (IPAddress.TryParse(uri.Host, out var literal))
        {
            addresses = [literal];
            Add("DNS", true, $"{uri.Host} is an IP address; no lookup needed.");
        }
        else
        {
            try
            {
                using var dnsTimeout = CancellationTokenSource.CreateLinkedTokenSource(token);
                dnsTimeout.CancelAfter(StepTimeout);
                addresses = await Dns.GetHostAddressesAsync(uri.Host, dnsTimeout.Token);
                Add("DNS", addresses.Length > 0, addresses.Length > 0
                    ? $"{uri.Host} resolves to {string.Join(", ", addresses.Select(a => a.ToString()))}."
                    : $"{uri.Host} has no address records.");
                if (addresses.Length == 0)
                {
                    return new DiagnosticReport(steps, DateTime.UtcNow);
                }
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException)
            {
                Add("DNS", false, $"{uri.Host} does not resolve from this computer ({Reason(ex)}). Add a DNS A record for it, or set the manager address to an IP in the portal Settings and reinstall.");
                return new DiagnosticReport(steps, DateTime.UtcNow);
            }
        }

        var proxy = HttpClient.DefaultProxy.GetProxy(uri);
        var proxied = proxy is not null && proxy != uri;
        Add("Proxy", true, proxied ? $"Requests go through the proxy {proxy}." : "Direct connection (no proxy for this address).");

        var port = uri.Port;
        var connected = false;
        var tcpErrors = new List<string>();
        foreach (var address in addresses.Take(4))
        {
            using var client = new TcpClient(address.AddressFamily);
            using var tcpTimeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            tcpTimeout.CancelAfter(StepTimeout);
            try
            {
                await client.ConnectAsync(address, port, tcpTimeout.Token);
                connected = true;
                Add("TCP", true, $"Connected to {address}:{port}.");
                break;
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException)
            {
                tcpErrors.Add($"{address}:{port} {Reason(ex)}");
            }
        }

        if (!connected && !proxied)
        {
            Add("TCP", false, $"Could not open a connection ({string.Join("; ", tcpErrors)}). Check that the portal is running, that the server firewall allows TCP {port}, and that outbound TCP {port} is allowed from this computer.");
            return new DiagnosticReport(steps, DateTime.UtcNow);
        }

        if (!connected)
        {
            Add("TCP", true, $"Direct connection failed ({string.Join("; ", tcpErrors)}); continuing through the proxy.");
        }

        if (uri.Scheme == "https" && connected)
        {
            var tls = await CheckTlsAsync(uri, addresses[0], trust, token);
            Add("TLS", tls.Ok, tls.Detail);
            if (!tls.Ok)
            {
                return new DiagnosticReport(steps, DateTime.UtcNow);
            }
        }

        using var handler = CertificateTrust.CreateHandler(() => trust);
        using var http = new HttpClient(handler) { Timeout = StepTimeout };
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"uAgent/{AgentRuntime.Version}");
        var baseUri = new Uri(uri.GetLeftPart(UriPartial.Authority) + "/");
        try
        {
            using var health = await http.GetAsync(new Uri(baseUri, "healthz"), token);
            Add("Portal health", health.IsSuccessStatusCode, health.IsSuccessStatusCode
                ? "The portal answered /healthz."
                : $"/healthz answered HTTP {(int)health.StatusCode}. A proxy or another web server may be answering on this address.");
            if (!health.IsSuccessStatusCode)
            {
                return new DiagnosticReport(steps, DateTime.UtcNow);
            }

            using var info = await http.GetAsync(new Uri(baseUri, "download/agent/info"), token);
            var body = await info.Content.ReadAsStringAsync(token);
            var isPortal = info.IsSuccessStatusCode && body.Contains("\"downloadPath\"", StringComparison.Ordinal);
            Add("Agent API", isPortal, isPortal
                ? "The uAgent API is reachable; registration requests will be accepted or rejected with a reason."
                : $"The address answered but is not a uAgent portal (HTTP {(int)info.StatusCode}).");
        }
        catch (Exception ex)
        {
            Add("Portal health", false, ManagerClient.Describe(ex));
        }

        return new DiagnosticReport(steps, DateTime.UtcNow);
    }

    private static async Task<(bool Ok, string Detail)> CheckTlsAsync(Uri uri, IPAddress address, TrustMaterial trust, CancellationToken token)
    {
        X509Certificate2? presented = null;
        var accepted = false;
        try
        {
            using var client = new TcpClient(address.AddressFamily);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(StepTimeout);
            await client.ConnectAsync(address, uri.Port, timeout.Token);
            await using var ssl = new SslStream(client.GetStream(), false, (_, certificate, chain, errors) =>
            {
                presented = certificate is null ? null : new X509Certificate2(certificate);
                accepted = CertificateTrust.Validate(presented, chain, errors, trust);
                return accepted;
            });
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = uri.IdnHost }, timeout.Token);
            return (true, $"Certificate {presented?.Subject} issued by {presented?.Issuer}, valid until {presented?.NotAfter:yyyy-MM-dd}, trusted via {trust.Describe()}.");
        }
        catch (Exception ex) when (!accepted)
        {
            var reason = CertificateTrust.LastFailure;
            return (false, reason.Length > 0 ? reason : $"The TLS handshake failed: {Reason(ex)}. Check that port {uri.Port} serves HTTPS.");
        }
        catch (Exception ex)
        {
            return (false, $"The TLS session failed after the certificate was accepted: {Reason(ex)}.");
        }
        finally
        {
            presented?.Dispose();
        }
    }

    private static string Reason(Exception ex) => ex switch
    {
        OperationCanceledException => "timed out",
        SocketException socket => socket.SocketErrorCode switch
        {
            SocketError.ConnectionRefused => "connection refused: nothing is listening, or a firewall rejected it",
            SocketError.TimedOut => "timed out: a firewall may be dropping the traffic",
            SocketError.HostUnreachable or SocketError.NetworkUnreachable => "no route to the host",
            SocketError.HostNotFound or SocketError.NoData => "host not found",
            SocketError.TryAgain => "temporary DNS failure",
            _ => socket.Message
        },
        _ => (ex.InnerException ?? ex).Message
    };
}
