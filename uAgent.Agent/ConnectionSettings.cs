using Microsoft.Extensions.Options;

namespace uAgent.Agent;

// Effective manager connection: the saved registration wins, then the block embedded in the installer,
// then configuration (appsettings / environment).
internal sealed class ConnectionSettings
{
    private readonly AgentStateStore _state;
    private readonly IOptionsMonitor<DashboardOptions> _options;
    private readonly EmbeddedConfig? _embedded;

    public ConnectionSettings(AgentStateStore state, IOptionsMonitor<DashboardOptions> options)
    {
        _state = state;
        _options = options;
        _embedded = EmbeddedConfig.ReadFromCurrentExecutable();
    }

    public string ManagerUrl => First(_state.Current.ManagerUrl, _embedded?.ManagerUrl, _options.CurrentValue.BaseUrl);

    public string CertificatePin => First(_state.Current.CertificatePin, _embedded?.CertificatePin, _options.CurrentValue.TrustedCertificateThumbprint);

    public TrustMaterial Trust
    {
        get
        {
            var state = _state.Current;
            return new TrustMaterial(
                CertificatePin,
                First(state.SpkiPin, _embedded?.SpkiPin),
                First(state.CaCertificate, _embedded?.CaCertificate));
        }
    }

    public string EnrollmentKey => First(_state.EnrollmentKey, _embedded?.EnrollmentKey, _options.CurrentValue.ApiKey);

    private static string First(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value))?.Trim() ?? string.Empty;
}
