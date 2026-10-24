namespace uAgent.Agent;

// Manager connection defaults. Installed agents normally take these from the installer's embedded settings
// and then from their saved registration; configuration only fills in what neither provides.
public sealed class DashboardOptions
{
    public const string SectionName = "Dashboard";

    public string BaseUrl { get; set; } = "https://uagent.helixops.ai";

    // Enrollment key used only to register. After registration the agent uses its own credential.
    public string ApiKey { get; set; } = string.Empty;

    // SHA-256 fingerprint of the manager certificate, used to trust a self-signed certificate
    // without disabling validation. Leave empty when the manager uses a publicly trusted certificate.
    public string TrustedCertificateThumbprint { get; set; } = string.Empty;
}
