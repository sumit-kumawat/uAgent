using System.Net.Security;
using System.Security.Cryptography;

namespace uAgent.Agent;

internal static class CertificateTrust
{
    // Accepts publicly trusted certificates as usual. When a pin is configured, a certificate that fails chain
    // validation is still accepted if its SHA-256 fingerprint matches exactly (certificate pinning), which lets
    // agents use the portal's self-signed certificate without turning validation off.
    public static SocketsHttpHandler CreateHandler(Func<string> pinProvider)
    {
        return new SocketsHttpHandler
        {
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            ConnectTimeout = TimeSpan.FromSeconds(15),
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
                    errors == SslPolicyErrors.None || (certificate is not null && Matches(certificate.GetCertHash(HashAlgorithmName.SHA256), pinProvider()))
            }
        };
    }

    public static bool Matches(byte[] certificateHash, string? pin)
    {
        var normalized = Normalize(pin);
        return normalized.Length == 64 &&
               string.Equals(Convert.ToHexString(certificateHash), normalized, StringComparison.OrdinalIgnoreCase);
    }

    public static string Normalize(string? thumbprint) =>
        new((thumbprint ?? string.Empty).Where(Uri.IsHexDigit).ToArray());
}
