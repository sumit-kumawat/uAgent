using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace uAgent.Agent;

// How the agent decides to trust the manager's TLS certificate. Validation is never switched off:
//   1. A certificate that passes normal Windows validation (trusted chain, matching host name, in date).
//   2. A certificate issued by the private root CA embedded by the portal. The chain is rebuilt against
//      that root only, and the host name must still match.
//   3. Lab only: a self-signed certificate whose public key (or exact certificate) matches the pin
//      embedded by the portal.
internal sealed record TrustMaterial(string CertificatePin, string SpkiPin, string CaCertificatePem)
{
    public static readonly TrustMaterial None = new(string.Empty, string.Empty, string.Empty);

    public bool HasPin => CertificateTrust.Normalize(CertificatePin).Length == 64 || CertificateTrust.Normalize(SpkiPin).Length == 64;

    public string Describe() =>
        CaCertificatePem.Length > 0 ? "Windows trust store or the portal's private root CA"
        : HasPin ? "Windows trust store or the pinned lab certificate"
        : "Windows trust store";
}

internal static class CertificateTrust
{
    private static string _lastFailure = string.Empty;

    // Why the most recent handshake was refused, for diagnostics and the status file.
    public static string LastFailure => Volatile.Read(ref _lastFailure);

    public static SocketsHttpHandler CreateHandler(Func<TrustMaterial> trustProvider)
    {
        return new SocketsHttpHandler
        {
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            ConnectTimeout = TimeSpan.FromSeconds(15),
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, certificate, chain, errors) =>
                    Validate(certificate as X509Certificate2 ?? (certificate is null ? null : new X509Certificate2(certificate)), chain, errors, trustProvider())
            }
        };
    }

    public static bool Validate(X509Certificate2? certificate, X509Chain? presented, SslPolicyErrors errors, TrustMaterial trust)
    {
        if (errors == SslPolicyErrors.None)
        {
            Volatile.Write(ref _lastFailure, string.Empty);
            return true;
        }

        if (certificate is null)
        {
            return Fail("The manager did not present a certificate.");
        }

        var nameMismatch = errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch);
        if (trust.CaCertificatePem.Length > 0)
        {
            if (nameMismatch)
            {
                return Fail($"The certificate does not cover the manager host name (it covers {Names(certificate)}). Reissue it from the portal Settings page.");
            }

            var status = BuildWithPrivateRoot(certificate, presented, trust.CaCertificatePem);
            if (status.Length == 0)
            {
                Volatile.Write(ref _lastFailure, string.Empty);
                return true;
            }

            return Fail($"The certificate chain does not lead to the portal's private root CA: {status}.");
        }

        if (trust.HasPin)
        {
            if (Matches(SpkiHash(certificate), trust.SpkiPin) || Matches(certificate.GetCertHash(HashAlgorithmName.SHA256), trust.CertificatePin))
            {
                Volatile.Write(ref _lastFailure, string.Empty);
                return true;
            }

            return Fail($"The certificate does not match the pinned lab certificate (subject {certificate.Subject}). The portal certificate was replaced with a new key; reinstall the agent from the portal.");
        }

        return Fail(nameMismatch
            ? $"The certificate does not cover the manager host name (it covers {Names(certificate)})."
            : $"The certificate is not trusted by Windows ({errors}). Issuer: {certificate.Issuer}. Install the issuing root CA through Group Policy or Intune, or use a public CA certificate.");
    }

    private static string BuildWithPrivateRoot(X509Certificate2 certificate, X509Chain? presented, string rootPem)
    {
        X509Certificate2 root;
        try
        {
            root = X509Certificate2.CreateFromPem(rootPem);
        }
        catch (CryptographicException ex)
        {
            return $"the embedded root CA could not be read ({ex.Message})";
        }

        using (root)
        using (var chain = new X509Chain())
        {
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(root);
            // Internal CAs created by the portal do not publish revocation lists.
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1")); // Server authentication
            if (presented is not null)
            {
                foreach (var element in presented.ChainElements)
                {
                    chain.ChainPolicy.ExtraStore.Add(element.Certificate);
                }
            }

            if (chain.Build(certificate))
            {
                return string.Empty;
            }

            return string.Join(", ", chain.ChainStatus.Select(s => s.Status.ToString()).Distinct());
        }
    }

    public static byte[] SpkiHash(X509Certificate2 certificate) =>
        SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo());

    public static bool Matches(byte[] hash, string? pin)
    {
        var normalized = Normalize(pin);
        return normalized.Length == 64 &&
               string.Equals(Convert.ToHexString(hash), normalized, StringComparison.OrdinalIgnoreCase);
    }

    public static string Normalize(string? thumbprint) =>
        new((thumbprint ?? string.Empty).Where(Uri.IsHexDigit).ToArray());

    private static string Names(X509Certificate2 certificate)
    {
        var san = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        if (san is null)
        {
            return certificate.GetNameInfo(X509NameType.DnsName, false);
        }

        var names = san.EnumerateDnsNames().Concat(san.EnumerateIPAddresses().Select(ip => ip.ToString()));
        return string.Join(", ", names);
    }

    private static bool Fail(string reason)
    {
        Volatile.Write(ref _lastFailure, reason);
        return false;
    }
}
