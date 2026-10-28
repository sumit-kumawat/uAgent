using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace uAgent.Agent;

internal sealed record TrustMaterial(string CertificatePin, string SpkiPin, string CaCertificatePem)
{
    public static readonly TrustMaterial None = new(string.Empty, string.Empty, string.Empty);

    public bool HasPin => CertificateTrust.Normalize(CertificatePin).Length == 64 || CertificateTrust.Normalize(SpkiPin).Length == 64;

    public string Describe() =>
        CaCertificatePem.Length > 0 ? "Windows trust store or the portal's private root CA"
        : HasPin ? "Windows trust store or the pinned certificate"
        : "Windows trust store";
}

internal static class CertificateTrust
{
    private static string _lastFailure = string.Empty;
    private static string[] _recoveryNames = [];

    // Why the most recent handshake was refused, for diagnostics and the status file.
    public static string LastFailure => Volatile.Read(ref _lastFailure);

    // Host names the manager's certificate vouches for, recorded when a handshake was refused only because
    // the address in use is not one of them. The certificate chain itself was verified against a trusted
    // root, so a certificate authority has asserted these names and the agent may try them as a new
    // address. Each one is still checked end to end, including this agent's credential, before it is used.
    public static IReadOnlyList<string> RecoveryNames => Volatile.Read(ref _recoveryNames);

    public static SocketsHttpHandler CreateHandler(Func<TrustMaterial> trustProvider)
    {
        return new SocketsHttpHandler
        {
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            // Below the manager's 65 s keep-alive and common firewall/NAT idle limits, so an idle connection
            // is closed here first rather than reused after the other side has dropped it.
            PooledConnectionIdleTimeout = TimeSpan.FromSeconds(50),
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
            Succeed();
            return true;
        }

        if (certificate is null)
        {
            return Fail("The manager did not present a certificate.");
        }

        var nameMismatch = errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch);
        if (trust.CaCertificatePem.Length > 0)
        {
            var status = BuildWithPrivateRoot(certificate, presented, trust.CaCertificatePem);
            if (status.Length > 0)
            {
                return Fail($"The certificate chain does not lead to the trusted root CA: {status}.");
            }

            if (nameMismatch)
            {
                return Fail($"The certificate does not cover the manager host name (it covers {Names(certificate)}).", certificate);
            }

            Succeed();
            return true;
        }

        if (trust.HasPin)
        {
            if (Matches(SpkiHash(certificate), trust.SpkiPin) || Matches(certificate.GetCertHash(HashAlgorithmName.SHA256), trust.CertificatePin))
            {
                Succeed();
                return true;
            }

            // The pinned key is gone, but the replacement may still be verifiable in its own right, in which
            // case the names it carries are a way back to the manager.
            return Fail($"The certificate does not match the pinned certificate (subject {certificate.Subject}). The portal certificate was replaced with a new key; reinstall the agent from the portal.",
                errors == SslPolicyErrors.RemoteCertificateNameMismatch ? certificate : null);
        }

        // Only the name check failed, so Windows verified the chain to a trusted root.
        if (errors == SslPolicyErrors.RemoteCertificateNameMismatch)
        {
            return Fail($"The certificate does not cover the manager host name (it covers {Names(certificate)}).", certificate);
        }

        return Fail(nameMismatch
            ? $"The certificate does not cover the manager host name (it covers {Names(certificate)})."
            : $"The certificate is not trusted by Windows ({errors}). Issuer: {certificate.Issuer}. Install the issuing root CA through Group Policy or Intune, or use a public CA certificate.");
    }

    private static void Succeed()
    {
        Volatile.Write(ref _lastFailure, string.Empty);
        Volatile.Write(ref _recoveryNames, []);
    }

    private static string[] DnsNames(X509Certificate2 certificate)
    {
        var san = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        var names = san is not null
            ? san.EnumerateDnsNames()
            : [certificate.GetNameInfo(X509NameType.DnsName, false)];
        return names
            .Where(name => !string.IsNullOrWhiteSpace(name) && !name.StartsWith('*') && Uri.CheckHostName(name) == UriHostNameType.Dns)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
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

    // `verified` is the manager's certificate when its chain was trusted and only the host name did not
    // match, which is the one case where the names inside it can be trusted as a recovery address.
    private static bool Fail(string reason, X509Certificate2? verified = null)
    {
        Volatile.Write(ref _lastFailure, reason);
        Volatile.Write(ref _recoveryNames, verified is null ? [] : DnsNames(verified));
        return false;
    }
}
