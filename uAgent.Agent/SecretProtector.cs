using System.Security.Cryptography;
using System.Text;

namespace uAgent.Agent;

// Secrets at rest are encrypted with DPAPI (machine scope) on Windows; the state file is also ACL'd to
// SYSTEM and Administrators. Other operating systems are development-only and store them base64-encoded
// in a file readable only by the owner.
internal static class SecretProtector
{
    private const string DpapiPrefix = "dpapi:";
    private const string PlainPrefix = "plain:";
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("uAgent.Credential.v1");

    public static string Protect(string? secret)
    {
        if (string.IsNullOrEmpty(secret))
        {
            return string.Empty;
        }

        var bytes = Encoding.UTF8.GetBytes(secret);
        if (OperatingSystem.IsWindows())
        {
            return DpapiPrefix + Convert.ToBase64String(ProtectedData.Protect(bytes, Entropy, DataProtectionScope.LocalMachine));
        }

        return PlainPrefix + Convert.ToBase64String(bytes);
    }

    public static string Unprotect(string? stored)
    {
        if (string.IsNullOrEmpty(stored))
        {
            return string.Empty;
        }

        try
        {
            if (stored.StartsWith(DpapiPrefix, StringComparison.Ordinal) && OperatingSystem.IsWindows())
            {
                var data = Convert.FromBase64String(stored[DpapiPrefix.Length..]);
                return Encoding.UTF8.GetString(ProtectedData.Unprotect(data, Entropy, DataProtectionScope.LocalMachine));
            }

            if (stored.StartsWith(PlainPrefix, StringComparison.Ordinal))
            {
                return Encoding.UTF8.GetString(Convert.FromBase64String(stored[PlainPrefix.Length..]));
            }
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            return string.Empty;
        }

        return string.Empty;
    }
}
