using System.Text;
using System.Text.Json;

namespace uAgent.Agent;

// Connection details the portal appends to each downloaded installer. The block carries the manager URL,
// the certificate pin and the current enrollment key, which is only good for registering; every agent then
// receives its own credential. The marker format must match portal/lib/installerPackage.js.
internal sealed record EmbeddedConfig(string ManagerUrl, string EnrollmentKey, string CertificatePin, string IssuedUtc)
{
    private const string BeginMarker = "#UAGENT-CONFIG-V1:";
    private const string EndMarker = ":UAGENT-CONFIG-END#";
    private const int TailBytes = 64 * 1024;

    public static EmbeddedConfig? ReadFromCurrentExecutable()
    {
        var path = Environment.ProcessPath;
        return string.IsNullOrEmpty(path) ? null : ReadFrom(path);
    }

    public static EmbeddedConfig? ReadFrom(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var length = (int)Math.Min(stream.Length, TailBytes);
            var buffer = new byte[length];
            stream.Seek(-length, SeekOrigin.End);
            stream.ReadExactly(buffer);

            var text = Encoding.ASCII.GetString(buffer);
            var begin = text.LastIndexOf(BeginMarker, StringComparison.Ordinal);
            if (begin < 0)
            {
                return null;
            }

            var start = begin + BeginMarker.Length;
            var end = text.IndexOf(EndMarker, start, StringComparison.Ordinal);
            if (end < 0)
            {
                return null;
            }

            var json = Encoding.UTF8.GetString(Convert.FromBase64String(text[start..end]));
            var config = JsonSerializer.Deserialize<EmbeddedConfig>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            return config is not null && Uri.TryCreate(config.ManagerUrl, UriKind.Absolute, out _) ? config : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException or JsonException)
        {
            return null;
        }
    }
}
