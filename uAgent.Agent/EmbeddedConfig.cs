using System.Text;
using System.Text.Json;

namespace uAgent.Agent;

// The marker format must remain compatible with the installer packaging process.
internal sealed record EmbeddedConfig(
    string ManagerUrl,
    string EnrollmentKey,
    string CertificatePin,
    string IssuedUtc,
    string? SpkiPin = null,
    string? CaCertificate = null)
{
    private const string BeginMarker = "#UAGENT-CONFIG-V1:";
    private const string EndMarker = ":UAGENT-CONFIG-END#";
    private const int TailBytes = 64 * 1024;

    public const string SidecarFileName = "uagent-install.json";

    // A signed installer is never modified, so its settings come from uagent-install.json in the same folder.
    public static EmbeddedConfig? ReadFromCurrentExecutable()
    {
        var path = Environment.ProcessPath;
        if (string.IsNullOrEmpty(path))
        {
            return null;
        }
        return ReadFrom(path) ?? ReadSidecar(Path.Combine(Path.GetDirectoryName(path) ?? ".", SidecarFileName));
    }

    public static EmbeddedConfig? ReadSidecar(string path)
    {
        try
        {
            if (!File.Exists(path) || new FileInfo(path).Length > TailBytes)
            {
                return null;
            }
            return Parse(File.ReadAllText(path, Encoding.UTF8));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    private static EmbeddedConfig? Parse(string json)
    {
        var config = JsonSerializer.Deserialize<EmbeddedConfig>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        return config is not null && Uri.TryCreate(config.ManagerUrl, UriKind.Absolute, out _) ? config : null;
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

            return Parse(Encoding.UTF8.GetString(Convert.FromBase64String(text[start..end])));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException or JsonException)
        {
            return null;
        }
    }
}
