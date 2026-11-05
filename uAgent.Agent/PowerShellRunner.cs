using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace uAgent.Agent;

internal readonly record struct PowerShellResult(int ExitCode, string Output, string Error, bool TimedOut)
{
    public bool Success => !TimedOut && ExitCode == 0;
}

// Runs a fixed script in Windows PowerShell 5.1, which every supported Windows version ships with the
// NetSecurity, DnsClient and NetTCPIP modules. Values reach the script only as UAGENT_* environment
// variables of the child process, never in the script text or on the command line, so nothing a portal
// user types can change what runs and a password does not appear in process listings.
[SupportedOSPlatform("windows")]
internal static class PowerShellRunner
{
    private const string Preamble =
        "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.Encoding]::UTF8;";

    public static PowerShellResult Run(string script, IReadOnlyDictionary<string, string>? variables, TimeSpan timeout)
    {
        var exe = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        var start = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            WorkingDirectory = Environment.SystemDirectory
        };
        foreach (var arg in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand" })
        {
            start.ArgumentList.Add(arg);
        }

        start.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(Preamble + script)));
        foreach (var (key, value) in variables ?? new Dictionary<string, string>())
        {
            start.Environment["UAGENT_" + key] = value;
        }

        using var process = Process.Start(start) ?? throw new InvalidOperationException("PowerShell could not be started.");
        process.StandardInput.Close();
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(timeout))
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
                // Already exited.
            }

            return new PowerShellResult(-1, string.Empty, $"PowerShell did not finish within {(int)timeout.TotalSeconds} seconds.", true);
        }

        process.WaitForExit();
        return new PowerShellResult(process.ExitCode, output.Result.Trim(), CleanError(error.Result), false);
    }

    // The script writes one JSON document; anything else is a failure with PowerShell's own message.
    public static JsonElement RunJson(string script, TimeSpan timeout, IReadOnlyDictionary<string, string>? variables = null)
    {
        var result = Run(script, variables, timeout);
        if (!result.Success)
        {
            throw new InvalidOperationException(result.Error.Length > 0 ? result.Error : $"PowerShell exited with code {result.ExitCode}.");
        }

        if (result.Output.Length == 0)
        {
            return JsonDocument.Parse("null").RootElement.Clone();
        }

        using var document = JsonDocument.Parse(result.Output);
        return document.RootElement.Clone();
    }

    // PowerShell writes errors as CLIXML or with position details; keep the first meaningful lines.
    private static string CleanError(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return string.Empty;
        }

        var lines = raw.Replace("#< CLIXML", string.Empty, StringComparison.Ordinal)
            .Split('\n')
            .Select(l => l.Trim())
            .Where(l => l.Length > 0 && !l.StartsWith("At line:", StringComparison.Ordinal) && !l.StartsWith('+') &&
                        !l.StartsWith("<Objs", StringComparison.Ordinal) && !l.StartsWith("CategoryInfo", StringComparison.Ordinal) &&
                        !l.StartsWith("FullyQualifiedErrorId", StringComparison.Ordinal))
            .Take(4);
        var text = string.Join(" ", lines);
        return text.Length > 600 ? text[..600] + "…" : text;
    }
}
