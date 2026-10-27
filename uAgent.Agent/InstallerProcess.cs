using System.ComponentModel;
using System.Diagnostics;
using System.Text;

namespace uAgent.Agent;

internal sealed record InstallerRun(int? ExitCode, bool TimedOut, string Output);

// Runs an installer (or scanner) without a window, enforces a deadline by killing the whole process tree, and keeps
// only the last few kilobytes of output.
internal static class InstallerProcess
{
    public const int TailLength = 8192;
    private static readonly TimeSpan DrainTimeout = TimeSpan.FromSeconds(5);

    // A cancelled token (service stopping) stops the wait but leaves the installer running to completion.
    public static async Task<InstallerRun> RunAsync(ProcessStartInfo start, TimeSpan timeout, CancellationToken token)
    {
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        using var process = Process.Start(start) ?? throw new InvalidOperationException($"{Path.GetFileName(start.FileName)} could not be started.");

        var stdout = new OutputTail();
        var stderr = new OutputTail();
        var pumps = start.RedirectStandardOutput && start.RedirectStandardError
            ? Task.WhenAll(PumpAsync(process.StandardOutput, stdout), PumpAsync(process.StandardError, stderr))
            : Task.CompletedTask;

        using var deadline = new CancellationTokenSource(timeout);
        using var wait = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
        try
        {
            await process.WaitForExitAsync(wait.Token);
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested && !token.IsCancellationRequested)
        {
            KillTree(process);
            await DrainAsync(pumps);
            return new InstallerRun(null, true, Combine(stdout.Text, stderr.Text));
        }

        await DrainAsync(pumps);
        return new InstallerRun(process.ExitCode, false, Combine(stdout.Text, stderr.Text));
    }

    // Reads the end of a log, detecting UTF-16 (msiexec's usual encoding) or UTF-8 from the BOM or the byte pattern.
    public static string ReadLogTail(string path, int maxBytes = TailLength)
    {
        if (!File.Exists(path))
        {
            return string.Empty;
        }

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var head = new byte[4];
        var headLength = stream.Read(head, 0, head.Length);
        var (encoding, preamble) = headLength switch
        {
            >= 2 when head[0] == 0xFF && head[1] == 0xFE => ((Encoding)Encoding.Unicode, 2),
            >= 2 when head[0] == 0xFE && head[1] == 0xFF => (Encoding.BigEndianUnicode, 2),
            >= 3 when head[0] == 0xEF && head[1] == 0xBB && head[2] == 0xBF => (Encoding.UTF8, 3),
            >= 2 when head[0] != 0 && head[1] == 0 => (Encoding.Unicode, 0),
            _ => (Encoding.UTF8, 0)
        };

        var start = Math.Max(preamble, stream.Length - maxBytes);
        if (encoding is UnicodeEncoding && (start - preamble) % 2 != 0)
        {
            start++;
        }

        stream.Position = start;
        var buffer = new byte[stream.Length - start];
        stream.ReadExactly(buffer);
        var text = encoding.GetString(buffer);
        if (start > preamble)
        {
            var newline = text.IndexOf('\n');
            text = newline >= 0 ? text[(newline + 1)..] : text;
        }

        return text.Trim('\0', '\r', '\n', ' ');
    }

    public static string DescribeWindowsError(int code)
    {
        var message = new Win32Exception(code).Message.Trim();
        return message.StartsWith("Unknown error", StringComparison.OrdinalIgnoreCase) ? string.Empty : message;
    }

    private static void KillTree(Process process)
    {
        try
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit(10_000);
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or NotSupportedException)
        {
            // Already exited, or a child could not be terminated; the timeout is reported either way.
        }
    }

    private static async Task PumpAsync(StreamReader reader, OutputTail tail)
    {
        var buffer = new char[4096];
        try
        {
            int read;
            while ((read = await reader.ReadAsync(buffer)) > 0)
            {
                tail.Append(buffer.AsSpan(0, read));
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException)
        {
            // The pipe closed; keep what was captured.
        }
    }

    // A child process that inherited the output pipe can keep it open long after the installer exits.
    private static Task DrainAsync(Task pumps) => Task.WhenAny(pumps, Task.Delay(DrainTimeout));

    private static string Combine(string stdout, string stderr)
    {
        stdout = stdout.Trim();
        stderr = stderr.Trim();
        var combined = (stdout.Length > 0, stderr.Length > 0) switch
        {
            (true, true) => $"Standard output:{Environment.NewLine}{stdout}{Environment.NewLine}{Environment.NewLine}Standard error:{Environment.NewLine}{stderr}",
            (true, false) => stdout,
            (false, true) => $"Standard error:{Environment.NewLine}{stderr}",
            _ => string.Empty
        };
        return combined.Length <= TailLength ? combined : combined[^TailLength..];
    }

    private sealed class OutputTail
    {
        private readonly StringBuilder _builder = new();
        private readonly object _gate = new();

        public string Text
        {
            get
            {
                lock (_gate)
                {
                    return _builder.ToString();
                }
            }
        }

        public void Append(ReadOnlySpan<char> chunk)
        {
            lock (_gate)
            {
                _builder.Append(chunk);
                if (_builder.Length > TailLength * 2)
                {
                    _builder.Remove(0, _builder.Length - TailLength);
                }
            }
        }
    }
}
