namespace uAgent.Agent;

// "/diagnose" outside the Windows installer: runs the same layered connectivity checks from any shell.
internal static class DiagnoseCommand
{
    public static async Task<int> RunAsync(CommandLine options)
    {
        var state = AgentStateStore.Load(AgentPaths.StatePath);
        var embedded = EmbeddedConfig.ReadFromCurrentExecutable();
        var managerUrl = First(options.ManagerUrl, state.ManagerUrl, embedded?.ManagerUrl);
        var caPem = options.CaCertificateFile is { Length: > 0 } file ? await File.ReadAllTextAsync(file) : First(state.CaCertificate, embedded?.CaCertificate);
        var trust = new TrustMaterial(First(options.CertificatePin, state.CertificatePin, embedded?.CertificatePin), First(state.SpkiPin, embedded?.SpkiPin), caPem);

        Console.WriteLine($"uAgent {AgentRuntime.Version} diagnose: {managerUrl} (trust: {trust.Describe()})");
        var report = await ConnectivityDiagnostics.RunAsync(managerUrl, trust, CancellationToken.None);
        foreach (var step in report.Steps)
        {
            Console.WriteLine($"  [{(step.Ok ? "OK" : "FAILED")}] {step.Name}: {step.Detail}");
        }

        Console.WriteLine(report.Ok ? "Result: reachable." : $"Result: blocked at {report.FirstFailure!.Name}.");
        return report.Ok ? 0 : 2;
    }

    private static string First(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value))?.Trim() ?? string.Empty;
}
