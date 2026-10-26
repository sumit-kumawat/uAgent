using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Win32;

namespace uAgent.Agent;

// One-click installer and maintenance commands. The same uAgent.exe is the installer and the service.
[SupportedOSPlatform("windows")]
internal sealed class AgentInstaller
{
    private const string UninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\uAgent";

    private readonly CommandLine _options;
    private readonly StreamWriter? _log;

    private AgentInstaller(CommandLine options, string logPath)
    {
        _options = options;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(logPath)!);
            _log = new StreamWriter(logPath, append: true) { AutoFlush = true };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _log = null;
        }
    }

    public static int Run(CommandLine options)
    {
        if (options.Verb == AgentVerb.Help)
        {
            Console.WriteLine(CommandLine.Usage);
            return 0;
        }

        if (!IsAdministrator())
        {
            return Elevate(options);
        }

        var logPath = options.Verb == AgentVerb.Uninstall
            ? Path.Combine(Path.GetTempPath(), $"uAgent-uninstall-{DateTime.Now:yyyyMMdd-HHmmss}.log")
            : Path.Combine(AgentPaths.LogDirectory, $"install-{DateTime.Now:yyyyMMdd}.log");
        var installer = new AgentInstaller(options, logPath);
        try
        {
            var code = options.Verb switch
            {
                AgentVerb.Install or AgentVerb.Upgrade or AgentVerb.Repair => installer.Install(),
                AgentVerb.Diagnose => installer.Diagnose(),
                AgentVerb.Uninstall => installer.Uninstall(),
                AgentVerb.Status => installer.Status(),
                AgentVerb.Configure => installer.Configure(),
                _ => 0
            };
            installer.Line(string.Empty);
            installer.Line($"Log: {logPath}", ConsoleColor.DarkGray);
            return code;
        }
        catch (Exception ex)
        {
            installer.Fail($"Unexpected error: {ex.Message}");
            installer._log?.WriteLine(ex.ToString());
            return 1;
        }
        finally
        {
            installer.Pause();
            installer._log?.Dispose();
        }
    }

    private int Install()
    {
        Banner(_options.Verb switch { AgentVerb.Upgrade => "Upgrade", AgentVerb.Repair => "Repair", _ => "Install" });

        var embedded = EmbeddedConfig.ReadFromCurrentExecutable();
        var existing = AgentStateStore.Load(AgentPaths.StatePath);
        var installedVersion = InstalledVersion();
        var managerUrl = First(_options.ManagerUrl, embedded?.ManagerUrl, existing.ManagerUrl, new DashboardOptions().BaseUrl);
        var trust = new TrustMaterial(
            First(_options.CertificatePin, embedded?.CertificatePin, existing.CertificatePin),
            First(embedded?.SpkiPin, existing.SpkiPin),
            First(embedded?.CaCertificate, existing.CaCertificate));
        var enrollmentKey = First(_options.EnrollmentKey, embedded?.EnrollmentKey);

        Info("Manager", managerUrl);
        Info("TLS trust", trust.Describe());
        Info("Version", installedVersion is null ? $"{AgentRuntime.Version} (new installation)" : $"{installedVersion} → {AgentRuntime.Version}");
        Info("Registration", existing.IsEnrolled
            ? $"keeping agent {existing.DisplayId}"
            : enrollmentKey.Length > 0 || existing.ProtectedEnrollmentKey.Length > 0 ? "automatic after install" : "NO ENROLLMENT KEY");
        Line(string.Empty);

        if (!Uri.TryCreate(managerUrl, UriKind.Absolute, out var managerUri) || managerUri.Scheme is not ("https" or "http"))
        {
            Fail($"The manager URL '{managerUrl}' is not a valid http(s) URL. Pass /manager=https://uagent.example.com.");
            return 1;
        }

        if (managerUri.Scheme == "http")
        {
            Warn("The manager URL uses plain HTTP; agent credentials will travel unencrypted. Use HTTPS in production.");
        }

        if (!existing.IsEnrolled && enrollmentKey.Length == 0 && existing.ProtectedEnrollmentKey.Length == 0)
        {
            Fail("This installer has no enrollment key. Download the installer from the portal's Download page, or pass /enrollkey=KEY.");
            return 1;
        }

        Step("Checking the connection to the manager");
        var probe = Probe(managerUrl, trust);
        if (probe is null)
        {
            Ok();
        }
        else
        {
            WarnResult(probe + " Installation continues; the service retries automatically.");
        }

        if (ServiceExists())
        {
            Step("Stopping the running agent service");
            StopService();
            Ok();
        }

        Step("Creating folders and securing permissions");
        Directory.CreateDirectory(AgentPaths.InstallDirectory);
        Directory.CreateDirectory(AgentPaths.DataDirectory);
        Directory.CreateDirectory(AgentPaths.LogDirectory);
        SecureDirectory(AgentPaths.InstallDirectory, allowUsersRead: true);
        SecureDirectory(AgentPaths.DataDirectory, allowUsersRead: false);
        Ok();

        Step("Installing program files");
        CopySelf();
        Ok();

        Step("Saving the manager connection");
        new AgentStateStore(AgentPaths.StatePath).Update(state =>
        {
            // The registration is kept when the address changes (IP to DNS name, renamed host). If the address
            // belongs to a different manager, it answers unknown_agent and the service registers again.
            state.ManagerUrl = managerUrl;
            state.CertificatePin = trust.CertificatePin;
            state.SpkiPin = trust.SpkiPin;
            state.CaCertificate = trust.CaCertificatePem;
            state.InstalledSha256 = ServiceHardening.Sha256(AgentPaths.InstalledExecutable);
            if (enrollmentKey.Length > 0)
            {
                state.ProtectedEnrollmentKey = SecretProtector.Protect(enrollmentKey);
            }
        });
        TryDelete(AgentPaths.StatusPath);
        Ok();

        Step("Registering the Windows service");
        RegisterService();
        Ok();

        Step("Checking Windows Firewall");
        var firewall = WindowsFirewall.Ensure(managerUri);
        if (firewall.Ok)
        {
            OkResult(firewall.Action);
            Detail(firewall.Detail);
        }
        else
        {
            WarnResult(firewall.Detail + " Installation continues.");
        }

        Step("Adding uAgent to Installed apps");
        RegisterUninstallEntry();
        Ok();

        Step("Starting the service");
        using (var controller = new ServiceController(AgentPaths.ServiceName))
        {
            controller.Start();
            controller.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
        }

        Ok();

        Step("Waiting for the agent to register with the manager");
        var status = WaitForConnection(TimeSpan.FromSeconds(_options.Verb == AgentVerb.Upgrade ? 30 : 90));
        Line(string.Empty);
        return Summarize(status, finalStep: true);
    }

    private int Uninstall()
    {
        Banner("Uninstall");
        if (!_options.Quiet)
        {
            Console.Write("  This stops the agent and removes it from this computer. Continue? [y/N] ");
            var answer = Console.ReadLine();
            if (!string.Equals(answer?.Trim(), "y", StringComparison.OrdinalIgnoreCase))
            {
                Line("  Uninstall cancelled.");
                return 2;
            }
        }

        var state = AgentStateStore.Load(AgentPaths.StatePath);
        if (state.IsEnrolled)
        {
            Step($"Notifying the manager that agent {state.DisplayId} is being removed");
            var error = Deregister(state);
            if (error is null)
            {
                Ok();
            }
            else
            {
                WarnResult(error);
            }
        }

        if (ServiceExists())
        {
            Step("Stopping the service");
            StopService();
            Ok();

            Step("Removing the service");
            var (code, output) = Exec("sc.exe", "delete", AgentPaths.ServiceName);
            if (code != 0)
            {
                throw new InvalidOperationException($"sc delete failed ({code}): {output}");
            }

            Ok();
        }

        Step("Removing the uAgent firewall rule");
        var firewall = WindowsFirewall.Remove();
        if (firewall.Ok)
        {
            OkResult(firewall.Action);
        }
        else
        {
            WarnResult(firewall.Detail);
        }

        Step("Removing the Installed apps entry");
        Registry.LocalMachine.DeleteSubKeyTree(UninstallKey, throwOnMissingSubKey: false);
        Ok();

        Step("Removing program files");
        RemoveDirectory(AgentPaths.InstallDirectory);
        Ok();

        if (_options.KeepData)
        {
            Info("Data kept", AgentPaths.DataDirectory);
        }
        else
        {
            Step("Removing credentials, status and logs");
            RemoveDirectory(AgentPaths.DataDirectory);
            Ok();
        }

        Line(string.Empty);
        Line("  uAgent was removed from this computer.", ConsoleColor.Green);
        return 0;
    }

    private int Diagnose()
    {
        Banner("Diagnose");
        var state = AgentStateStore.Load(AgentPaths.StatePath);
        var embedded = EmbeddedConfig.ReadFromCurrentExecutable();
        var managerUrl = First(_options.ManagerUrl, state.ManagerUrl, embedded?.ManagerUrl);
        var trust = new TrustMaterial(
            First(_options.CertificatePin, state.CertificatePin, embedded?.CertificatePin),
            First(state.SpkiPin, embedded?.SpkiPin),
            First(state.CaCertificate, embedded?.CaCertificate));
        Info("Installation", ServiceExists() ? $"installed, service {ServiceState()}, runs as LocalSystem" : "not installed");
        Info("Registration", state.IsEnrolled ? $"agent {state.DisplayId} ({state.Status})" : "not registered");
        Info("Manager", managerUrl.Length > 0 ? managerUrl : "not configured");
        Info("TLS trust", trust.Describe());
        Info("Firewall", WindowsFirewall.Describe());
        Line(string.Empty);

        var report = ConnectivityDiagnostics.RunAsync(managerUrl, trust, CancellationToken.None).GetAwaiter().GetResult();
        foreach (var step in report.Steps)
        {
            Step(step.Name);
            if (step.Ok)
            {
                Ok();
                Detail(step.Detail);
            }
            else
            {
                FailResult();
                Line($"    {step.Detail}", ConsoleColor.Red);
            }
        }

        Line(string.Empty);
        if (report.Ok)
        {
            Line("  This computer can reach the manager.", ConsoleColor.Green);
            if (!state.IsEnrolled)
            {
                Line("  The service registers on its next attempt (within 5 minutes); no reinstall is needed.");
            }
        }
        else
        {
            Fail($"Blocked at {report.FirstFailure!.Name}. Fix it and the service connects on its own; no reinstall is needed.");
        }

        return report.Ok ? 0 : 2;
    }

    private int Status()
    {
        Banner("Status");
        var state = AgentStateStore.Load(AgentPaths.StatePath);
        Info("Service", ServiceExists() ? ServiceState() : "not installed");
        Info("Installed version", InstalledVersion() ?? "not installed");
        Info("Manager", state.ManagerUrl.Length > 0 ? state.ManagerUrl : "not configured");
        Info("Agent ID", state.IsEnrolled ? $"{state.DisplayId} ({state.Status})" : "not registered");
        Line(string.Empty);
        return Summarize(AgentStatusFile.Read(), finalStep: false);
    }

    private int Configure()
    {
        Banner("Configure");
        if (_options.ManagerUrl is null && _options.EnrollmentKey is null && _options.CertificatePin is null && !_options.ReEnroll)
        {
            Fail("Nothing to change. Use /manager=URL, /enrollkey=KEY, /pin=SHA256 or /reenroll.");
            return 1;
        }

        if (_options.ManagerUrl is not null && !Uri.TryCreate(_options.ManagerUrl, UriKind.Absolute, out _))
        {
            Fail($"'{_options.ManagerUrl}' is not a valid URL.");
            return 1;
        }

        Step("Saving the manager connection");
        new AgentStateStore(AgentPaths.StatePath).Update(state =>
        {
            var reEnroll = _options.ReEnroll;
            state.ManagerUrl = _options.ManagerUrl ?? state.ManagerUrl;
            state.CertificatePin = _options.CertificatePin ?? state.CertificatePin;
            if (_options.EnrollmentKey is not null)
            {
                state.ProtectedEnrollmentKey = SecretProtector.Protect(_options.EnrollmentKey);
            }

            if (reEnroll)
            {
                state.AgentId = string.Empty;
                state.ProtectedApiKey = string.Empty;
                state.DisplayId = string.Empty;
                state.Status = string.Empty;
            }
        });
        TryDelete(AgentPaths.StatusPath);
        Ok();

        if (!ServiceExists())
        {
            Warn("The service is not installed; the settings apply after installation.");
            return 0;
        }

        Step("Restarting the service");
        StopService();
        using (var controller = new ServiceController(AgentPaths.ServiceName))
        {
            controller.Start();
            controller.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
        }

        Ok();
        Step("Waiting for the agent to connect");
        var status = WaitForConnection(TimeSpan.FromSeconds(60));
        Line(string.Empty);
        return Summarize(status, finalStep: true);
    }

    private int Summarize(AgentStatusSnapshot? status, bool finalStep)
    {
        if (status is null)
        {
            if (finalStep)
            {
                WarnResult("The service has not reported yet.");
            }

            Warn("No status has been reported yet. Check again in a minute with 'uAgent.exe /status'.");
            return 2;
        }

        switch (status.State)
        {
            case ConnectionStates.Connected:
                if (finalStep)
                {
                    Ok();
                }

                Line($"  Agent {status.DisplayId} is connected to {status.ManagerUrl}.", ConsoleColor.Green);
                if (status.DashboardUrl.Length > 0)
                {
                    Line($"  View it in the dashboard: {status.DashboardUrl}");
                }

                Line("  The service starts automatically with Windows and restarts itself after failures.");
                return 0;
            case ConnectionStates.PendingApproval:
                if (finalStep)
                {
                    Ok();
                }

                Line($"  Agent {status.DisplayId} is registered and waiting for an administrator to approve it in the portal.", ConsoleColor.Yellow);
                if (status.DashboardUrl.Length > 0)
                {
                    Line($"  Approve it here: {status.DashboardUrl}");
                }

                return 0;
            case ConnectionStates.Starting:
            case ConnectionStates.Disconnected:
                if (finalStep)
                {
                    WarnResult("Not registered yet.");
                }

                Line("  Installation:  complete. The service is running and starts with Windows.", ConsoleColor.Green);
                Warn($"Registration:  pending. {(status.LastError.Length > 0 ? status.LastError : "The service has not reached the manager yet.")}");
                if (status.Diagnosis.Length > 0)
                {
                    Warn($"Diagnosis:     {status.Diagnosis}");
                }

                if (status.NextAttemptUtc is { } next)
                {
                    Line($"  Next attempt:  {next.ToLocalTime():HH:mm:ss}. Retries continue with backoff (up to 5 minutes apart).");
                }

                Line("  The agent registers by itself once the manager is reachable; you do not need to reinstall.");
                Line("  Run 'uAgent.exe /diagnose' for a step-by-step DNS, firewall and TLS check.");
                return 2;
            default:
                if (finalStep)
                {
                    FailResult();
                }

                Fail($"{status.State}: {status.LastError}");
                Line("  Fix the problem above, then run the installer again or 'uAgent.exe /configure'.");
                return 1;
        }
    }

    private static AgentStatusSnapshot? WaitForConnection(TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        AgentStatusSnapshot? last = null;
        while (DateTime.UtcNow < deadline)
        {
            last = AgentStatusFile.Read() ?? last;
            if (last is not null && last.State is not (ConnectionStates.Starting or ConnectionStates.Disconnected))
            {
                return last;
            }

            Console.Write(".");
            Thread.Sleep(2000);
        }

        return last;
    }

    private static string? Probe(string managerUrl, TrustMaterial trust)
    {
        try
        {
            using var handler = CertificateTrust.CreateHandler(() => trust);
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
            using var response = client.GetAsync(new Uri(new Uri(managerUrl.TrimEnd('/') + "/"), "healthz")).GetAwaiter().GetResult();
            return response.IsSuccessStatusCode ? null : $"The manager answered HTTP {(int)response.StatusCode}.";
        }
        catch (Exception ex)
        {
            return ManagerClient.Describe(ex);
        }
    }

    private static string? Deregister(AgentState state)
    {
        try
        {
            using var handler = CertificateTrust.CreateHandler(() => new TrustMaterial(state.CertificatePin, state.SpkiPin, state.CaCertificate));
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
            using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(new Uri(state.ManagerUrl.TrimEnd('/') + "/"), $"api/agents/{Uri.EscapeDataString(state.AgentId)}/deregister"));
            request.Headers.TryAddWithoutValidation(uAgent.Shared.ApiHeaders.ApiKey, SecretProtector.Unprotect(state.ProtectedApiKey));
            request.Content = new StringContent("{\"reason\":\"Uninstalled by an administrator\"}", System.Text.Encoding.UTF8, "application/json");
            using var response = client.Send(request);
            return response.IsSuccessStatusCode ? null : $"The manager answered HTTP {(int)response.StatusCode}; remove the agent in the portal if needed.";
        }
        catch (Exception ex)
        {
            return $"{ManagerClient.Describe(ex)} Remove the agent in the portal if needed.";
        }
    }

    private void RegisterService()
    {
        var binPath = $"\"{AgentPaths.InstalledExecutable}\"";
        var (code, output) = ServiceExists()
            ? Exec("sc.exe", "config", AgentPaths.ServiceName, "binPath=", binPath, "start=", "auto", "obj=", "LocalSystem", "DisplayName=", AgentPaths.ServiceDisplayName)
            : Exec("sc.exe", "create", AgentPaths.ServiceName, "binPath=", binPath, "start=", "auto", "obj=", "LocalSystem", "DisplayName=", AgentPaths.ServiceDisplayName);
        if (code != 0)
        {
            throw new InvalidOperationException($"The service could not be registered ({code}): {output}");
        }

        Exec("sc.exe", "description", AgentPaths.ServiceName, ServiceHardening.Description);
        Require(Exec("sc.exe", ServiceHardening.FailureArguments), "configure service recovery");
        Require(Exec("sc.exe", "failureflag", AgentPaths.ServiceName, "1"), "enable recovery on non-crash failures");
        Require(Exec("sc.exe", "sdset", AgentPaths.ServiceName, ServiceHardening.ServiceSddl), "restrict service permissions to administrators");
    }

    private static void RegisterUninstallEntry()
    {
        using var key = Registry.LocalMachine.CreateSubKey(UninstallKey, writable: true);
        var exe = AgentPaths.InstalledExecutable;
        key.SetValue("DisplayName", "uAgent Endpoint Agent");
        key.SetValue("DisplayVersion", AgentRuntime.Version);
        key.SetValue("Publisher", "Sumit Kumawat");
        key.SetValue("InstallLocation", AgentPaths.InstallDirectory);
        key.SetValue("DisplayIcon", exe);
        key.SetValue("UninstallString", $"\"{exe}\" /uninstall");
        key.SetValue("QuietUninstallString", $"\"{exe}\" /uninstall /quiet");
        key.SetValue("NoModify", 1, RegistryValueKind.DWord);
        key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
        key.SetValue("EstimatedSize", (int)(new FileInfo(exe).Length / 1024), RegistryValueKind.DWord);
        key.SetValue("InstallDate", DateTime.Now.ToString("yyyyMMdd"));
    }

    private void SecureDirectory(string path, bool allowUsersRead)
    {
        Require(Exec("icacls.exe", ServiceHardening.DirectoryAclArguments(path, allowUsersRead)), $"secure {path}");
        Exec("icacls.exe", path, "/setowner", ServiceHardening.AdministratorsSid, "/T", "/C", "/Q");
    }

    private static void CopySelf()
    {
        var source = Environment.ProcessPath ?? throw new InvalidOperationException("The installer path is unknown.");
        var target = AgentPaths.InstalledExecutable;
        if (string.Equals(Path.GetFullPath(source), Path.GetFullPath(target), StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        for (var attempt = 1; ; attempt++)
        {
            try
            {
                File.Copy(source, target, overwrite: true);
                return;
            }
            catch (IOException) when (attempt < 15)
            {
                Thread.Sleep(1000); // The previous service process may still be releasing the file.
            }
        }
    }

    private static void StopService()
    {
        using var controller = new ServiceController(AgentPaths.ServiceName);
        controller.Refresh();
        if (controller.Status is ServiceControllerStatus.Stopped)
        {
            return;
        }

        if (controller.Status is not ServiceControllerStatus.StopPending)
        {
            controller.Stop();
        }

        controller.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(60));
        Thread.Sleep(1000);
    }

    private static bool ServiceExists() =>
        ServiceController.GetServices().Any(service => string.Equals(service.ServiceName, AgentPaths.ServiceName, StringComparison.OrdinalIgnoreCase));

    private static string ServiceState()
    {
        using var controller = new ServiceController(AgentPaths.ServiceName);
        return $"{controller.Status} (start: {controller.StartType})";
    }

    private static string? InstalledVersion()
    {
        using var key = Registry.LocalMachine.OpenSubKey(UninstallKey);
        return key?.GetValue("DisplayVersion") as string;
    }

    private static void RemoveDirectory(string path)
    {
        if (!Directory.Exists(path))
        {
            return;
        }

        var self = Environment.ProcessPath ?? string.Empty;
        if (self.StartsWith(path, StringComparison.OrdinalIgnoreCase))
        {
            // The running uninstaller cannot delete itself; remove the folder right after this process exits.
            Process.Start(new ProcessStartInfo("cmd.exe", $"/c ping -n 4 127.0.0.1 >nul & rmdir /s /q \"{path}\"")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetTempPath()
            });
            return;
        }

        Directory.Delete(path, recursive: true);
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static int Elevate(CommandLine options)
    {
        try
        {
            var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas" };
            foreach (var arg in Environment.GetCommandLineArgs().Skip(1))
            {
                start.ArgumentList.Add(arg);
            }

            using var process = Process.Start(start);
            process?.WaitForExit();
            return process?.ExitCode ?? 1;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("uAgent must be run as an administrator. The elevation prompt was cancelled.");
            Console.ResetColor();
            if (!options.Quiet)
            {
                Console.WriteLine("Press Enter to close.");
                Console.ReadLine();
            }

            return 5;
        }
    }

    private (int Code, string Output) Exec(string file, params string[] args)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, file))
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var arg in args)
        {
            start.ArgumentList.Add(arg);
        }

        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();
        _log?.WriteLine($"> {file} {string.Join(' ', args)} => {process.ExitCode} {output.Trim()}");
        return (process.ExitCode, output.Trim());
    }

    private static void Require((int Code, string Output) result, string action)
    {
        if (result.Code != 0)
        {
            throw new InvalidOperationException($"Could not {action} ({result.Code}): {result.Output}");
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // A stale status file is overwritten by the service on its first cycle.
        }
    }

    private static string First(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value))?.Trim() ?? string.Empty;

    private void Banner(string action)
    {
        Line(string.Empty);
        Line($"  uAgent Endpoint Agent {AgentRuntime.Version} — {action}", ConsoleColor.Cyan);
        Line("  Developed by Sumit Kumawat · © 2026 Sumit Kumawat", ConsoleColor.DarkGray);
        Line("  " + new string('─', 56), ConsoleColor.DarkGray);
    }

    private void Info(string label, string value) => Line($"  {label,-14} {value}");

    private void Step(string text)
    {
        Console.Write($"  • {text} ");
        _log?.Write($"{DateTime.Now:HH:mm:ss} {text} ");
    }

    private void Ok() => Result("OK", ConsoleColor.Green);

    private void OkResult(string text) => Result(text.ToUpperInvariant() == "OK" ? "OK" : $"OK ({text})", ConsoleColor.Green);

    private void Detail(string text) => Line($"    {text}", ConsoleColor.DarkGray);

    private void WarnResult(string message)
    {
        Result("WARNING", ConsoleColor.Yellow);
        Line($"    {message}", ConsoleColor.Yellow);
    }

    private void FailResult() => Result("FAILED", ConsoleColor.Red);

    private void Result(string text, ConsoleColor color)
    {
        Console.ForegroundColor = color;
        Console.WriteLine(text);
        Console.ResetColor();
        _log?.WriteLine(text);
    }

    private void Warn(string message) => Line($"  ! {message}", ConsoleColor.Yellow);

    private void Fail(string message) => Line($"  ✖ {message}", ConsoleColor.Red);

    private void Line(string text, ConsoleColor? color = null)
    {
        if (color is { } c)
        {
            Console.ForegroundColor = c;
        }

        Console.WriteLine(text);
        Console.ResetColor();
        _log?.WriteLine(text);
    }

    private void Pause()
    {
        if (_options.Quiet || _options.Verb == AgentVerb.Upgrade || Console.IsInputRedirected)
        {
            return;
        }

        Console.WriteLine();
        Console.Write("  Press Enter to close.");
        Console.ReadLine();
    }
}
