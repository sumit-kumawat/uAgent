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

    // SYSTEM: full control. Administrators: full control. Interactive, service and authenticated users:
    // query status only, so they cannot stop, reconfigure or delete the service.
    private const string ServiceSddl =
        "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWLOCRRC;;;AU)" +
        "S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)";

    private const string SystemSid = "*S-1-5-18";
    private const string AdministratorsSid = "*S-1-5-32-544";
    private const string UsersSid = "*S-1-5-32-545";

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
                AgentVerb.Install or AgentVerb.Upgrade => installer.Install(),
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
        Banner(_options.Verb == AgentVerb.Upgrade ? "Upgrade" : "Install");

        var embedded = EmbeddedConfig.ReadFromCurrentExecutable();
        var existing = AgentStateStore.Load(AgentPaths.StatePath);
        var installedVersion = InstalledVersion();
        var managerUrl = First(_options.ManagerUrl, embedded?.ManagerUrl, existing.ManagerUrl, new DashboardOptions().BaseUrl);
        var pin = First(_options.CertificatePin, embedded?.CertificatePin, existing.CertificatePin);
        var enrollmentKey = First(_options.EnrollmentKey, embedded?.EnrollmentKey);

        Info("Manager", managerUrl);
        Info("Version", installedVersion is null ? $"{AgentRuntime.Version} (new installation)" : $"{installedVersion} → {AgentRuntime.Version}");
        Info("Registration", existing.IsEnrolled
            ? $"keeping agent {existing.DisplayId}"
            : enrollmentKey.Length > 0 || existing.ProtectedEnrollmentKey.Length > 0 ? "automatic after install" : "NO ENROLLMENT KEY");
        Line(string.Empty);

        if (!Uri.TryCreate(managerUrl, UriKind.Absolute, out var managerUri) || managerUri.Scheme is not ("https" or "http"))
        {
            Fail($"The manager URL '{managerUrl}' is not a valid http(s) URL. Pass /manager=https://uagent.helixops.ai.");
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
        var probe = Probe(managerUrl, pin);
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
        var managerChanged = existing.ManagerUrl.Length > 0 &&
                             !string.Equals(existing.ManagerUrl.TrimEnd('/'), managerUrl.TrimEnd('/'), StringComparison.OrdinalIgnoreCase);
        new AgentStateStore(AgentPaths.StatePath).Update(state =>
        {
            state.ManagerUrl = managerUrl;
            state.CertificatePin = pin;
            if (enrollmentKey.Length > 0)
            {
                state.ProtectedEnrollmentKey = SecretProtector.Protect(enrollmentKey);
            }

            if (managerChanged)
            {
                state.AgentId = string.Empty;
                state.ProtectedApiKey = string.Empty;
                state.DisplayId = string.Empty;
                state.Status = string.Empty;
            }
        });
        TryDelete(AgentPaths.StatusPath);
        Ok();

        Step("Registering the Windows service");
        RegisterService();
        Ok();

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
            var reEnroll = _options.ReEnroll ||
                           (_options.ManagerUrl is not null && !string.Equals(state.ManagerUrl.TrimEnd('/'), _options.ManagerUrl.TrimEnd('/'), StringComparison.OrdinalIgnoreCase));
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
                    WarnResult("Not connected yet.");
                }

                Warn($"The agent is installed and running but cannot reach the manager yet: {status.LastError}");
                Line("  It keeps retrying automatically and appears in the dashboard as soon as the manager is reachable.");
                Line("  Check DNS/firewall access to the manager, then run 'uAgent.exe /status'.");
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

    private static string? Probe(string managerUrl, string pin)
    {
        try
        {
            using var handler = CertificateTrust.CreateHandler(() => pin);
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
            using var handler = CertificateTrust.CreateHandler(() => state.CertificatePin);
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

        Exec("sc.exe", "description", AgentPaths.ServiceName, "Reports this computer to the uAgent manager and runs authorised remote actions.");
        // Restart after 5 s, 10 s, then every 30 s; the failure counter resets after a day without failures.
        Require(Exec("sc.exe", "failure", AgentPaths.ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/10000/restart/30000"), "configure service recovery");
        Require(Exec("sc.exe", "failureflag", AgentPaths.ServiceName, "1"), "enable recovery on non-crash failures");
        Require(Exec("sc.exe", "sdset", AgentPaths.ServiceName, ServiceSddl), "restrict service permissions to administrators");
    }

    private static void RegisterUninstallEntry()
    {
        using var key = Registry.LocalMachine.CreateSubKey(UninstallKey, writable: true);
        var exe = AgentPaths.InstalledExecutable;
        key.SetValue("DisplayName", "uAgent Endpoint Agent");
        key.SetValue("DisplayVersion", AgentRuntime.Version);
        key.SetValue("Publisher", "HelixOps");
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
        var grants = new List<string> { path, "/inheritance:r", "/grant:r", $"{SystemSid}:(OI)(CI)F", "/grant:r", $"{AdministratorsSid}:(OI)(CI)F" };
        if (allowUsersRead)
        {
            grants.AddRange(["/grant:r", $"{UsersSid}:(OI)(CI)RX"]);
        }

        grants.AddRange(["/T", "/C", "/Q"]);
        Require(Exec("icacls.exe", grants.ToArray()), $"secure {path}");
        Exec("icacls.exe", path, "/setowner", AdministratorsSid, "/T", "/C", "/Q");
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
        Line("  " + new string('─', 56), ConsoleColor.DarkGray);
    }

    private void Info(string label, string value) => Line($"  {label,-14} {value}");

    private void Step(string text)
    {
        Console.Write($"  • {text} ");
        _log?.Write($"{DateTime.Now:HH:mm:ss} {text} ");
    }

    private void Ok() => Result("OK", ConsoleColor.Green);

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
