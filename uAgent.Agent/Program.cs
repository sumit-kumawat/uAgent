using Microsoft.Extensions.Hosting.WindowsServices;
using Polly;
using Serilog;
using uAgent.Agent;

// The same executable is the installer and the service:
//   - started by the Service Control Manager  -> runs the agent;
//   - double-clicked / run with switches      -> installer and maintenance commands (see CommandLine.Usage);
//   - "/run", or any non-Windows host         -> runs the agent in the console.
var isService = OperatingSystem.IsWindows() && WindowsServiceHelpers.IsWindowsService();
var commandLine = CommandLine.Parse(args, defaultToInstall: OperatingSystem.IsWindows() && !isService);

if (OperatingSystem.IsWindows() && !isService && commandLine.Verb != AgentVerb.Run)
{
    return AgentInstaller.Run(commandLine);
}

if (!OperatingSystem.IsWindows() && commandLine.Verb == AgentVerb.Help)
{
    Console.WriteLine(CommandLine.Usage);
    return 0;
}

if (!OperatingSystem.IsWindows() && commandLine.Verb == AgentVerb.Diagnose)
{
    return await DiagnoseCommand.RunAsync(commandLine);
}

var logConfiguration = new LoggerConfiguration();
AgentLogging.Configure(logConfiguration);
Log.Logger = logConfiguration.CreateBootstrapLogger();

try
{
    var host = Host.CreateDefaultBuilder(commandLine.HostArgs)
        .UseWindowsService(options => options.ServiceName = AgentPaths.ServiceName)
        .ConfigureAppConfiguration(configuration =>
            configuration.AddJsonFile(AgentPaths.SettingsPath, optional: true, reloadOnChange: true))
        .UseSerilog((_, _, configuration) => AgentLogging.Configure(configuration))
        .ConfigureServices((context, services) =>
        {
            services.Configure<AgentOptions>(context.Configuration.GetSection(AgentOptions.SectionName));
            services.Configure<DashboardOptions>(context.Configuration.GetSection(DashboardOptions.SectionName));
            services.AddSingleton<AgentStateStore>();
            services.AddSingleton<ConnectionSettings>();
            services.AddSingleton<ManagerClient>();
            services.AddSingleton<AgentUpdater>();
            services.AddSingleton<TamperGuard>();
            services.AddHostedService<AgentService>();
            services.AddHttpClient(ManagerClient.HttpClientName, client =>
                {
                    client.Timeout = TimeSpan.FromSeconds(100);
                    client.DefaultRequestHeaders.UserAgent.ParseAdd($"uAgent/{AgentRuntime.Version}");
                })
                .ConfigurePrimaryHttpMessageHandler(serviceProvider =>
                {
                    var connection = serviceProvider.GetRequiredService<ConnectionSettings>();
                    return CertificateTrust.CreateHandler(() => connection.Trust);
                })
                .AddTransientHttpErrorPolicy(policy =>
                    policy.WaitAndRetryAsync(
                        retryCount: 2,
                        sleepDurationProvider: attempt => TimeSpan.FromSeconds(attempt * 2),
                        onRetry: (outcome, delay, attempt, _) =>
                            Log.Warning(
                                "Manager request failed ({Reason}). Retry {Attempt} in {DelaySeconds}s.",
                                outcome.Exception?.Message ?? outcome.Result?.StatusCode.ToString() ?? "unknown",
                                attempt,
                                delay.TotalSeconds)));
        })
        .Build();

    await host.RunAsync();
    return 0;
}
catch (Exception ex)
{
    Log.Fatal(ex, "uAgent terminated unexpectedly");
    return 1;
}
finally
{
    await Log.CloseAndFlushAsync();
}
