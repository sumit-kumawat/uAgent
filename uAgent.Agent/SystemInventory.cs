using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.ServiceProcess;
using System.Text;
using Microsoft.Win32;
using uAgent.Shared;

namespace uAgent.Agent;

// Read-only inventory of the host: resource usage, processes, services, installed applications and folder listings.
// Collection never changes the system. Folder listings return metadata only and are limited to configured roots.
[SupportedOSPlatform("windows")]
internal sealed class SystemInventory
{
    private const int MaxDirectoryEntries = 2000;
    private const uint ProcessQueryLimitedInformation = 0x1000;

    private readonly object _gate = new();
    private Dictionary<int, (TimeSpan Cpu, long Ticks)> _processSamples = new();
    private long _processSampleTicks;
    private (ulong Idle, ulong Kernel, ulong User)? _cpuSample;
    private double _lastCpuPercent;
    private (string? Manufacturer, string? Model)? _hardware;

    public SystemMetrics Metrics(MachineDetails machine)
    {
        var processes = Process.GetProcesses();
        int threads = 0, handles = 0;
        foreach (var process in processes)
        {
            try
            {
                threads += process.Threads.Count;
                handles += process.HandleCount;
            }
            catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or NotSupportedException)
            {
                // The process exited or is protected; it is still counted below.
            }
            finally
            {
                process.Dispose();
            }
        }

        var memory = MemoryStatus();
        var hardware = _hardware ??= ReadHardware();
        return new SystemMetrics(
            Math.Round(CpuPercent(), 1),
            (long)memory.ullTotalPhys,
            (long)memory.ullAvailPhys,
            processes.Length,
            threads,
            handles,
            machine.Uptime,
            Disks(),
            DateTime.UtcNow,
            Environment.ProcessorCount,
            RuntimeInformation.OSArchitecture.ToString(),
            machine.OsVersion,
            hardware.Manufacturer,
            hardware.Model);
    }

    // CPU is measured between two samples. The first call samples twice, 400 ms apart, so it is accurate immediately.
    public IReadOnlyList<ProcessInfo> Processes()
    {
        lock (_gate)
        {
            if (_processSampleTicks == 0 || Stopwatch.GetElapsedTime(_processSampleTicks) > TimeSpan.FromSeconds(30))
            {
                Sample(out _);
                Thread.Sleep(400);
            }

            var previous = _processSamples;
            var previousTicks = _processSampleTicks;
            var current = Sample(out var snapshot);
            var elapsed = Stopwatch.GetElapsedTime(previousTicks, _processSampleTicks).TotalMilliseconds;
            var cores = Math.Max(1, Environment.ProcessorCount);

            var list = new List<ProcessInfo>(snapshot.Count);
            foreach (var item in snapshot)
            {
                double cpu = 0;
                if (elapsed > 0 && previous.TryGetValue(item.Pid, out var before) && current.TryGetValue(item.Pid, out var now))
                {
                    cpu = Math.Clamp((now.Cpu - before.Cpu).TotalMilliseconds / (elapsed * cores) * 100, 0, 100);
                }

                list.Add(item with { CpuPercent = Math.Round(cpu, 1) });
            }

            return list;
        }
    }

    public static IReadOnlyList<ServiceInfo> Services()
    {
        var services = ServiceController.GetServices();
        var list = new List<ServiceInfo>(services.Length);
        foreach (var service in services)
        {
            using (service)
            {
                try
                {
                    list.Add(new ServiceInfo(
                        service.ServiceName,
                        service.DisplayName,
                        service.Status.ToString(),
                        service.StartType.ToString(),
                        service.ServiceType.ToString(),
                        service.CanStop));
                }
                catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
                {
                    list.Add(new ServiceInfo(service.ServiceName, service.ServiceName, "Unknown", "Unknown", "Unknown", false));
                }
            }
        }

        return list.OrderBy(s => s.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static IReadOnlyList<ApplicationInfo> Applications()
    {
        const string uninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        var apps = new Dictionary<string, ApplicationInfo>(StringComparer.OrdinalIgnoreCase);

        void ReadKey(RegistryKey? root, string scope)
        {
            if (root is null)
            {
                return;
            }

            foreach (var name in root.GetSubKeyNames())
            {
                try
                {
                    using var key = root.OpenSubKey(name);
                    if (key is null || key.GetValue("DisplayName") is not string displayName || string.IsNullOrWhiteSpace(displayName))
                    {
                        continue;
                    }

                    if (key.GetValue("SystemComponent") is int system && system == 1 || key.GetValue("ParentKeyName") is not null)
                    {
                        continue; // Windows components and updates are not separately installed applications.
                    }

                    var version = key.GetValue("DisplayVersion") as string;
                    var size = key.GetValue("EstimatedSize") is int kb && kb > 0 ? (long)kb * 1024 : (long?)null;
                    var info = new ApplicationInfo(
                        displayName.Trim(),
                        version?.Trim(),
                        (key.GetValue("Publisher") as string)?.Trim(),
                        FormatInstallDate(key.GetValue("InstallDate") as string),
                        size,
                        scope,
                        (key.GetValue("InstallLocation") as string)?.Trim());
                    apps.TryAdd($"{info.Name}|{info.Version}", info);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
                {
                    // Unreadable entry; skip it.
                }
            }
        }

        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var key = hive.OpenSubKey(uninstallPath);
            ReadKey(key, view == RegistryView.Registry64 ? "Machine (64-bit)" : "Machine (32-bit)");
        }

        using (var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64))
        {
            foreach (var sid in users.GetSubKeyNames().Where(s => s.StartsWith("S-1-5-21-", StringComparison.Ordinal) && !s.EndsWith("_Classes", StringComparison.Ordinal)))
            {
                using var key = users.OpenSubKey($@"{sid}\{uninstallPath}");
                ReadKey(key, "User");
            }
        }

        return apps.Values.OrderBy(a => a.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static DirectoryListing ListDirectory(string? requested, IReadOnlyList<string> configuredRoots)
    {
        var roots = AllowedRoots(configuredRoots);
        if (string.IsNullOrWhiteSpace(requested))
        {
            var entries = roots.Select(root => new FileEntry(root, true, null, null, "Root")).ToList();
            return new DirectoryListing(string.Empty, null, entries, false, roots);
        }

        string path;
        try
        {
            path = WithSeparator(Path.GetFullPath(requested.Trim()));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new InvalidOperationException($"'{requested}' is not a valid path.");
        }

        if (!roots.Any(root => path.StartsWith(root, StringComparison.OrdinalIgnoreCase)))
        {
            throw new UnauthorizedAccessException($"'{path}' is outside the folders this agent allows to be listed.");
        }

        if (path.StartsWith(WithSeparator(AgentPaths.DataDirectory), StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException("The agent's own credential folder cannot be listed.");
        }

        var directory = new DirectoryInfo(path);
        if (!directory.Exists)
        {
            throw new DirectoryNotFoundException($"'{path}' does not exist.");
        }

        var options = new EnumerationOptions { IgnoreInaccessible = true, RecurseSubdirectories = false, AttributesToSkip = 0 };
        var list = new List<FileEntry>();
        var truncated = false;
        foreach (var info in directory.EnumerateFileSystemInfos("*", options))
        {
            if (list.Count >= MaxDirectoryEntries)
            {
                truncated = true;
                break;
            }

            var isDirectory = info.Attributes.HasFlag(FileAttributes.Directory);
            list.Add(new FileEntry(
                info.Name,
                isDirectory,
                isDirectory ? null : SafeLength(info as FileInfo),
                info.LastWriteTimeUtc,
                info.Attributes.ToString()));
        }

        var ordered = list.OrderByDescending(e => e.IsDirectory).ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase).ToList();
        var parent = directory.Parent is { } p && roots.Any(root => WithSeparator(p.FullName).StartsWith(root, StringComparison.OrdinalIgnoreCase))
            ? WithSeparator(p.FullName)
            : string.Empty;
        return new DirectoryListing(path, parent, ordered, truncated, roots);
    }

    private static List<string> AllowedRoots(IReadOnlyList<string> configured)
    {
        var roots = configured
            .Where(r => !string.IsNullOrWhiteSpace(r))
            .Select(r => WithSeparator(Path.GetFullPath(r.Trim())))
            .ToList();
        if (roots.Count == 0)
        {
            roots = DriveInfo.GetDrives()
                .Where(d => d.DriveType == DriveType.Fixed && d.IsReady)
                .Select(d => WithSeparator(d.RootDirectory.FullName))
                .ToList();
        }

        return roots.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static string WithSeparator(string path) =>
        path.EndsWith(Path.DirectorySeparatorChar) ? path : path + Path.DirectorySeparatorChar;

    private static long? SafeLength(FileInfo? file)
    {
        try
        {
            return file?.Length;
        }
        catch (IOException)
        {
            return null;
        }
    }

    private static string? FormatInstallDate(string? raw) =>
        raw is { Length: 8 } && raw.All(char.IsAsciiDigit) ? $"{raw[..4]}-{raw[4..6]}-{raw[6..]}" : raw;

    private Dictionary<int, (TimeSpan Cpu, long Ticks)> Sample(out List<ProcessInfo> snapshot)
    {
        var samples = new Dictionary<int, (TimeSpan, long)>();
        snapshot = [];
        var now = Stopwatch.GetTimestamp();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    var pid = process.Id;
                    TimeSpan cpu = TimeSpan.Zero;
                    DateTime? started = null;
                    try
                    {
                        cpu = process.TotalProcessorTime;
                        started = process.StartTime.ToUniversalTime();
                    }
                    catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or NotSupportedException)
                    {
                        // Protected process: CPU and start time are not readable, the rest still is.
                    }

                    samples[pid] = (cpu, now);
                    snapshot.Add(new ProcessInfo(
                        pid,
                        pid == 0 ? "System Idle Process" : process.ProcessName,
                        0,
                        process.WorkingSet64,
                        process.PrivateMemorySize64,
                        SafeCount(() => process.Threads.Count),
                        SafeCount(() => process.HandleCount),
                        SafeCount(() => process.SessionId),
                        started,
                        ImagePath(pid)));
                }
                catch (InvalidOperationException)
                {
                    // Exited during the scan.
                }
            }
        }

        _processSamples = samples;
        _processSampleTicks = now;
        return samples;
    }

    private static int SafeCount(Func<int> read)
    {
        try
        {
            return read();
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or NotSupportedException)
        {
            return 0;
        }
    }

    private static string? ImagePath(int pid)
    {
        if (pid <= 4)
        {
            return null;
        }

        var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var buffer = new StringBuilder(1024);
            var size = buffer.Capacity;
            return QueryFullProcessImageName(handle, 0, buffer, ref size) ? buffer.ToString(0, size) : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private double CpuPercent()
    {
        lock (_gate)
        {
            if (_cpuSample is null)
            {
                _cpuSample = ReadSystemTimes();
                Thread.Sleep(250);
            }

            var before = _cpuSample.Value;
            var now = ReadSystemTimes();
            _cpuSample = now;
            var idle = now.Idle - before.Idle;
            var total = (now.Kernel - before.Kernel) + (now.User - before.User); // kernel time includes idle
            if (total == 0)
            {
                return _lastCpuPercent;
            }

            _lastCpuPercent = Math.Clamp((1.0 - (double)idle / total) * 100, 0, 100);
            return _lastCpuPercent;
        }
    }

    private static (ulong Idle, ulong Kernel, ulong User) ReadSystemTimes()
    {
        if (!GetSystemTimes(out var idle, out var kernel, out var user))
        {
            return (0, 0, 0);
        }

        return (idle, kernel, user);
    }

    private static MEMORYSTATUSEX MemoryStatus()
    {
        var status = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
        return GlobalMemoryStatusEx(ref status) ? status : default;
    }

    private static List<DiskUsage> Disks()
    {
        var disks = new List<DiskUsage>();
        foreach (var drive in DriveInfo.GetDrives())
        {
            try
            {
                if (drive.DriveType == DriveType.Fixed && drive.IsReady)
                {
                    disks.Add(new DiskUsage(drive.Name, drive.VolumeLabel, drive.DriveFormat, drive.TotalSize, drive.AvailableFreeSpace));
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Drive became unavailable.
            }
        }

        return disks;
    }

    private static (string? Manufacturer, string? Model) ReadHardware()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
            return ((key?.GetValue("SystemManufacturer") as string)?.Trim(), (key?.GetValue("SystemProductName") as string)?.Trim());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return (null, null);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX buffer);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSystemTimes(out ulong idleTime, out ulong kernelTime, out ulong userTime);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "QueryFullProcessImageNameW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder name, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
