using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace uAgent.Agent;

[SupportedOSPlatform("windows")]
internal static class LocalAccountHelper
{
    private const uint UF_PASSWD_CANT_CHANGE = 0x0040;
    private const uint UF_DONT_EXPIRE_PASSWD = 0x10000;
    private const int NERR_Success = 0;

    public static void SetPasswordNeverExpires(string userName, bool enabled) =>
        UpdateFlags(userName, UF_DONT_EXPIRE_PASSWD, enabled);

    public static void SetCannotChangePassword(string userName, bool enabled) =>
        UpdateFlags(userName, UF_PASSWD_CANT_CHANGE, enabled);

    public static TimeSpan? GetMaxPasswordAge()
    {
        var status = NetUserModalsGet(null, 0, out var buffer);
        if (status != NERR_Success || buffer == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var seconds = Marshal.PtrToStructure<USER_MODALS_INFO_0>(buffer).usrmod0_max_passwd_age;
            return seconds is 0 or uint.MaxValue ? null : TimeSpan.FromSeconds(seconds);
        }
        finally
        {
            NetApiBufferFree(buffer);
        }
    }

    private static void UpdateFlags(string userName, uint flag, bool enabled)
    {
        var current = ReadFlags(userName);
        var updated = enabled ? current | flag : current & ~flag;
        if (updated != current)
        {
            WriteFlags(userName, updated);
        }
    }

    private static uint ReadFlags(string userName)
    {
        var status = NetUserGetInfo(null, userName, 1, out var buffer);
        if (status != NERR_Success || buffer == IntPtr.Zero)
        {
            throw new Win32Exception(status, $"NetUserGetInfo failed for '{userName}' with status {status}.");
        }

        try
        {
            return Marshal.PtrToStructure<USER_INFO_1>(buffer).usri1_flags;
        }
        finally
        {
            NetApiBufferFree(buffer);
        }
    }

    private static void WriteFlags(string userName, uint flags)
    {
        var info = new USER_INFO_1008 { usri1008_flags = flags };
        var handle = GCHandle.Alloc(info, GCHandleType.Pinned);
        try
        {
            var status = NetUserSetInfo(null, userName, 1008, handle.AddrOfPinnedObject(), out var errorIndex);
            if (status != NERR_Success)
            {
                throw new Win32Exception(
                    status,
                    $"NetUserSetInfo failed for '{userName}' with status {status} (parameter index {errorIndex}).");
            }
        }
        finally
        {
            handle.Free();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct USER_INFO_1
    {
        public IntPtr usri1_name;
        public IntPtr usri1_password;
        public uint usri1_password_age;
        public uint usri1_priv;
        public IntPtr usri1_home_dir;
        public IntPtr usri1_comment;
        public uint usri1_flags;
        public IntPtr usri1_script_path;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct USER_INFO_1008
    {
        public uint usri1008_flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct USER_MODALS_INFO_0
    {
        public uint usrmod0_min_passwd_len;
        public uint usrmod0_max_passwd_age;
        public uint usrmod0_min_passwd_age;
        public uint usrmod0_force_logoff;
        public uint usrmod0_password_hist_len;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int NetUserGetInfo(string? serverName, string userName, int level, out IntPtr buffer);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int NetUserSetInfo(string? serverName, string userName, int level, IntPtr buffer, out uint parameterError);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int NetUserModalsGet(string? serverName, int level, out IntPtr buffer);

    [DllImport("netapi32.dll", ExactSpelling = true)]
    private static extern int NetApiBufferFree(IntPtr buffer);
}
