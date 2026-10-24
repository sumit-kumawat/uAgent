using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace uAgent.Agent;

// P/Invoke wrappers around the Windows net management API (netapi32.dll) for local accounts.
// LocalSystem can change flags on local accounts. These calls do not apply to domain accounts;
// domain changes go through UserPrincipal or the directory entry security descriptor instead.
[SupportedOSPlatform("windows")]
internal static class LocalAccountHelper
{
    // USER_INFO_1008 account control flags (lmaccess.h).
    private const uint UF_SCRIPT = 0x0001;
    private const uint UF_ACCOUNTDISABLE = 0x0002;
    private const uint UF_LOCKOUT = 0x0010;
    private const uint UF_PASSWD_CANT_CHANGE = 0x0040;
    private const uint UF_DONT_EXPIRE_PASSWD = 0x10000;

    private const int NERR_Success = 0;

    public static void SetPasswordNeverExpires(string userName, bool enabled)
    {
        UpdateFlags(userName, UF_DONT_EXPIRE_PASSWD, enabled);
    }

    public static void SetCannotChangePassword(string userName, bool enabled)
    {
        UpdateFlags(userName, UF_PASSWD_CANT_CHANGE, enabled);
    }

    public static void SetAccountDisabled(string userName, bool disabled)
    {
        UpdateFlags(userName, UF_ACCOUNTDISABLE, disabled);
    }

    public static void Unlock(string userName)
    {
        // Clearing UF_LOCKOUT releases an account that the system locked after bad logons.
        UpdateFlags(userName, UF_LOCKOUT, false);
    }

    // Reads the account lockout threshold so callers can confirm policy before acting.
    public static uint GetLockoutThreshold()
    {
        var status = NetUserModalsGet(null, 3, out var buffer);
        if (status != NERR_Success || buffer == IntPtr.Zero)
        {
            throw new Win32Exception(status, $"NetUserModalsGet failed with status {status}.");
        }

        try
        {
            var modals = Marshal.PtrToStructure<USER_MODALS_INFO_3>(buffer);
            return modals.usrmod3_lockout_threshold;
        }
        finally
        {
            NetApiBufferFree(buffer);
        }
    }

    // Round-trips the force-logoff modal so the policy write path is exercised without changing values.
    public static void TouchForceLogoffPolicy()
    {
        var status = NetUserModalsGet(null, 0, out var buffer);
        if (status != NERR_Success || buffer == IntPtr.Zero)
        {
            throw new Win32Exception(status, $"NetUserModalsGet failed with status {status}.");
        }

        try
        {
            var modals = Marshal.PtrToStructure<USER_MODALS_INFO_0>(buffer);
            var handle = GCHandle.Alloc(modals, GCHandleType.Pinned);
            try
            {
                var setStatus = NetUserModalsSet(null, 0, handle.AddrOfPinnedObject(), out _);
                if (setStatus != NERR_Success)
                {
                    throw new Win32Exception(setStatus, $"NetUserModalsSet failed with status {setStatus}.");
                }
            }
            finally
            {
                handle.Free();
            }
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
        if (updated == current)
        {
            return;
        }

        WriteFlags(userName, updated);
    }

    private static uint ReadFlags(string userName)
    {
        var status = NetUserGetInfo(null, userName, 1008, out var buffer);
        if (status != NERR_Success || buffer == IntPtr.Zero)
        {
            throw new Win32Exception(status, $"NetUserGetInfo failed for '{userName}' with status {status}.");
        }

        try
        {
            var info = Marshal.PtrToStructure<USER_INFO_1008>(buffer);
            return info.usri1008_flags;
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

    [StructLayout(LayoutKind.Sequential)]
    private struct USER_MODALS_INFO_3
    {
        public uint usrmod3_lockout_duration;
        public uint usrmod3_lockout_observation_window;
        public uint usrmod3_lockout_threshold;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int NetUserGetInfo(
        string? serverName,
        string userName,
        int level,
        out IntPtr buffer);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int NetUserSetInfo(
        string? serverName,
        string userName,
        int level,
        IntPtr buffer,
        out uint parameterError);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int NetUserModalsGet(
        string? serverName,
        int level,
        out IntPtr buffer);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int NetUserModalsSet(
        string? serverName,
        int level,
        IntPtr buffer,
        out uint parameterError);

    [DllImport("netapi32.dll", ExactSpelling = true)]
    private static extern int NetApiBufferFree(IntPtr buffer);
}
