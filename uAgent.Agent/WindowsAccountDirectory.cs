using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using uAgent.Shared;

namespace uAgent.Agent;

// Domain operations use the process identity. LocalSystem can manage local accounts.
// Domain changes succeed only when that identity has rights to the account.
[SupportedOSPlatform("windows")]
internal static class WindowsAccountDirectory
{
    public static IReadOnlyList<AccountStatus> Collect(
        IReadOnlyList<string> protectedAccounts,
        bool isDomainJoined,
        ILogger logger)
    {
        if (isDomainJoined)
        {
            try
            {
                return ReadAccounts(protectedAccounts, ContextType.Domain, AccountSources.Domain, logger);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Domain account lookup failed. Falling back to the local account database.");
                return ReadAccounts(protectedAccounts, ContextType.Machine, AccountSources.Local, logger);
            }
        }

        return ReadAccounts(protectedAccounts, ContextType.Machine, AccountSources.Local, logger);
    }

    // Change Password extended right. Denying it to SELF and Everyone is how "user cannot change password" is stored in AD.
    private static readonly Guid ChangePasswordRight = new("ab721a53-1e2f-11d0-9819-00aa0040529b");

    public static void Apply(AgentCommand command, bool isDomainJoined)
    {
        // The two flag commands use the Windows net API on local accounts, so they are routed before the shared path.
        if (!isDomainJoined && command.CommandType == CommandTypes.PasswordNeverExpires)
        {
            LocalAccountHelper.SetPasswordNeverExpires(command.SamAccountName, true);
            return;
        }

        if (!isDomainJoined && command.CommandType == CommandTypes.CannotChangePassword)
        {
            LocalAccountHelper.SetCannotChangePassword(command.SamAccountName, true);
            return;
        }

        var contextType = isDomainJoined ? ContextType.Domain : ContextType.Machine;
        using var context = new PrincipalContext(contextType);
        using var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, command.SamAccountName)
            ?? throw new InvalidOperationException($"Account '{command.SamAccountName}' was not found.");

        switch (command.CommandType)
        {
            case CommandTypes.UnlockAccount:
                user.UnlockAccount();
                break;
            case CommandTypes.ResetPassword:
                if (string.IsNullOrEmpty(command.NewPassword))
                {
                    throw new InvalidOperationException("NewPassword is required to reset a password.");
                }

                user.SetPassword(command.NewPassword);
                break;
            case CommandTypes.EnableAccount:
                user.Enabled = true;
                break;
            case CommandTypes.DisableAccount:
                user.Enabled = false;
                break;
            case CommandTypes.PasswordNeverExpires:
                user.PasswordNeverExpires = true;
                break;
            case CommandTypes.CannotChangePassword:
                DenyChangePassword(user);
                break;
            default:
                throw new InvalidOperationException($"Unknown command type '{command.CommandType}'.");
        }

        user.Save();
    }

    // Adds Deny ACEs for the Change Password extended right to SELF and Everyone on the directory object.
    private static void DenyChangePassword(UserPrincipal user)
    {
        if (user.GetUnderlyingObject() is not DirectoryEntry entry)
        {
            throw new InvalidOperationException("The account does not expose a directory entry.");
        }

        var security = entry.ObjectSecurity;
        var self = new SecurityIdentifier(WellKnownSidType.SelfSid, null);
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);

        security.AddAccessRule(new ActiveDirectoryAccessRule(
            self,
            ActiveDirectoryRights.ExtendedRight,
            AccessControlType.Deny,
            ChangePasswordRight));
        security.AddAccessRule(new ActiveDirectoryAccessRule(
            everyone,
            ActiveDirectoryRights.ExtendedRight,
            AccessControlType.Deny,
            ChangePasswordRight));

        entry.CommitChanges();
    }

    private static List<AccountStatus> ReadAccounts(
        IReadOnlyList<string> protectedAccounts,
        ContextType contextType,
        string source,
        ILogger logger)
    {
        var results = new List<AccountStatus>();
        using var context = new PrincipalContext(contextType);
        foreach (var name in protectedAccounts)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            var samAccountName = name.Trim();
            try
            {
                using var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, samAccountName);
                if (user is null)
                {
                    logger.LogWarning("Protected account {SamAccountName} was not found in {Source}", samAccountName, source);
                    continue;
                }

                var neverExpires = false;
                try
                {
                    neverExpires = user.PasswordNeverExpires;
                }
                catch (Exception)
                {
                    // Some directories do not expose the flag; leave expiry unreported.
                }

                results.Add(new AccountStatus(
                    user.SamAccountName ?? samAccountName,
                    user.DisplayName ?? string.Empty,
                    user.Enabled ?? false,
                    user.IsAccountLockedOut(),
                    user.AccountExpirationDate,
                    user.LastPasswordSet,
                    user.LastLogon,
                    user.BadLogonCount,
                    source,
                    neverExpires ? null : ReadPasswordExpiryUtc(user),
                    neverExpires));
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to read protected account {SamAccountName}", samAccountName);
            }
        }

        return results;
    }

    // Domain accounts publish a computed expiry. Local accounts and directories without the
    // attribute leave this null so the portal does not invent an expiry.
    private static DateTime? ReadPasswordExpiryUtc(UserPrincipal user)
    {
        try
        {
            if (user.GetUnderlyingObject() is not DirectoryEntry entry)
            {
                return null;
            }

            entry.RefreshCache(new[] { "msDS-UserPasswordExpiryTimeComputed" });
            var raw = entry.Properties["msDS-UserPasswordExpiryTimeComputed"].Value;
            var fileTime = raw switch
            {
                long value => value,
                int value => value,
                string text when long.TryParse(text, out var parsed) => parsed,
                _ => 0L
            };
            if (fileTime <= 0 || fileTime >= 0x7FFFFFFFFFFFFFFF)
            {
                return null;
            }

            return DateTime.FromFileTimeUtc(fileTime);
        }
        catch (Exception)
        {
            return null;
        }
    }
}
