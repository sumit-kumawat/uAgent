using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging.Abstractions;
using uAgent.Shared;

namespace uAgent.Agent;

internal sealed record AccountCollection(
    IReadOnlyList<string> ProtectedAccounts,
    bool EnumerateAll,
    int MaxAccounts,
    bool IsDomainJoined);

// Account is the state read back from Windows after the change; Changed is false when nothing had to be done.
internal sealed record AccountChange(AccountStatus Account, string Message, bool Changed);

// Domain operations use the process identity. LocalSystem can manage local accounts.
// Domain changes succeed only when that identity has rights to the account.
[SupportedOSPlatform("windows")]
internal static class WindowsAccountDirectory
{
    // Every local account is enumerated. On a domain-joined host the domain users that hold membership in a
    // local group (Administrators, Remote Desktop Users, ...) are added, because they are the domain accounts
    // authorised on this computer. Protected names are always looked up and flagged.
    public static IReadOnlyList<AccountStatus> Collect(AccountCollection request, ILogger logger)
    {
        var protectedNames = new HashSet<string>(request.ProtectedAccounts, StringComparer.OrdinalIgnoreCase);
        var max = Math.Max(1, request.MaxAccounts);
        var results = new List<AccountStatus>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(AccountStatus? account)
        {
            if (account is not null && results.Count < max && seen.Add($"{account.Source}\\{account.SamAccountName}"))
            {
                results.Add(account);
            }
        }

        using var machine = new PrincipalContext(ContextType.Machine);
        var membership = ReadLocalGroupMembership(machine, logger);
        var maxPasswordAge = SafeMaxPasswordAge();

        if (request.EnumerateAll)
        {
            try
            {
                using var searcher = new PrincipalSearcher(new UserPrincipal(machine));
                foreach (var principal in searcher.FindAll())
                {
                    using (principal)
                    {
                        if (principal is UserPrincipal user)
                        {
                            Add(Read(user, AccountSources.Local, membership, protectedNames, maxPasswordAge, logger));
                        }
                    }

                    if (results.Count >= max)
                    {
                        logger.LogWarning("Account inventory reached the configured limit of {Max} accounts.", max);
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Local account enumeration failed.");
            }
        }

        if (request.IsDomainJoined)
        {
            var domainNames = protectedNames
                .Concat(request.EnumerateAll ? membership.DomainMembers : [])
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            if (domainNames.Length > 0)
            {
                try
                {
                    using var domain = new PrincipalContext(ContextType.Domain);
                    foreach (var name in domainNames)
                    {
                        Add(Lookup(domain, name, AccountSources.Domain, membership, protectedNames, null, logger));
                    }
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "The domain could not be queried. Domain accounts are omitted from this inventory.");
                }
            }
        }

        // Protected names that were not found in the domain (or when enumeration is off) are checked locally.
        foreach (var name in protectedNames)
        {
            if (!seen.Contains($"{AccountSources.Local}\\{name}") && !seen.Contains($"{AccountSources.Domain}\\{name}"))
            {
                Add(Lookup(machine, name, AccountSources.Local, membership, protectedNames, maxPasswordAge, logger));
            }
        }

        return results;
    }

    public static AccountChange Apply(AgentCommand command, bool isDomainJoined)
    {
        var name = command.SamAccountName;
        var source = command.AccountSource;
        if (source == AccountSources.Local || (!isDomainJoined && source != AccountSources.Domain))
        {
            return ApplyIn(command, domain: false);
        }

        if (source != AccountSources.Domain && LocalAccountExists(name))
        {
            return ApplyIn(command, domain: false);
        }

        try
        {
            return ApplyIn(command, domain: true);
        }
        catch (Exception ex) when (IsAccessDenied(ex))
        {
            throw new InvalidOperationException(
                $"Access is denied changing domain account '{name}'. The agent runs as LocalSystem and can change accounts on this computer. A domain administrator has to change '{name}' in Active Directory.",
                ex);
        }
    }

    private static bool LocalAccountExists(string name)
    {
        try
        {
            using var context = new PrincipalContext(ContextType.Machine);
            using var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, name);
            return user is not null;
        }
        catch (Exception ex) when (ex is PrincipalServerDownException or InvalidOperationException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static bool IsAccessDenied(Exception ex)
    {
        for (var current = ex; current is not null; current = current.InnerException)
        {
            if (current is UnauthorizedAccessException)
            {
                return true;
            }

            if (current.Message.Contains("Access is denied", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    // Applies one change, then reads the account back from a fresh context and confirms Windows reports the
    // requested state. A request that is already satisfied is reported as such instead of being re-applied.
    private static AccountChange ApplyIn(AgentCommand command, bool domain)
    {
        var name = command.SamAccountName;
        var scope = domain ? AccountSources.Domain : AccountSources.Local;
        var desired = command.Value ?? true;
        string? unchanged = null;

        using (var context = new PrincipalContext(domain ? ContextType.Domain : ContextType.Machine))
        using (var user = Find(context, name, domain))
        {
            switch (command.CommandType)
            {
                case CommandTypes.UnlockAccount:
                    if (!Safe(user.IsAccountLockedOut))
                    {
                        unchanged = "is not locked out";
                        break;
                    }

                    user.UnlockAccount();
                    user.Save();
                    break;
                case CommandTypes.ResetPassword:
                    if (string.IsNullOrEmpty(command.NewPassword))
                    {
                        throw new InvalidOperationException("A new password is required to reset a password.");
                    }

                    user.SetPassword(command.NewPassword);
                    user.Save();
                    break;
                case CommandTypes.EnableAccount:
                case CommandTypes.DisableAccount:
                    var enable = command.CommandType == CommandTypes.EnableAccount;
                    if (user.Enabled == enable)
                    {
                        unchanged = enable ? "is already enabled" : "is already disabled";
                        break;
                    }

                    user.Enabled = enable;
                    user.Save();
                    break;
                case CommandTypes.PasswordNeverExpires:
                    if (Safe(() => user.PasswordNeverExpires) == desired)
                    {
                        unchanged = desired ? "already has a password that never expires" : "already has a password that expires";
                        break;
                    }

                    if (domain)
                    {
                        user.PasswordNeverExpires = desired;
                        user.Save();
                    }
                    else
                    {
                        LocalAccountHelper.SetPasswordNeverExpires(name, desired);
                    }

                    break;
                case CommandTypes.CannotChangePassword:
                    if (SafeFlag(() => user.UserCannotChangePassword) == desired)
                    {
                        unchanged = desired ? "already cannot change its password" : "can already change its password";
                        break;
                    }

                    if (domain)
                    {
                        user.UserCannotChangePassword = desired;
                        user.Save();
                    }
                    else
                    {
                        LocalAccountHelper.SetCannotChangePassword(name, desired);
                    }

                    break;
                default:
                    throw new InvalidOperationException($"Unknown command type '{command.CommandType}'.");
            }
        }

        var verified = ReadBack(name, domain);
        var problem = command.CommandType switch
        {
            CommandTypes.UnlockAccount when verified.LockedOut => "is still locked out",
            CommandTypes.EnableAccount when !verified.Enabled => "is still disabled",
            CommandTypes.DisableAccount when verified.Enabled => "is still enabled",
            CommandTypes.PasswordNeverExpires when verified.PasswordNeverExpires != desired =>
                desired ? "still has an expiring password" : "still has a password that never expires",
            CommandTypes.CannotChangePassword when verified.UserCannotChangePassword is { } flag && flag != desired =>
                desired ? "can still change its password" : "still cannot change its password",
            _ => null
        };
        if (problem is not null)
        {
            throw new InvalidOperationException($"The change was sent, but Windows reports that '{name}' {problem}.");
        }

        var where = scope == AccountSources.Domain ? "domain account" : "local account";
        var message = unchanged is not null
            ? $"No change needed: '{name}' ({where}) {unchanged}."
            : command.CommandType switch
            {
                CommandTypes.UnlockAccount => $"'{name}' ({where}) was unlocked. Verified: not locked out.",
                CommandTypes.ResetPassword => $"The password for '{name}' ({where}) was reset.",
                CommandTypes.EnableAccount => $"'{name}' ({where}) was enabled. Verified: enabled.",
                CommandTypes.DisableAccount => $"'{name}' ({where}) was disabled. Verified: disabled.",
                CommandTypes.PasswordNeverExpires => desired
                    ? $"The password for '{name}' ({where}) is now set to never expire. Verified."
                    : $"The password for '{name}' ({where}) now follows the expiry policy. Verified.",
                _ => desired
                    ? $"'{name}' ({where}) can no longer change its password. Verified."
                    : $"'{name}' ({where}) can change its password again. Verified."
            };
        return new AccountChange(verified, message, unchanged is null);
    }

    private static UserPrincipal Find(PrincipalContext context, string name, bool domain) =>
        UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, name)
        ?? throw new InvalidOperationException($"Account '{name}' was not found in the {(domain ? "domain" : "local")} account database.");

    private static AccountStatus ReadBack(string name, bool domain)
    {
        using var context = new PrincipalContext(domain ? ContextType.Domain : ContextType.Machine);
        using var user = Find(context, name, domain);
        return Read(user, domain ? AccountSources.Domain : AccountSources.Local, new GroupMembership(), [], domain ? null : SafeMaxPasswordAge(), NullLogger.Instance)
            ?? throw new InvalidOperationException($"Account '{name}' could not be read back after the change.");
    }

    private sealed class GroupMembership
    {
        public Dictionary<string, List<string>> GroupsBySid { get; } = new(StringComparer.OrdinalIgnoreCase);

        public HashSet<string> DomainMembers { get; } = new(StringComparer.OrdinalIgnoreCase);

        public IReadOnlyList<string> GroupsOf(string? sid) =>
            sid is not null && GroupsBySid.TryGetValue(sid, out var groups) ? groups : [];
    }

    // One pass over the local groups gives every account's local group list and the domain users granted access here.
    private static GroupMembership ReadLocalGroupMembership(PrincipalContext machine, ILogger logger)
    {
        var membership = new GroupMembership();
        try
        {
            using var searcher = new PrincipalSearcher(new GroupPrincipal(machine));
            foreach (var principal in searcher.FindAll())
            {
                using (principal)
                {
                    if (principal is not GroupPrincipal group || string.IsNullOrEmpty(group.Name))
                    {
                        continue;
                    }

                    try
                    {
                        foreach (var member in group.GetMembers(recursive: false))
                        {
                            using (member)
                            {
                                if (member is not UserPrincipal || member.Sid is null)
                                {
                                    continue;
                                }

                                var sid = member.Sid.Value;
                                if (!membership.GroupsBySid.TryGetValue(sid, out var groups))
                                {
                                    groups = [];
                                    membership.GroupsBySid[sid] = groups;
                                }

                                groups.Add(group.Name);
                                if (member.ContextType == ContextType.Domain && !string.IsNullOrEmpty(member.SamAccountName))
                                {
                                    membership.DomainMembers.Add(member.SamAccountName);
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        // Orphaned SIDs or an unreachable domain controller make one group unreadable; keep the others.
                        logger.LogDebug(ex, "Members of local group {Group} could not be read.", group.Name);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Local group membership could not be read.");
        }

        return membership;
    }

    private static AccountStatus? Lookup(
        PrincipalContext context,
        string name,
        string source,
        GroupMembership membership,
        HashSet<string> protectedNames,
        TimeSpan? maxPasswordAge,
        ILogger logger)
    {
        try
        {
            using var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, name);
            if (user is null)
            {
                logger.LogDebug("Account {SamAccountName} was not found in {Source}.", name, source);
                return null;
            }

            return Read(user, source, membership, protectedNames, maxPasswordAge, logger);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to read account {SamAccountName} from {Source}.", name, source);
            return null;
        }
    }

    private static AccountStatus? Read(
        UserPrincipal user,
        string source,
        GroupMembership membership,
        HashSet<string> protectedNames,
        TimeSpan? maxPasswordAge,
        ILogger logger)
    {
        var samAccountName = user.SamAccountName;
        if (string.IsNullOrEmpty(samAccountName))
        {
            return null;
        }

        try
        {
            var neverExpires = Safe(() => user.PasswordNeverExpires);
            var lastPasswordSet = user.LastPasswordSet;
            DateTime? expires = null;
            if (!neverExpires)
            {
                expires = source == AccountSources.Domain
                    ? ReadPasswordExpiryUtc(user)
                    : lastPasswordSet is { } set && maxPasswordAge is { } age ? DateTime.SpecifyKind(set, DateTimeKind.Utc) + age : null;
            }

            return new AccountStatus(
                samAccountName,
                user.DisplayName ?? string.Empty,
                user.Enabled ?? false,
                Safe(user.IsAccountLockedOut),
                user.AccountExpirationDate,
                lastPasswordSet,
                user.LastLogon,
                Safe(() => user.BadLogonCount),
                source,
                expires,
                neverExpires,
                user.Sid?.Value,
                string.IsNullOrWhiteSpace(user.Description) ? null : user.Description.Trim(),
                membership.GroupsOf(user.Sid?.Value),
                protectedNames.Contains(samAccountName),
                SafeFlag(() => user.UserCannotChangePassword));
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to read account {SamAccountName}.", samAccountName);
            return null;
        }
    }

    private static T Safe<T>(Func<T> read)
    {
        try
        {
            return read();
        }
        catch (Exception)
        {
            return default!; // Some directories do not expose every attribute; report the default instead.
        }
    }

    private static bool? SafeFlag(Func<bool> read)
    {
        try
        {
            return read();
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static TimeSpan? SafeMaxPasswordAge()
    {
        try
        {
            return LocalAccountHelper.GetMaxPasswordAge();
        }
        catch (Exception)
        {
            return null;
        }
    }

    // Domain accounts publish a computed expiry. Directories without the attribute leave this null
    // so the portal does not invent an expiry.
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
