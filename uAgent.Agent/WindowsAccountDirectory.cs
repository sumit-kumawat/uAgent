using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using uAgent.Shared;

namespace uAgent.Agent;

internal sealed record AccountCollection(
    IReadOnlyList<string> ProtectedAccounts,
    bool EnumerateAll,
    int MaxAccounts,
    bool IsDomainJoined);

// Domain operations use the process identity. LocalSystem can manage local accounts.
// Domain changes succeed only when that identity has rights to the account.
[SupportedOSPlatform("windows")]
internal static class WindowsAccountDirectory
{
    // Change Password extended right. Denying it to SELF and Everyone is how "user cannot change password" is stored in AD.
    private static readonly Guid ChangePasswordRight = new("ab721a53-1e2f-11d0-9819-00aa0040529b");

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

    public static void Apply(AgentCommand command, bool isDomainJoined)
    {
        var name = command.SamAccountName;
        var source = command.AccountSource;
        if (source == AccountSources.Local || (!isDomainJoined && source != AccountSources.Domain))
        {
            ApplyIn(command, domain: false);
            return;
        }

        // The portal used to omit the account source. On a domain member that sent every name, including
        // local accounts such as DefaultAccount, to Active Directory.
        if (source != AccountSources.Domain && LocalAccountExists(name))
        {
            ApplyIn(command, domain: false);
            return;
        }

        try
        {
            ApplyIn(command, domain: true);
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

    private static void ApplyIn(AgentCommand command, bool domain)
    {
        var useDomain = domain;

        // The two flag commands use the Windows net API on local accounts, so they are routed before the shared path.
        if (!useDomain && command.CommandType == CommandTypes.PasswordNeverExpires)
        {
            LocalAccountHelper.SetPasswordNeverExpires(command.SamAccountName, true);
            return;
        }

        if (!useDomain && command.CommandType == CommandTypes.CannotChangePassword)
        {
            LocalAccountHelper.SetCannotChangePassword(command.SamAccountName, true);
            return;
        }

        using var context = new PrincipalContext(useDomain ? ContextType.Domain : ContextType.Machine);
        using var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, command.SamAccountName)
            ?? throw new InvalidOperationException($"Account '{command.SamAccountName}' was not found in the {(useDomain ? "domain" : "local")} account database.");

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
                protectedNames.Contains(samAccountName));
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
