using System.Security.Principal;

namespace Lockbox;

/// <summary>
/// Identifies a Windows account on a machine. Lockbox records the account that encrypted a secrets
/// file as <c>"encryptedBy"</c>. That is <b>diagnostic metadata only</b> and is never used for security.
/// </summary>
/// <param name="Account">The account name, for example <c>DOMAIN\user</c>.</param>
/// <param name="Sid">The account's security identifier, when known.</param>
/// <param name="Machine">The machine name.</param>
public sealed record AccountInfo(string Account, string? Sid, string Machine)
{
    /// <summary>Gets the account the current process is running as.</summary>
    public static AccountInfo GetCurrent()
    {
        if (OperatingSystem.IsWindows())
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new AccountInfo(identity.Name, identity.User?.Value, Environment.MachineName);
        }

        // Only reached in tests and tooling on other platforms. DPAPI itself is Windows-only.
        return new AccountInfo($@"{Environment.UserDomainName}\{Environment.UserName}", null, Environment.MachineName);
    }

    /// <summary>
    /// Whether both values refer to the same account. Compares SIDs when both are known, otherwise account names.
    /// The machine isn't compared, because a roaming domain profile can decrypt on other machines.
    /// </summary>
    public bool IsSameAccountAs(AccountInfo other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return Sid is not null && other.Sid is not null
            ? string.Equals(Sid, other.Sid, StringComparison.OrdinalIgnoreCase)
            : string.Equals(Account, other.Account, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Whether both values are on the same machine.</summary>
    public bool IsSameMachineAs(AccountInfo other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return string.Equals(Machine, other.Machine, StringComparison.OrdinalIgnoreCase);
    }

    /// <inheritdoc />
    public override string ToString() => $"{Account} on {Machine}";
}
