namespace Lockbox;

/// <summary>
/// Describes a secrets file without decrypting anything. Intended for <c>show-credentials-info</c>.
/// </summary>
/// <param name="FilePath">The full path of the file.</param>
/// <param name="Version">The file format version.</param>
/// <param name="Protector">The protector that encrypted the secrets, for example <c>dpapi-user</c>.</param>
/// <param name="EncryptedBy">The account that last wrote secrets to the file, if recorded. Diagnostic only.</param>
/// <param name="Secrets">The secrets in the file, ordered by name.</param>
public sealed record SecretFileInfo(
    string FilePath,
    int Version,
    string Protector,
    AccountInfo? EncryptedBy,
    IReadOnlyList<SecretEntryInfo> Secrets);

/// <summary>A secret's name and when its current value was encrypted. Never includes the value.</summary>
/// <param name="Name">The secret's name, for example <c>jira.pat</c>.</param>
/// <param name="CreatedUtc">When the current value was encrypted, in UTC.</param>
public sealed record SecretEntryInfo(string Name, DateTime CreatedUtc);

/// <summary>The result of checking that one secret can be decrypted. Never includes the value.</summary>
/// <param name="Name">The secret's name.</param>
/// <param name="Error">Why the secret can't be used, or <see langword="null"/> when it decrypted successfully.</param>
public sealed record SecretCheckResult(string Name, SecretStoreException? Error)
{
    /// <summary>Whether the secret decrypted successfully.</summary>
    public bool Succeeded => Error is null;
}
