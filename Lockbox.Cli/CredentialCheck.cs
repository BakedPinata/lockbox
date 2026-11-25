namespace Lockbox.Cli;

/// <summary>
/// Checks credentials against the real service, for example by requesting a token. Called by
/// <c>verify-credentials</c> (and after <c>set-credentials</c>) once every secret has decrypted.
/// </summary>
/// <param name="credentials">The decrypted values, keyed by <see cref="CredentialDefinition.Name"/>.</param>
/// <param name="cancellationToken">Cancels the check.</param>
/// <returns>Whether the service accepted the credentials, and an optional message. Never include secret values.</returns>
public delegate Task<CredentialCheckResult> CredentialCheck(IReadOnlyDictionary<string, string> credentials, CancellationToken cancellationToken);

/// <summary>The outcome of a <see cref="CredentialCheck"/>.</summary>
/// <param name="Succeeded">Whether the service accepted the credentials.</param>
/// <param name="Message">Extra detail to show, for example "Signed in as alice" or "HTTP 401". Never a secret value.</param>
public sealed record CredentialCheckResult(bool Succeeded, string? Message = null)
{
    /// <summary>The service accepted the credentials.</summary>
    public static CredentialCheckResult Success(string? message = null) => new(true, message);

    /// <summary>The service rejected the credentials, or couldn't be reached.</summary>
    public static CredentialCheckResult Failure(string message) => new(false, message);
}
