namespace Lockbox;

/// <summary>
/// Encrypts and decrypts secret values. <see cref="SecretStore"/> uses this so that other
/// mechanisms (for example a certificate-based protector) can be added without changing apps.
/// </summary>
public interface ISecretProtector
{
    /// <summary>
    /// Identifies the mechanism. It is written to the secrets file as <c>"protector"</c> and
    /// checked on load, so a file is never handed to the wrong protector.
    /// </summary>
    string Id { get; }

    /// <summary>Encrypts <paramref name="plaintext"/>.</summary>
    /// <param name="plaintext">The bytes to protect.</param>
    /// <param name="context">
    /// A non-secret value the ciphertext is bound to. <see cref="Unprotect"/> must fail when it is
    /// given a different context. <see cref="SecretStore"/> passes <c>"&lt;AppName&gt;|&lt;secretName&gt;"</c>.
    /// </param>
    byte[] Protect(byte[] plaintext, string context);

    /// <summary>Decrypts data produced by <see cref="Protect"/>.</summary>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// The data can't be decrypted by the current identity, the context doesn't match, or the data is damaged.
    /// </exception>
    byte[] Unprotect(byte[] ciphertext, string context);
}
