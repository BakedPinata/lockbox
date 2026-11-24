using System.Security.Cryptography;
using System.Text;

namespace Lockbox;

/// <summary>
/// Protects secrets with Windows DPAPI in <see cref="DataProtectionScope.CurrentUser"/> scope.
/// Only processes running as the Windows account that encrypted a value can decrypt it.
/// </summary>
/// <remarks>
/// The context is passed to DPAPI as optional entropy. It isn't a secret. It stops other apps
/// running as the same user from casually decrypting the values, and it binds each value to its
/// name so that swapped entries fail to decrypt.
/// <c>DataProtectionScope.LocalMachine</c> is deliberately not supported: any user on the machine could decrypt.
/// </remarks>
public sealed class DpapiUserProtector : ISecretProtector
{
    /// <summary>The value written to the secrets file's <c>"protector"</c> property.</summary>
    public const string ProtectorId = "dpapi-user";

    /// <inheritdoc />
    public string Id => ProtectorId;

    /// <inheritdoc />
    public byte[] Protect(byte[] plaintext, string context)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(context);
        return ProtectedData.Protect(plaintext, Encoding.UTF8.GetBytes(context), DataProtectionScope.CurrentUser);
    }

    /// <inheritdoc />
    public byte[] Unprotect(byte[] ciphertext, string context)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(context);
        return ProtectedData.Unprotect(ciphertext, Encoding.UTF8.GetBytes(context), DataProtectionScope.CurrentUser);
    }
}
