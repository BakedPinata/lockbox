namespace Lockbox;

/// <summary>Why a <see cref="SecretStore"/> operation failed.</summary>
public enum SecretStoreError
{
    /// <summary>There is no secrets file at the path.</summary>
    FileNotFound,

    /// <summary>The secrets file couldn't be read or written, for example because access was denied.</summary>
    FileAccessFailed,

    /// <summary>The secrets file isn't valid JSON or doesn't match the expected format.</summary>
    CorruptFile,

    /// <summary>The secrets file was written by a newer version of Lockbox.</summary>
    UnsupportedVersion,

    /// <summary>The secrets file was written with a different protector from the one in use.</summary>
    ProtectorMismatch,

    /// <summary>The requested secret isn't in the file.</summary>
    SecretNotFound,

    /// <summary>The file's secrets belong to a different Windows account from the one running the process.</summary>
    EncryptedByAnotherAccount,

    /// <summary>The file was encrypted by the same account but on a different machine, and couldn't be decrypted here.</summary>
    EncryptedOnAnotherMachine,

    /// <summary>The secret couldn't be decrypted for another reason (edited or swapped entry, or an admin password reset).</summary>
    DecryptionFailed,
}

/// <summary>
/// A <see cref="SecretStore"/> operation failed. The message says what went wrong and how to fix it.
/// Messages and properties never contain secret values.
/// </summary>
#pragma warning disable CA1032 // Standard constructors would allow an exception with no error kind or path.
public sealed class SecretStoreException : Exception
#pragma warning restore CA1032
{
    internal SecretStoreException(SecretStoreError error, string filePath, string? secretName, string message, Exception? innerException = null)
        : base(message, innerException)
    {
        Error = error;
        FilePath = filePath;
        SecretName = secretName;
    }

    /// <summary>Why the operation failed.</summary>
    public SecretStoreError Error { get; }

    /// <summary>The full path of the secrets file involved.</summary>
    public string FilePath { get; }

    /// <summary>The secret involved, if the failure concerns a single secret.</summary>
    public string? SecretName { get; }
}
