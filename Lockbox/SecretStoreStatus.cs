namespace Lockbox;

/// <summary>What <see cref="SecretStore.Inspect"/> found about the secrets file as a whole.</summary>
public enum SecretFileState
{
    /// <summary>There's no file yet. Saving creates it.</summary>
    Missing,

    /// <summary>The file can be read and added to by the current account (it's theirs, or it holds no secrets).</summary>
    Usable,

    /// <summary>The file's secrets belong to another account. It must be replaced before saving.</summary>
    OtherAccount,

    /// <summary>The file was written with another protector. It must be replaced before saving.</summary>
    OtherProtector,

    /// <summary>The file is damaged. It must be replaced before saving.</summary>
    Corrupt,

    /// <summary>The file was written by a newer version of Lockbox. Update the app; don't overwrite it.</summary>
    Unsupported,

    /// <summary>The file couldn't be read, for example because access was denied.</summary>
    Unreadable,
}

/// <summary>What <see cref="SecretStore.Inspect"/> found about one secret.</summary>
public enum SecretState
{
    /// <summary>The file couldn't be read, so the secret's state is unknown.</summary>
    Unknown,

    /// <summary>The secret isn't in the file.</summary>
    Missing,

    /// <summary>The secret is present and decrypts. Its current value can be kept.</summary>
    Usable,

    /// <summary>The secret is present but doesn't decrypt for the current account. It must be entered again.</summary>
    Unreadable,
}

/// <summary>One secret's state. Never includes the value.</summary>
/// <param name="Name">The secret's name.</param>
/// <param name="State">Whether it's present and decrypts.</param>
/// <param name="CreatedUtc">When the current value was encrypted, if present.</param>
/// <param name="Error">Why it doesn't decrypt, for <see cref="SecretState.Unreadable"/>.</param>
public sealed record SecretStatus(string Name, SecretState State, DateTime? CreatedUtc, SecretStoreException? Error);

/// <summary>The result of <see cref="SecretStore.Inspect"/>.</summary>
/// <param name="FileState">What was found about the file.</param>
/// <param name="Info">The file's metadata, when it could be read.</param>
/// <param name="Error">An explanation for every state except <see cref="SecretFileState.Missing"/> and <see cref="SecretFileState.Usable"/>.</param>
/// <param name="Secrets">Each requested secret, in the order asked for.</param>
public sealed record SecretStoreStatus(
    SecretFileState FileState,
    SecretFileInfo? Info,
    SecretStoreException? Error,
    IReadOnlyList<SecretStatus> Secrets)
{
    /// <summary>
    /// Whether the existing file must be replaced (with <see cref="SecretStore.ReplaceSecrets"/>, after asking the user)
    /// before secrets can be saved.
    /// </summary>
    public bool RequiresReplace => FileState is SecretFileState.OtherAccount or SecretFileState.OtherProtector or SecretFileState.Corrupt;

    /// <summary>Whether secrets can be saved at all (possibly after replacing the file).</summary>
    public bool CanSave => FileState is not (SecretFileState.Unsupported or SecretFileState.Unreadable);
}
