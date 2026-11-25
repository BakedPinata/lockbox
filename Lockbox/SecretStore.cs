using System.Security.Cryptography;
using System.Text;

namespace Lockbox;

/// <summary>
/// Loads and saves named secrets in a JSON file, encrypted with an <see cref="ISecretProtector"/>
/// (Windows DPAPI, CurrentUser scope, by default).
/// </summary>
/// <remarks>
/// <para>
/// Every operation reads the file again, so changes made by another process (for example
/// <c>set-credentials</c>) are picked up. Writes replace the file atomically.
/// </para>
/// <para>
/// Each value is bound to <c>"&lt;AppName&gt;|&lt;secretName&gt;"</c>. A value copied to another name,
/// or read by an app with a different <see cref="AppName"/>, fails to decrypt.
/// </para>
/// <para>
/// Errors are reported as <see cref="SecretStoreException"/> with a message that explains how to fix
/// the problem. Secret values are never included in messages.
/// </para>
/// </remarks>
public sealed class SecretStore
{
    /// <summary>The file name used by <see cref="GetDefaultPath"/>.</summary>
    public const string DefaultFileName = "secrets.json";

    private const int MaxSecretNameLength = 128;

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private readonly ISecretProtector _protector;
    private readonly TimeProvider _timeProvider;
    private readonly Func<AccountInfo> _currentAccount;

    /// <summary>Creates a store for an app.</summary>
    /// <param name="appName">
    /// The app's name, for example <c>JiraExport</c>. It names the default folder and is bound into every
    /// encrypted value, so keep it the same across releases. It can't contain <c>|</c> or path characters.
    /// </param>
    /// <param name="filePath">
    /// The secrets file to use, for example from config or <c>--secrets-path</c>. Environment variables such as
    /// <c>%USERPROFILE%</c> are expanded. When <see langword="null"/> or empty, <see cref="GetDefaultPath"/> is used.
    /// </param>
    /// <param name="protector">The protector to use. Defaults to <see cref="DpapiUserProtector"/>.</param>
    public SecretStore(string appName, string? filePath = null, ISecretProtector? protector = null)
        : this(appName, filePath, protector ?? new DpapiUserProtector(), TimeProvider.System, AccountInfo.GetCurrent)
    {
    }

    internal SecretStore(string appName, string? filePath, ISecretProtector protector, TimeProvider timeProvider, Func<AccountInfo> currentAccount)
    {
        ValidateAppName(appName);
        ArgumentNullException.ThrowIfNull(protector);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(currentAccount);

        AppName = appName;
        FilePath = string.IsNullOrWhiteSpace(filePath)
            ? GetDefaultPath(appName)
            : Path.GetFullPath(Environment.ExpandEnvironmentVariables(filePath));
        _protector = protector;
        _timeProvider = timeProvider;
        _currentAccount = currentAccount;
    }

    /// <summary>The app name that values are bound to.</summary>
    public string AppName { get; }

    /// <summary>The full path of the secrets file.</summary>
    public string FilePath { get; }

    /// <summary>Whether the secrets file exists.</summary>
    public bool Exists => File.Exists(FilePath);

    /// <summary>The <see cref="ISecretProtector.Id"/> of the protector this store encrypts with.</summary>
    public string ProtectorId => _protector.Id;

    /// <summary>The account this process runs as, which is the account that <see cref="SetSecrets"/> encrypts for.</summary>
    public AccountInfo CurrentAccount => _currentAccount();

    /// <summary>Gets the default secrets file path: <c>%APPDATA%\&lt;appName&gt;\secrets.json</c>.</summary>
    public static string GetDefaultPath(string appName)
    {
        ValidateAppName(appName);
        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), appName, DefaultFileName);
    }

    /// <summary>
    /// Whether <paramref name="name"/> can be used as a secret name: 1–128 characters of letters, digits,
    /// <c>.</c>, <c>_</c> and <c>-</c>, starting with a letter or digit. For example <c>api.password</c>.
    /// </summary>
    public static bool IsValidSecretName(string? name)
    {
        if (string.IsNullOrEmpty(name) || name.Length > MaxSecretNameLength || !char.IsAsciiLetterOrDigit(name[0]))
        {
            return false;
        }

        foreach (var c in name)
        {
            if (!char.IsAsciiLetterOrDigit(c) && c is not ('.' or '_' or '-'))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Decrypts and returns a secret.</summary>
    /// <exception cref="SecretStoreException">The file or secret is missing, or the secret can't be decrypted.</exception>
    public string GetSecret(string name)
    {
        ValidateSecretName(name);
        var file = LoadForReading();
        return Decrypt(file, name);
    }

    /// <summary>
    /// Checks that each secret is present and decrypts, without returning the values. Intended for
    /// <c>verify-credentials</c>.
    /// </summary>
    /// <exception cref="SecretStoreException">The file itself is missing or can't be used.</exception>
    public IReadOnlyList<SecretCheckResult> CheckSecrets(IEnumerable<string> names)
    {
        ArgumentNullException.ThrowIfNull(names);
        var nameList = names.ToList();
        nameList.ForEach(ValidateSecretName);

        var file = LoadForReading();
        var results = new List<SecretCheckResult>(nameList.Count);
        foreach (var name in nameList)
        {
            try
            {
                _ = Decrypt(file, name);
                results.Add(new SecretCheckResult(name, null));
            }
            catch (SecretStoreException ex)
            {
                results.Add(new SecretCheckResult(name, ex));
            }
        }

        return results;
    }

    /// <summary>
    /// Describes the file (path, protector, who encrypted it, secret names and dates) without decrypting
    /// anything. Intended for <c>show-credentials-info</c>.
    /// </summary>
    /// <exception cref="SecretStoreException">The file is missing or can't be read.</exception>
    public SecretFileInfo GetInfo()
    {
        var file = Load() ?? throw FileNotFound();
        return ToInfo(file);
    }

    /// <summary>Encrypts and saves one secret, keeping the file's other secrets.</summary>
    /// <inheritdoc cref="SetSecrets" path="/exception"/>
    public void SetSecret(string name, string value) =>
        SetSecrets(new Dictionary<string, string>(StringComparer.Ordinal) { [name] = value });

    /// <summary>
    /// Encrypts and saves several secrets in one write, keeping the file's other secrets. The file and its
    /// folder are created if needed.
    /// </summary>
    /// <exception cref="SecretStoreException">
    /// The existing file belongs to another account or protector, is corrupt or newer, or can't be written.
    /// Secrets from different accounts can't be mixed in one file. Use <see cref="Delete"/> to start again.
    /// </exception>
    public void SetSecrets(IReadOnlyDictionary<string, string> secrets)
    {
        ValidateValues(secrets);
        var current = _currentAccount();
        var file = Load() ?? new SecretFile(_protector.Id);

        if (file.Secrets.Count > 0)
        {
            if (!string.Equals(file.Protector, _protector.Id, StringComparison.Ordinal))
            {
                throw ProtectorMismatch(file);
            }

            if (file.EncryptedBy is { } owner && !owner.IsSameAccountAs(current))
            {
                throw AnotherAccountsFile(owner, current);
            }
        }

        EncryptInto(file, secrets, current);
        Save(file);
    }

    /// <summary>
    /// Replaces the whole file with these secrets in one atomic write, discarding everything it held before:
    /// another account's secrets, another protector's, or a corrupt file. Use it only once the user has agreed.
    /// </summary>
    /// <exception cref="SecretStoreException">The file can't be written.</exception>
    public void ReplaceSecrets(IReadOnlyDictionary<string, string> secrets)
    {
        ValidateValues(secrets);
        var file = new SecretFile(_protector.Id);
        EncryptInto(file, secrets, _currentAccount());
        Save(file);
    }

    /// <summary>
    /// Describes the file and each of <paramref name="names"/> without throwing: whether the file can be added to,
    /// must be replaced first, or can't be used, and whether each secret is present and decrypts. Intended for setup
    /// tools that need to decide what to offer.
    /// </summary>
    public SecretStoreStatus Inspect(IEnumerable<string> names)
    {
        ArgumentNullException.ThrowIfNull(names);
        var nameList = names.ToList();
        nameList.ForEach(ValidateSecretName);

        SecretFile? file;
        try
        {
            file = Load();
        }
        catch (SecretStoreException ex)
        {
            var state = ex.Error switch
            {
                SecretStoreError.CorruptFile => SecretFileState.Corrupt,
                SecretStoreError.UnsupportedVersion => SecretFileState.Unsupported,
                _ => SecretFileState.Unreadable,
            };
            return new SecretStoreStatus(state, null, ex, [.. nameList.Select(n => new SecretStatus(n, SecretState.Unknown, null, null))]);
        }

        if (file is null)
        {
            return new SecretStoreStatus(SecretFileState.Missing, null, null, [.. nameList.Select(n => new SecretStatus(n, SecretState.Missing, null, null))]);
        }

        var current = _currentAccount();
        var (fileState, fileError) = file.Secrets.Count == 0
            ? (SecretFileState.Usable, null)
            : !string.Equals(file.Protector, _protector.Id, StringComparison.Ordinal)
                ? (SecretFileState.OtherProtector, ProtectorMismatch(file))
                : file.EncryptedBy is { } owner && !owner.IsSameAccountAs(current)
                    ? (SecretFileState.OtherAccount, AnotherAccountsFile(owner, current))
                    : (SecretFileState.Usable, (SecretStoreException?)null);

        var secrets = new List<SecretStatus>(nameList.Count);
        foreach (var name in nameList)
        {
            if (!file.Secrets.TryGetValue(name, out var entry))
            {
                secrets.Add(new SecretStatus(name, SecretState.Missing, null, null));
                continue;
            }

            try
            {
                if (fileState == SecretFileState.OtherProtector)
                {
                    throw fileError!;
                }

                _ = Decrypt(file, name);
                secrets.Add(new SecretStatus(name, SecretState.Usable, entry.CreatedUtc, null));
            }
            catch (SecretStoreException ex)
            {
                secrets.Add(new SecretStatus(name, SecretState.Unreadable, entry.CreatedUtc, ex));
            }
        }

        return new SecretStoreStatus(fileState, ToInfo(file), fileError, secrets);
    }

    /// <summary>Removes a secret from the file.</summary>
    /// <returns><see langword="true"/> if the secret was removed; <see langword="false"/> if it wasn't there.</returns>
    /// <exception cref="SecretStoreException">The file is corrupt, newer, or can't be read or written.</exception>
    public bool RemoveSecret(string name)
    {
        ValidateSecretName(name);
        var file = Load();
        if (file is null || !file.Secrets.Remove(name))
        {
            return false;
        }

        // encryptedBy is left alone: the remaining secrets still belong to that account.
        Save(file);
        return true;
    }

    /// <summary>Deletes the secrets file, if it exists.</summary>
    /// <returns><see langword="true"/> if a file was deleted.</returns>
    /// <exception cref="SecretStoreException">The file couldn't be deleted.</exception>
    public bool Delete()
    {
        try
        {
            if (!File.Exists(FilePath))
            {
                return false;
            }

            File.Delete(FilePath);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw FileAccessFailed("deleted", ex);
        }
    }

    internal static void ValidateAppName(string appName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(appName);
        if (appName.Contains('|', StringComparison.Ordinal)
            || appName is "." or ".."
            || appName.AsSpan().IndexOfAny(Path.GetInvalidFileNameChars()) >= 0
            || appName.AsSpan().IndexOfAny('/', '\\') >= 0)
        {
            throw new ArgumentException($"'{appName}' can't be used as an app name. It can't contain '|' or path characters.", nameof(appName));
        }
    }

    private static void ValidateSecretName(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (!IsValidSecretName(name))
        {
            throw new ArgumentException(
                $"'{name}' can't be used as a secret name. Use 1–{MaxSecretNameLength} letters, digits, '.', '_' or '-', starting with a letter or digit.",
                nameof(name));
        }
    }

    private static void ValidateValues(IReadOnlyDictionary<string, string> secrets)
    {
        ArgumentNullException.ThrowIfNull(secrets);
        if (secrets.Count == 0)
        {
            throw new ArgumentException("At least one secret is required.", nameof(secrets));
        }

        foreach (var (name, value) in secrets)
        {
            ValidateSecretName(name);
            if (string.IsNullOrEmpty(value))
            {
                throw new ArgumentException($"The value for '{name}' is empty.", nameof(secrets));
            }
        }
    }

    private void EncryptInto(SecretFile file, IReadOnlyDictionary<string, string> secrets, AccountInfo current)
    {
        var createdUtc = _timeProvider.GetUtcNow().UtcDateTime;
        foreach (var (name, value) in secrets)
        {
            var plaintext = StrictUtf8.GetBytes(value);
            try
            {
                file.Secrets[name] = new SecretEntry(createdUtc, _protector.Protect(plaintext, GetContext(name)));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }

        file.Protector = _protector.Id;
        file.EncryptedBy = current;
    }

    private SecretFileInfo ToInfo(SecretFile file) => new(
        FilePath,
        SecretFile.CurrentVersion,
        file.Protector,
        file.EncryptedBy,
        [.. file.Secrets.Select(kv => new SecretEntryInfo(kv.Key, kv.Value.CreatedUtc))]);

    private SecretStoreException AnotherAccountsFile(AccountInfo owner, AccountInfo current) => new(
        SecretStoreError.EncryptedByAnotherAccount,
        FilePath,
        null,
        $"The secrets file '{FilePath}' was encrypted by {owner.Account} on {owner.Machine}, but you are running as " +
        $"{current.Account} on {current.Machine}. Its secrets can only be read by that account, so secrets from different " +
        "accounts can't be mixed in one file. Use a different secrets path, or replace all of its secrets.");

    private string GetContext(string name) => $"{AppName}|{name}";

    /// <summary>Loads the file, or returns <see langword="null"/> if it doesn't exist.</summary>
    private SecretFile? Load()
    {
        byte[] json;
        try
        {
            json = File.ReadAllBytes(FilePath);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw FileAccessFailed("read", ex);
        }

        return SecretFile.Parse(json, FilePath);
    }

    private SecretFile LoadForReading()
    {
        var file = Load() ?? throw FileNotFound();
        if (!string.Equals(file.Protector, _protector.Id, StringComparison.Ordinal))
        {
            throw ProtectorMismatch(file);
        }

        return file;
    }

    private void Save(SecretFile file)
    {
        var directory = Path.GetDirectoryName(FilePath)!;
        var tempPath = Path.Combine(directory, $"{Path.GetFileName(FilePath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            Directory.CreateDirectory(directory);
            using (var stream = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                file.WriteTo(stream);
                stream.Flush(flushToDisk: true);
            }

            File.Move(tempPath, FilePath, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            TryDelete(tempPath);
            throw FileAccessFailed("written", ex);
        }
    }

    private string Decrypt(SecretFile file, string name)
    {
        if (!file.Secrets.TryGetValue(name, out var entry))
        {
            throw new SecretStoreException(
                SecretStoreError.SecretNotFound,
                FilePath,
                name,
                $"The secret '{name}' isn't in '{FilePath}'. Run set-credentials as {_currentAccount().Account} to add it.");
        }

        byte[] plaintext;
        try
        {
            plaintext = _protector.Unprotect(entry.Ciphertext, GetContext(name));
        }
        catch (CryptographicException ex)
        {
            throw DecryptionFailed(file, name, ex);
        }

        try
        {
            return StrictUtf8.GetString(plaintext);
        }
        catch (DecoderFallbackException ex)
        {
            throw new SecretStoreException(
                SecretStoreError.CorruptFile,
                FilePath,
                name,
                $"The secret '{name}' in '{FilePath}' decrypted to data that isn't valid text. Run set-credentials again.",
                ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private SecretStoreException DecryptionFailed(SecretFile file, string name, CryptographicException inner)
    {
        var current = _currentAccount();
        var prefix = $"The secret '{name}' in '{FilePath}' can't be decrypted.";

        if (file.EncryptedBy is not { } owner)
        {
            return new SecretStoreException(
                SecretStoreError.DecryptionFailed,
                FilePath,
                name,
                $"{prefix} The file doesn't record which account encrypted it. It can only be decrypted by that account, on the machine " +
                $"where it was encrypted. You are running as {current.Account} on {current.Machine}. Re-run set-credentials as the account that will run the app.",
                inner);
        }

        if (!owner.IsSameAccountAs(current))
        {
            return new SecretStoreException(
                SecretStoreError.EncryptedByAnotherAccount,
                FilePath,
                name,
                $"{prefix} This file was encrypted by {owner.Account} on {owner.Machine}; you are running as {current.Account} on {current.Machine}. " +
                "Re-run set-credentials as the account that will run the app.",
                inner);
        }

        if (!owner.IsSameMachineAs(current))
        {
            return new SecretStoreException(
                SecretStoreError.EncryptedOnAnotherMachine,
                FilePath,
                name,
                $"{prefix} This file was encrypted on {owner.Machine}; you are running on {current.Machine}. Encrypted values only move " +
                $"between machines with a roaming profile. Re-run set-credentials on this machine as {current.Account}.",
                inner);
        }

        return new SecretStoreException(
            SecretStoreError.DecryptionFailed,
            FilePath,
            name,
            $"{prefix} It was encrypted by this account ({current.Account} on {current.Machine}), so the entry may have been copied from another " +
            "secret or app, the file may have been edited, or an administrator may have reset this account's password. Re-run set-credentials.",
            inner);
    }

    private SecretStoreException FileNotFound() => new(
        SecretStoreError.FileNotFound,
        FilePath,
        null,
        $"No secrets file was found at '{FilePath}'. Run set-credentials as {_currentAccount().Account} to create it.");

    private SecretStoreException ProtectorMismatch(SecretFile file) => new(
        SecretStoreError.ProtectorMismatch,
        FilePath,
        null,
        $"The secrets file '{FilePath}' was written with protector '{file.Protector}', but this app uses '{_protector.Id}'. " +
        "Point the app at the right file, or delete it and run set-credentials again.");

    private SecretStoreException FileAccessFailed(string verb, Exception inner) => new(
        SecretStoreError.FileAccessFailed,
        FilePath,
        null,
        $"The secrets file '{FilePath}' couldn't be {verb}: {inner.Message}",
        inner);

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Best effort. A leftover temp file contains only ciphertext.
        }
    }
}
