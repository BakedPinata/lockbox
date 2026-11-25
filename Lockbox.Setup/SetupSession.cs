using System.Globalization;

namespace Lockbox.Setup;

/// <summary>The outcome of <see cref="SetupSession.Save"/>.</summary>
public abstract record SaveResult
{
    /// <summary>The credentials were encrypted and saved.</summary>
    public sealed record Saved(int Count) : SaveResult;

    /// <summary>Every field was left blank and every current value is usable, so nothing was written.</summary>
    public sealed record NothingChanged : SaveResult;

    /// <summary>These credentials need a value: they're missing or their current value doesn't decrypt.</summary>
    public sealed record ValuesRequired(IReadOnlyList<CredentialField> Fields) : SaveResult;

    /// <summary>The existing file must be replaced. Ask the user with <see cref="Question"/>, then save again with confirmation.</summary>
    public sealed record ReplaceConfirmationRequired(string Question) : SaveResult;

    /// <summary>Nothing was saved, for the reason given.</summary>
    public sealed record Failed(string Message) : SaveResult;
}

/// <summary>
/// The setup tool's logic for one app: the same rules as <c>set-credentials</c>. A blank field keeps the current value
/// if it decrypts. Another account's, another protector's or a corrupt file is only replaced once the user agrees,
/// and only when every value has been entered.
/// </summary>
public sealed class SetupSession
{
    private readonly SecretStore _store;
    private readonly TimeProvider _time;

    /// <summary>Creates a session that encrypts as the current Windows account.</summary>
    public SetupSession(AppDescription app)
        : this(app, new SecretStore(app.AppName, app.SecretsPath), TimeProvider.System)
    {
    }

    internal SetupSession(AppDescription app, SecretStore store, TimeProvider time)
    {
        App = app;
        _store = store;
        _time = time;
        Status = _store.Inspect(app.Credentials.Select(c => c.Name));
    }

    /// <summary>The app being set up.</summary>
    public AppDescription App { get; }

    /// <summary>The secrets file path.</summary>
    public string SecretsPath => _store.FilePath;

    /// <summary>The account the credentials will be encrypted for.</summary>
    public AccountInfo CurrentAccount => _store.CurrentAccount;

    /// <summary>The file's state as of the last <see cref="Refresh"/> or <see cref="Save"/>.</summary>
    public SecretStoreStatus Status { get; private set; }

    /// <summary>Whether a blank field for <paramref name="name"/> keeps the current value.</summary>
    public bool CanKeep(string name) =>
        !Status.RequiresReplace && Status.Secrets.Any(s => s.Name == name && s.State == SecretState.Usable);

    /// <summary>Reads the file's state again.</summary>
    public SecretStoreStatus Refresh() => Status = _store.Inspect(App.Credentials.Select(c => c.Name));

    /// <summary>A warning about the file, or <see langword="null"/> if it can simply be saved to.</summary>
    public string? FileWarning => Status.FileState switch
    {
        SecretFileState.Missing or SecretFileState.Usable => null,
        SecretFileState.OtherAccount =>
            $"These credentials were encrypted by {Status.Info!.EncryptedBy}. You're running as {CurrentAccount}, so they can't be decrypted " +
            "here. Saving will replace them with your own.",
        _ => Status.Error!.Message,
    };

    /// <summary>A short description of a credential's current state, for display. Never includes the value.</summary>
    public string DescribeCredential(string name)
    {
        var status = Status.Secrets.Single(s => s.Name == name);
        return status.State switch
        {
            SecretState.Usable => $"Set {Describe(status.CreatedUtc!.Value)}",
            SecretState.Unreadable => $"Set {Describe(status.CreatedUtc!.Value)}, but can't be decrypted by this account",
            SecretState.Missing => "Not set",
            _ => "Unknown",
        };
    }

    /// <summary>Validates and saves what the user entered.</summary>
    /// <param name="entered">Each credential's field text. Blank or missing keeps the current value where possible.</param>
    /// <param name="replaceConfirmed">Whether the user has agreed to replace a file that must be replaced.</param>
    public SaveResult Save(IReadOnlyDictionary<string, string?> entered, bool replaceConfirmed)
    {
        ArgumentNullException.ThrowIfNull(entered);
        Refresh();
        if (!Status.CanSave)
        {
            return new SaveResult.Failed(Status.Error!.Message);
        }

        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var required = new List<CredentialField>();
        foreach (var field in App.Credentials)
        {
            var text = entered.GetValueOrDefault(field.Name);
            var value = field.Masked ? text : text?.Trim();
            if (!string.IsNullOrWhiteSpace(value))
            {
                values[field.Name] = value!;
            }
            else if (!CanKeep(field.Name))
            {
                required.Add(field);
            }
        }

        if (required.Count > 0)
        {
            return new SaveResult.ValuesRequired(required);
        }

        if (Status.RequiresReplace && !replaceConfirmed)
        {
            var count = Status.Info?.Secrets.Count;
            return new SaveResult.ReplaceConfirmationRequired(Status.FileState == SecretFileState.Corrupt
                ? "The secrets file is damaged. Replace it with the credentials you entered?"
                : $"Replace all {count} credential(s) in this file with the ones you entered? The current ones will be lost.");
        }

        if (values.Count == 0)
        {
            return new SaveResult.NothingChanged();
        }

        try
        {
            if (Status.RequiresReplace)
            {
                _store.ReplaceSecrets(values);
            }
            else
            {
                _store.SetSecrets(values);
            }
        }
        catch (SecretStoreException ex)
        {
            return new SaveResult.Failed(ex.Message);
        }
        finally
        {
            Refresh();
        }

        return new SaveResult.Saved(values.Count);
    }

    private string Describe(DateTime createdUtc)
    {
        var age = _time.GetUtcNow().UtcDateTime - createdUtc;
        var ago = age.TotalMinutes < 1 ? "just now"
            : age.TotalHours < 1 ? Plural((int)age.TotalMinutes, "minute") + " ago"
            : age.TotalDays < 1 ? Plural((int)age.TotalHours, "hour") + " ago"
            : Plural((int)age.TotalDays, "day") + " ago";
        return $"{createdUtc.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)} UTC ({ago})";
    }

    private static string Plural(int count, string unit) => count == 1 ? $"1 {unit}" : $"{count} {unit}s";
}
