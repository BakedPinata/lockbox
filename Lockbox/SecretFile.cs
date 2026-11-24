using System.Text.Json;
using System.Text.Json.Serialization;

namespace Lockbox;

/// <summary>A validated, in-memory copy of a secrets file.</summary>
internal sealed class SecretFile
{
    public const int CurrentVersion = 1;

    private static readonly byte[] Utf8Bom = [0xEF, 0xBB, 0xBF];

    public SecretFile(string protector) => Protector = protector;

    public string Protector { get; set; }

    public AccountInfo? EncryptedBy { get; set; }

    // Sorted so the file's contents are stable from one save to the next.
    public SortedDictionary<string, SecretEntry> Secrets { get; } = new(StringComparer.Ordinal);

    public static SecretFile Parse(ReadOnlySpan<byte> json, string filePath)
    {
        if (json.StartsWith(Utf8Bom))
        {
            json = json[Utf8Bom.Length..];
        }

        // Read the version on its own first, so a newer format is reported as "newer"
        // instead of failing to deserialize and being reported as corrupt.
        VersionModel? versionModel;
        try
        {
            versionModel = JsonSerializer.Deserialize(json, SecretFileJsonContext.Default.VersionModel);
        }
        catch (JsonException ex)
        {
            throw Corrupt(filePath, $"it isn't valid JSON at {ex.Path ?? "$"}", ex);
        }

        if (versionModel?.Version is not int version || version < 1)
        {
            throw Corrupt(filePath, "it has no valid \"version\"");
        }

        if (version > CurrentVersion)
        {
            throw new SecretStoreException(
                SecretStoreError.UnsupportedVersion,
                filePath,
                null,
                $"The secrets file '{filePath}' has format version {version}, but this version of Lockbox only reads version {CurrentVersion}. " +
                "Update the app, or delete the file and run set-credentials again.");
        }

        SecretFileModel model;
        try
        {
            model = JsonSerializer.Deserialize(json, SecretFileJsonContext.Default.SecretFileModel)!;
        }
        catch (JsonException ex)
        {
            throw Corrupt(filePath, $"unexpected content at {ex.Path ?? "$"}", ex);
        }

        if (string.IsNullOrWhiteSpace(model.Protector))
        {
            throw Corrupt(filePath, "it has no \"protector\"");
        }

        if (model.Secrets is null)
        {
            throw Corrupt(filePath, "it has no \"secrets\"");
        }

        var file = new SecretFile(model.Protector) { EncryptedBy = ToAccountInfo(model.EncryptedBy) };
        foreach (var (name, entry) in model.Secrets)
        {
            if (!SecretStore.IsValidSecretName(name))
            {
                throw Corrupt(filePath, $"it has an invalid secret name '{name}'");
            }

            if (entry?.CreatedUtc is not DateTime created || entry.Ciphertext is not { Length: > 0 } ciphertext)
            {
                throw Corrupt(filePath, $"the entry for '{name}' needs \"createdUtc\" and \"ciphertext\"");
            }

            file.Secrets[name] = new SecretEntry(ToUtc(created), ciphertext);
        }

        return file;
    }

    public void WriteTo(Stream stream)
    {
        var model = new SecretFileModel
        {
            Version = CurrentVersion,
            Protector = Protector,
            EncryptedBy = EncryptedBy is null
                ? null
                : new AccountModel { Account = EncryptedBy.Account, Sid = EncryptedBy.Sid, Machine = EncryptedBy.Machine },
            Secrets = Secrets.ToDictionary(
                kv => kv.Key,
                kv => (SecretEntryModel?)new SecretEntryModel { CreatedUtc = kv.Value.CreatedUtc, Ciphertext = kv.Value.Ciphertext },
                StringComparer.Ordinal),
        };
        JsonSerializer.Serialize(stream, model, SecretFileJsonContext.Default.SecretFileModel);
    }

    private static AccountInfo? ToAccountInfo(AccountModel? model)
    {
        // encryptedBy is diagnostic only, so be lenient: unusable metadata is treated as absent.
        if (model is null || (string.IsNullOrWhiteSpace(model.Account) && string.IsNullOrWhiteSpace(model.Sid)))
        {
            return null;
        }

        return new AccountInfo(
            string.IsNullOrWhiteSpace(model.Account) ? "(unknown account)" : model.Account,
            string.IsNullOrWhiteSpace(model.Sid) ? null : model.Sid,
            string.IsNullOrWhiteSpace(model.Machine) ? "(unknown machine)" : model.Machine);
    }

    private static DateTime ToUtc(DateTime value) => value.Kind switch
    {
        DateTimeKind.Utc => value,
        DateTimeKind.Local => value.ToUniversalTime(),
        _ => DateTime.SpecifyKind(value, DateTimeKind.Utc),
    };

    private static SecretStoreException Corrupt(string filePath, string detail, Exception? inner = null) => new(
        SecretStoreError.CorruptFile,
        filePath,
        null,
        $"The secrets file '{filePath}' is damaged or isn't a Lockbox secrets file: {detail}. Delete it and run set-credentials again.",
        inner);
}

internal sealed record SecretEntry(DateTime CreatedUtc, byte[] Ciphertext);

// JSON shapes. Everything is nullable so that validation in SecretFile.Parse can give precise messages.

internal sealed class VersionModel
{
    public int? Version { get; set; }
}

internal sealed class SecretFileModel
{
    public int? Version { get; set; }

    public string? Protector { get; set; }

    public AccountModel? EncryptedBy { get; set; }

    public Dictionary<string, SecretEntryModel?>? Secrets { get; set; }
}

internal sealed class AccountModel
{
    public string? Account { get; set; }

    public string? Sid { get; set; }

    public string? Machine { get; set; }
}

internal sealed class SecretEntryModel
{
    public DateTime? CreatedUtc { get; set; }

    public byte[]? Ciphertext { get; set; }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    ReadCommentHandling = JsonCommentHandling.Skip,
    AllowTrailingCommas = true)]
[JsonSerializable(typeof(VersionModel))]
[JsonSerializable(typeof(SecretFileModel))]
internal sealed partial class SecretFileJsonContext : JsonSerializerContext;
