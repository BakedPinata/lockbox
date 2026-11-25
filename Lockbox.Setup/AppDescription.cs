using System.Text.Json;

namespace Lockbox.Setup;

/// <summary>A credential the app needs, as reported by its <c>describe-credentials</c> command.</summary>
public sealed record CredentialField(string Name, string Prompt, bool Masked);

/// <summary>What an app reports about its credentials through <c>describe-credentials</c>.</summary>
/// <param name="AppName">The app name its secrets are bound to.</param>
/// <param name="SecretsPath">The secrets file the app will read.</param>
/// <param name="ServiceName">What the app's credential check talks to.</param>
/// <param name="HasServiceCheck">Whether <c>verify-credentials</c> also checks the credentials with the service.</param>
/// <param name="Credentials">The credentials, in prompt order.</param>
public sealed record AppDescription(
    string AppName,
    string SecretsPath,
    string ServiceName,
    bool HasServiceCheck,
    IReadOnlyList<CredentialField> Credentials)
{
    /// <summary>The format this version understands (matches <c>CredentialCommands.DescribeFormat</c>).</summary>
    public const string Format = "lockbox-credentials/1";

    /// <summary>Parses <c>describe-credentials</c> output.</summary>
    /// <exception cref="FormatException">The output isn't a description this version understands.</exception>
    public static AppDescription Parse(string output)
    {
        ArgumentNullException.ThrowIfNull(output);

        // The JSON is the last non-empty line; anything before it (such as a banner) is ignored.
        var json = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).LastOrDefault();
        if (json is null || !json.StartsWith('{'))
        {
            throw new FormatException("The app didn't print a credential description.");
        }

        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            var format = String(root, "format");
            if (format != Format)
            {
                throw new FormatException($"The app describes its credentials in format '{format}', but this tool only understands '{Format}'. Update the tool.");
            }

            var appName = String(root, "appName");
            var secretsPath = String(root, "secretsPath");
            _ = SecretStore.GetDefaultPath(appName); // Validates the app name.
            if (!Path.IsPathFullyQualified(secretsPath))
            {
                throw new FormatException("The app reported a secrets path that isn't a full path.");
            }

            var credentials = root.GetProperty("credentials").EnumerateArray()
                .Select(c => new CredentialField(String(c, "name"), String(c, "prompt"), c.GetProperty("masked").GetBoolean()))
                .ToList();
            if (credentials.Count == 0 || credentials.Any(c => !SecretStore.IsValidSecretName(c.Name)) ||
                credentials.Select(c => c.Name).Distinct(StringComparer.Ordinal).Count() != credentials.Count)
            {
                throw new FormatException("The app reported no credentials, or invalid or duplicate names.");
            }

            return new AppDescription(
                appName,
                secretsPath,
                root.TryGetProperty("serviceName", out var service) && service.ValueKind == JsonValueKind.String ? service.GetString()! : "the service",
                root.TryGetProperty("hasServiceCheck", out var check) && check.ValueKind == JsonValueKind.True,
                credentials);
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or ArgumentException)
        {
            throw new FormatException($"The app's credential description couldn't be read: {ex.Message}", ex);
        }
    }

    private static string String(JsonElement element, string property) =>
        element.GetProperty(property).GetString() is { Length: > 0 } value
            ? value
            : throw new FormatException($"The credential description has no \"{property}\".");
}
