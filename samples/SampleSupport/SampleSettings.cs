using System.Text.Json;

namespace SampleSupport;

/// <summary>
/// Non-secret settings, read from a JSON file next to the executable. Secrets never go here: they live in
/// the Lockbox secrets file.
/// </summary>
/// <param name="BaseUrl">The service's base URL.</param>
/// <param name="SecretsPath">Overrides the default secrets file path. Environment variables are expanded.</param>
public sealed record SampleSettings(string? BaseUrl, string? SecretsPath)
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    /// <summary>Loads <paramref name="fileName"/> from the executable's folder. A missing file gives empty settings.</summary>
    /// <exception cref="InvalidDataException">The file isn't valid JSON.</exception>
    public static SampleSettings Load(string fileName)
    {
        var path = Path.Combine(AppContext.BaseDirectory, fileName);
        if (!File.Exists(path))
        {
            return new SampleSettings(null, null);
        }

        try
        {
            return JsonSerializer.Deserialize<SampleSettings>(File.ReadAllText(path), Options) ?? new SampleSettings(null, null);
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"The settings file '{path}' isn't valid JSON: {ex.Message}", ex);
        }
    }
}
