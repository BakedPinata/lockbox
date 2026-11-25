using System.Buffers.Text;
using System.Text.Json;

namespace ApiExportSample.Auth;

/// <summary>A JWT from the API's login endpoint, with when it expires. Kept in memory only, never written to disk.</summary>
internal sealed class AccessToken
{
    private static readonly TimeSpan MaxRenewalMargin = TimeSpan.FromSeconds(60);

    public AccessToken(string value, DateTimeOffset obtainedAt, DateTimeOffset? expiresAt)
    {
        ArgumentException.ThrowIfNullOrEmpty(value);
        Value = value;
        ObtainedAt = obtainedAt;
        ExpiresAt = expiresAt;
    }

    public string Value { get; }

    public DateTimeOffset ObtainedAt { get; }

    /// <summary>When the token expires, or <see langword="null"/> if unknown (then only a 401 triggers a new login).</summary>
    public DateTimeOffset? ExpiresAt { get; }

    /// <summary>
    /// How long before expiry to log in again: a fifth of the token's lifetime, at most 60 seconds.
    /// Renewing early avoids sending a token that expires in flight.
    /// </summary>
    public TimeSpan RenewalMargin => ExpiresAt is { } expires
        ? TimeSpan.FromTicks(Math.Min(MaxRenewalMargin.Ticks, Math.Max(0, (expires - ObtainedAt).Ticks / 5)))
        : TimeSpan.Zero;

    /// <summary>Creates a token, taking the expiry from the JWT's <c>exp</c> claim, or else from <paramref name="expiresInSeconds"/>.</summary>
    public static AccessToken Create(string value, DateTimeOffset now, int? expiresInSeconds)
    {
        var expires = ReadJwtExpiry(value)
            ?? (expiresInSeconds is > 0 ? now.AddSeconds(expiresInSeconds.Value) : null);
        return new AccessToken(value, now, expires);
    }

    /// <summary>
    /// Reads the <c>exp</c> claim without validating the signature. The client only uses it to schedule
    /// renewal; the server is still the one that decides whether a token is valid.
    /// </summary>
    public static DateTimeOffset? ReadJwtExpiry(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length != 3)
        {
            return null;
        }

        try
        {
            using var payload = JsonDocument.Parse(Base64Url.DecodeFromChars(parts[1]));
            return payload.RootElement.ValueKind == JsonValueKind.Object
                && payload.RootElement.TryGetProperty("exp", out var exp)
                && exp.ValueKind == JsonValueKind.Number
                && exp.TryGetInt64(out var seconds)
                ? DateTimeOffset.FromUnixTimeSeconds(seconds)
                : null;
        }
        catch (Exception ex) when (ex is FormatException or JsonException or ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    public bool NeedsRenewal(DateTimeOffset now) => ExpiresAt is { } expires && now >= expires - RenewalMargin;

    public override string ToString() => $"AccessToken {{ ExpiresAt = {ExpiresAt?.ToString("u") ?? "unknown"} }}";
}
