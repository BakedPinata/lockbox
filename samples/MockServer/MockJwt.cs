using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace MockServer;

/// <summary>Minimal HS256 JWTs. Good enough for a mock; a real API should use a maintained JWT library.</summary>
internal sealed class MockJwt(TimeProvider time)
{
    private readonly Lock _sync = new();
    private byte[] _key = RandomNumberGenerator.GetBytes(32);

    public string Issue(string subject, TimeSpan lifetime)
    {
        var now = time.GetUtcNow();
        var header = Base64Url.EncodeToString("""{"alg":"HS256","typ":"JWT"}"""u8);
        var payload = Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object>
        {
            ["sub"] = subject,
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = (now + lifetime).ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"),
        }));
        var signingInput = $"{header}.{payload}";
        return $"{signingInput}.{Base64Url.EncodeToString(Sign(signingInput))}";
    }

    /// <summary>Checks the signature against the current key and that the token hasn't expired.</summary>
    public TokenStatus Validate(string token)
    {
        var parts = token.Split('.');
        if (parts.Length != 3)
        {
            return TokenStatus.Invalid;
        }

        byte[] signature;
        long exp;
        try
        {
            signature = Base64Url.DecodeFromChars(parts[2]);
            using var payload = JsonDocument.Parse(Base64Url.DecodeFromChars(parts[1]));
            exp = payload.RootElement.GetProperty("exp").GetInt64();
        }
        catch (Exception ex) when (ex is FormatException or JsonException or KeyNotFoundException or InvalidOperationException)
        {
            return TokenStatus.Invalid;
        }

        if (!CryptographicOperations.FixedTimeEquals(signature, Sign($"{parts[0]}.{parts[1]}")))
        {
            return TokenStatus.Invalid;
        }

        return time.GetUtcNow().ToUnixTimeSeconds() >= exp ? TokenStatus.Expired : TokenStatus.Valid;
    }

    /// <summary>Invalidates every token issued so far.</summary>
    public void RotateKey()
    {
        lock (_sync)
        {
            _key = RandomNumberGenerator.GetBytes(32);
        }
    }

    private byte[] Sign(string signingInput)
    {
        lock (_sync)
        {
            return HMACSHA256.HashData(_key, Encoding.ASCII.GetBytes(signingInput));
        }
    }
}

internal enum TokenStatus
{
    Valid,
    Expired,
    Invalid,
}
