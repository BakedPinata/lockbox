using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.Logging;

namespace ApiExportSample.Auth;

/// <summary>The username or password was rejected.</summary>
internal sealed class LoginFailedException(string message) : Exception(message);

/// <summary>Exchanges the username and password for a JWT.</summary>
/// <remarks>
/// Uses its own named HttpClient without <see cref="BearerTokenHandler"/>, so logging in never recurses.
/// Adapt the request and response shapes to the real API.
/// </remarks>
internal sealed class LoginClient(IHttpClientFactory httpClientFactory, ApiCredentials credentials, TimeProvider time, ILogger<LoginClient> logger)
{
    public const string HttpClientName = "api-login";

    public async Task<AccessToken> LoginAsync(CancellationToken cancellationToken)
    {
        var http = httpClientFactory.CreateClient(HttpClientName);
        using var response = await http.PostAsJsonAsync(
            "auth/login",
            new LoginRequest(credentials.Username, credentials.Password),
            cancellationToken).ConfigureAwait(false);

        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden or HttpStatusCode.BadRequest)
        {
            throw new LoginFailedException(
                $"The API rejected the username or password (HTTP {(int)response.StatusCode}). If the password changed, run set-credentials again.");
        }

        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"Login failed: HTTP {(int)response.StatusCode} {response.ReasonPhrase}.", null, response.StatusCode);
        }

        var body = await response.Content.ReadFromJsonAsync<LoginResponse>(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrEmpty(body?.Token))
        {
            throw new InvalidDataException("The login response didn't contain a token.");
        }

        var token = AccessToken.Create(body.Token, time.GetUtcNow(), body.ExpiresIn);
        logger.LogInformation(
            "Signed in as {Username}. The token expires {Expiry}.",
            credentials.Username,
            token.ExpiresAt is { } expires ? $"at {expires:HH:mm:ss} UTC" : "at an unknown time");
        return token;
    }

    private sealed record LoginRequest(string Username, string Password);

    private sealed record LoginResponse(string? Token, int? ExpiresIn);
}
