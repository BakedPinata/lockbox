using Microsoft.Extensions.Logging;

namespace ApiExportSample.Auth;

/// <summary>
/// Holds the current JWT in memory and logs in again when it's about to expire or the API rejects it.
/// Concurrent callers share one login.
/// </summary>
internal sealed class TokenProvider(Func<CancellationToken, Task<AccessToken>> login, TimeProvider time, ILogger<TokenProvider> logger) : IDisposable
{
    private readonly SemaphoreSlim _loginGate = new(1, 1);
    private readonly Lock _sync = new();
    private AccessToken? _current;

    public async Task<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        if (TryGetUsable() is { } usable)
        {
            return usable;
        }

        await _loginGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Another caller may have logged in while this one waited.
            if (TryGetUsable() is { } refreshed)
            {
                return refreshed;
            }

            AccessToken? previous;
            lock (_sync)
            {
                previous = _current;
            }

            if (previous is not null)
            {
                logger.LogInformation("The token expires at {Expiry:HH:mm:ss} UTC. Signing in again.", previous.ExpiresAt);
            }

            var token = await login(cancellationToken).ConfigureAwait(false);
            lock (_sync)
            {
                _current = token;
            }

            return token.Value;
        }
        finally
        {
            _loginGate.Release();
        }
    }

    /// <summary>
    /// Forgets <paramref name="rejectedToken"/> after the API refused it, so the next call logs in again.
    /// A newer token obtained meanwhile by another request is kept.
    /// </summary>
    public void Invalidate(string rejectedToken)
    {
        lock (_sync)
        {
            if (_current?.Value == rejectedToken)
            {
                _current = null;
            }
        }
    }

    public void Dispose() => _loginGate.Dispose();

    private string? TryGetUsable()
    {
        lock (_sync)
        {
            return _current is { } token && !token.NeedsRenewal(time.GetUtcNow()) ? token.Value : null;
        }
    }
}
