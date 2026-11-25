using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;

namespace ApiExportSample.Auth;

/// <summary>
/// Adds <c>Authorization: Bearer &lt;jwt&gt;</c> to every request. On a 401 it logs in again once and retries once;
/// a second 401 is returned to the caller.
/// </summary>
internal sealed class BearerTokenHandler(TokenProvider tokens, ILogger<BearerTokenHandler> logger) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // Buffer any body so the request can be sent a second time.
        if (request.Content is not null)
        {
            await request.Content.LoadIntoBufferAsync(cancellationToken).ConfigureAwait(false);
        }

        var token = await tokens.GetTokenAsync(cancellationToken).ConfigureAwait(false);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.Unauthorized)
        {
            return response;
        }

        logger.LogWarning("The API rejected the token for {Method} {Path} (HTTP 401). Signing in again and retrying once.", request.Method, request.RequestUri?.AbsolutePath);
        response.Dispose();
        tokens.Invalidate(token);

        token = await tokens.GetTokenAsync(cancellationToken).ConfigureAwait(false);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }
}
