namespace SampleSupport;

public static class ServiceUrl
{
    /// <summary>
    /// Parses a base URL that credentials will be sent to. It must be HTTPS, except for loopback addresses
    /// (such as the local mock server), so credentials never cross the network in plain text.
    /// </summary>
    /// <returns>The URL, ending in <c>/</c> so relative request paths resolve under it.</returns>
    /// <exception cref="ArgumentException">The URL is missing, not absolute, or plain HTTP to another machine.</exception>
    public static Uri Parse(string? url)
    {
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            throw new ArgumentException($"'{url}' isn't an absolute URL. Set BaseUrl in the settings file.", nameof(url));
        }

        if (uri.Scheme != Uri.UriSchemeHttps && !(uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback))
        {
            throw new ArgumentException(
                $"Refusing to send credentials to '{uri}': use https:// (plain http:// is only allowed for localhost).", nameof(url));
        }

        return uri.AbsoluteUri.EndsWith('/') ? uri : new Uri(uri.AbsoluteUri + "/");
    }
}
