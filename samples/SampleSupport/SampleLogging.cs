using Microsoft.Extensions.Logging;

namespace SampleSupport;

public static class SampleLogging
{
    /// <summary>The category prefix IHttpClientFactory logs under.</summary>
    public const string HttpClientCategory = "System.Net.Http.HttpClient";

    /// <summary>
    /// Console logging for the samples. With <paramref name="verbose"/>, IHttpClientFactory's request and
    /// header logs are shown. Their header values are redacted by <c>RedactLoggedHeaders</c> when each client is
    /// registered, so the <c>Authorization</c> header appears as <c>*</c>.
    /// </summary>
    public static void Configure(ILoggingBuilder logging, bool verbose)
    {
        ArgumentNullException.ThrowIfNull(logging);
        logging.AddSimpleConsole(o =>
        {
            o.SingleLine = true;
            o.TimestampFormat = "HH:mm:ss ";
        });
        logging.SetMinimumLevel(LogLevel.Information);
        logging.AddFilter(HttpClientCategory, verbose ? LogLevel.Trace : LogLevel.Warning);
    }

    /// <summary>Redacts every logged header value. Pass to <c>IHttpClientBuilder.RedactLoggedHeaders</c>.</summary>
    public static bool RedactAllHeaders(string headerName) => true;
}
