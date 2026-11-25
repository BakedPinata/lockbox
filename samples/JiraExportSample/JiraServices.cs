using System.Net.Http.Headers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SampleSupport;

namespace JiraExportSample;

internal static class JiraServices
{
    /// <summary>
    /// Registers <see cref="JiraClient"/> with the PAT as a default <c>Authorization: Bearer</c> header. A PAT doesn't
    /// expire during a run, so no handler is needed. Every logged header value is redacted.
    /// </summary>
    public static ServiceProvider Build(Uri baseUrl, string personalAccessToken, bool verbose, Action<ILoggingBuilder>? configureLogging = null)
    {
        var services = new ServiceCollection();
        services.AddLogging(logging =>
        {
            SampleLogging.Configure(logging, verbose);
            configureLogging?.Invoke(logging);
        });
        services.AddSingleton(TimeProvider.System);

        services.AddHttpClient<JiraClient>(client =>
            {
                client.BaseAddress = baseUrl;
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", personalAccessToken);
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            })
            .RedactLoggedHeaders(SampleLogging.RedactAllHeaders);

        return services.BuildServiceProvider();
    }
}
