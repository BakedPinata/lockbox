using ApiExportSample.Auth;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SampleSupport;

namespace ApiExportSample;

internal static class ApiServices
{
    /// <summary>
    /// Wires up IHttpClientFactory:
    /// <list type="bullet">
    /// <item>the <c>api-login</c> client posts the username and password (no auth handler);</item>
    /// <item>the <see cref="RecordExporter"/> client gets the JWT from <see cref="BearerTokenHandler"/>;</item>
    /// <item>both redact every logged header value, so <c>--verbose</c> never shows the token.</item>
    /// </list>
    /// </summary>
    public static ServiceProvider Build(
        Uri baseUrl,
        ApiCredentials credentials,
        bool verbose,
        Action<ILoggingBuilder>? configureLogging = null,
        TimeProvider? time = null)
    {
        var services = new ServiceCollection();
        services.AddLogging(logging =>
        {
            SampleLogging.Configure(logging, verbose);
            configureLogging?.Invoke(logging);
        });

        services.AddSingleton(time ?? TimeProvider.System);
        services.AddSingleton(credentials);
        services.AddSingleton<LoginClient>();
        services.AddSingleton(sp => new TokenProvider(
            sp.GetRequiredService<LoginClient>().LoginAsync,
            sp.GetRequiredService<TimeProvider>(),
            sp.GetRequiredService<ILogger<TokenProvider>>()));
        services.AddTransient<BearerTokenHandler>();

        services.AddHttpClient(LoginClient.HttpClientName, c => c.BaseAddress = baseUrl)
            .RedactLoggedHeaders(SampleLogging.RedactAllHeaders);

        services.AddHttpClient<RecordExporter>(c => c.BaseAddress = baseUrl)
            .AddHttpMessageHandler<BearerTokenHandler>()
            .RedactLoggedHeaders(SampleLogging.RedactAllHeaders);

        return services.BuildServiceProvider();
    }
}
