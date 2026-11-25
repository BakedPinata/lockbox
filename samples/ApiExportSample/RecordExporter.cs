using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace ApiExportSample;

/// <summary>The API still refused the request after signing in again.</summary>
internal sealed class ApiAuthorizationException(string message) : Exception(message);

/// <summary>Pages through the API's records. Its HttpClient has <see cref="Auth.BearerTokenHandler"/>, so this class never sees a token.</summary>
internal sealed class RecordExporter(HttpClient http, TimeProvider time, ILogger<RecordExporter> logger)
{
    public const int PageSize = 10;

    public async Task<IReadOnlyList<JsonElement>> ExportAsync(TimeSpan delayBetweenPages, CancellationToken cancellationToken)
    {
        var records = new List<JsonElement>();
        for (var page = 1; ; page++)
        {
            using var response = await http.GetAsync($"api/records?page={page}&pageSize={PageSize}", cancellationToken).ConfigureAwait(false);
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                throw new ApiAuthorizationException(
                    "The API still refused the request after signing in again (HTTP 401). Check the account's access, then run verify-credentials.");
            }

            response.EnsureSuccessStatusCode();
            var body = await response.Content.ReadFromJsonAsync<RecordsPage>(cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidDataException($"Page {page} of the API response was empty.");

            records.AddRange(body.Records);
            logger.LogInformation("Page {Page}: {Count} records ({Total} so far).", page, body.Records.Count, records.Count);
            if (!body.HasMore)
            {
                return records;
            }

            if (delayBetweenPages > TimeSpan.Zero)
            {
                await Task.Delay(delayBetweenPages, time, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private sealed record RecordsPage(int Page, List<JsonElement> Records, bool HasMore);
}
