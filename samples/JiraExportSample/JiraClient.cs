using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace JiraExportSample;

/// <summary>Jira refused the personal access token.</summary>
internal sealed class JiraAuthorizationException(string message) : Exception(message);

internal sealed record JiraUser(string? Name, string? DisplayName);

/// <summary>
/// Calls Jira Server/Data Center. The PAT is set once as the client's default <c>Authorization: Bearer</c> header
/// (see <see cref="JiraServices"/>), so this class never sees it.
/// </summary>
internal sealed class JiraClient(HttpClient http, TimeProvider time, ILogger<JiraClient> logger)
{
    public const int PageSize = 50;

    public async Task<JiraUser> GetMyselfAsync(CancellationToken cancellationToken)
    {
        using var response = await http.GetAsync("rest/api/2/myself", cancellationToken).ConfigureAwait(false);
        ThrowIfUnauthorized(response);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<JiraUser>(cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidDataException("Jira's /myself response was empty.");
    }

    /// <summary>Runs a JQL search and returns every matching issue, one page at a time.</summary>
    public async Task<IReadOnlyList<JsonElement>> SearchAsync(string jql, TimeSpan delayBetweenPages, CancellationToken cancellationToken)
    {
        var issues = new List<JsonElement>();
        while (true)
        {
            var url = $"rest/api/2/search?jql={Uri.EscapeDataString(jql)}&startAt={issues.Count}&maxResults={PageSize}&fields=summary,status";
            using var response = await http.GetAsync(url, cancellationToken).ConfigureAwait(false);
            ThrowIfUnauthorized(response);
            response.EnsureSuccessStatusCode();
            var page = await response.Content.ReadFromJsonAsync<SearchPage>(cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidDataException("Jira's search response was empty.");

            issues.AddRange(page.Issues);
            logger.LogInformation("Fetched {Count} of {Total} issues.", issues.Count, page.Total);
            if (page.Issues.Count == 0 || issues.Count >= page.Total)
            {
                return issues;
            }

            if (delayBetweenPages > TimeSpan.Zero)
            {
                await Task.Delay(delayBetweenPages, time, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private static void ThrowIfUnauthorized(HttpResponseMessage response)
    {
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            throw new JiraAuthorizationException(
                "Jira rejected the personal access token (HTTP 401). It may have expired or been revoked: create a new one in Jira, then run set-credentials.");
        }
    }

    private sealed record SearchPage(int StartAt, int Total, List<JsonElement> Issues);
}
