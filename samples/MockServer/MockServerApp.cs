using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http.HttpResults;

namespace MockServer;

/// <summary>Counters the tests (and the console log) use to show what happened.</summary>
internal sealed class MockStats
{
    private int _logins;
    private int _failedLogins;
    private int _apiRequests;
    private int _rejectedTokens;
    private int _jiraRequests;
    private int _rejectedPats;

    public int Logins => _logins;

    public int FailedLogins => _failedLogins;

    public int ApiRequests => _apiRequests;

    public int RejectedTokens => _rejectedTokens;

    public int JiraRequests => _jiraRequests;

    public int RejectedPats => _rejectedPats;

    public void Login(bool ok) => Interlocked.Increment(ref ok ? ref _logins : ref _failedLogins);

    public int ApiRequest() => Interlocked.Increment(ref _apiRequests);

    public void RejectedToken() => Interlocked.Increment(ref _rejectedTokens);

    public void JiraRequest(bool ok) => Interlocked.Increment(ref ok ? ref _jiraRequests : ref _rejectedPats);
}

internal sealed record LoginRequest(string? Username, string? Password);

/// <summary>A built (not yet started) mock server and the state tests inspect.</summary>
internal sealed record MockHost(WebApplication App, MockStats Stats, MockJwt Jwt);

internal static class MockServerApp
{
    public static MockHost Build(MockOptions options, TimeProvider? time = null)
    {
        time ??= TimeProvider.System;
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls(options.Url);
        builder.Logging.ClearProviders();
        builder.Logging.AddSimpleConsole(o => o.SingleLine = true);
        builder.Logging.AddFilter("Microsoft", LogLevel.Warning);

        var app = builder.Build();
        var jwt = new MockJwt(time);
        var stats = new MockStats();
        var log = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Mock");

        app.MapGet("/health", () => "ok");

        // ---- API with username/password login and short-lived JWTs ----

        app.MapPost("/auth/login", Results<Ok<object>, UnauthorizedHttpResult> (LoginRequest request) =>
        {
            var ok = FixedTimeEquals(request.Username, options.ApiUsername) & FixedTimeEquals(request.Password, options.ApiPassword);
            stats.Login(ok);
            if (!ok)
            {
                log.LogWarning("Login rejected: wrong username or password.");
                return TypedResults.Unauthorized();
            }

            log.LogInformation("Login OK. Issued a token valid for {Seconds} s.", options.TokenLifetime.TotalSeconds);
            return TypedResults.Ok<object>(new
            {
                token = jwt.Issue(options.ApiUsername, options.TokenLifetime),
                expiresIn = (int)options.TokenLifetime.TotalSeconds,
            });
        });

        app.MapGet("/api/records", IResult (HttpContext context, int page = 1, int pageSize = 10) =>
        {
            var status = BearerToken(context) is { } token ? jwt.Validate(token) : TokenStatus.Invalid;
            if (status != TokenStatus.Valid)
            {
                stats.RejectedToken();
                log.LogWarning("API request rejected: token {Status}.", status.ToString().ToLowerInvariant());
                context.Response.Headers.WWWAuthenticate = $"Bearer error=\"invalid_token\", error_description=\"{status.ToString().ToLowerInvariant()}\"";
                return TypedResults.Unauthorized();
            }

            var count = stats.ApiRequest();
            if (options.InvalidateEvery > 0 && count % options.InvalidateEvery == 0)
            {
                jwt.RotateKey();
                log.LogInformation("Rotated the signing key after {Count} requests. Existing tokens are now invalid.", count);
            }

            pageSize = Math.Clamp(pageSize, 1, 100);
            var first = (Math.Max(page, 1) - 1) * pageSize;
            var records = Enumerable.Range(first + 1, Math.Max(0, Math.Min(pageSize, options.RecordCount - first)))
                .Select(i => new { id = i, name = $"Record {i}", value = i * 1.5m })
                .ToList();
            return TypedResults.Ok(new { page, records, hasMore = first + pageSize < options.RecordCount });
        });

        // ---- Jira Server/Data Center style API with a Bearer PAT ----

        app.MapGet("/rest/api/2/myself", IResult (HttpContext context) =>
        {
            if (!JiraAuthorized(context))
            {
                return TypedResults.Unauthorized();
            }

            return TypedResults.Ok(new { name = "demo", displayName = "Demo User", emailAddress = "demo@example.com" });
        });

        app.MapGet("/rest/api/2/search", IResult (HttpContext context, string? jql, int startAt = 0, int maxResults = 50) =>
        {
            if (!JiraAuthorized(context))
            {
                return TypedResults.Unauthorized();
            }

            maxResults = Math.Clamp(maxResults, 1, 100);
            startAt = Math.Max(0, startAt);
            var issues = Enumerable.Range(startAt + 1, Math.Max(0, Math.Min(maxResults, options.IssueCount - startAt)))
                .Select(i => new
                {
                    key = $"DEMO-{i}",
                    fields = new { summary = $"Demo issue {i}", status = new { name = (i % 3) switch { 0 => "Done", 1 => "Open", _ => "In Progress" } } },
                })
                .ToList();
            return TypedResults.Ok(new { startAt, maxResults, total = options.IssueCount, issues });
        });

        return new MockHost(app, stats, jwt);

        bool JiraAuthorized(HttpContext context)
        {
            var ok = FixedTimeEquals(BearerToken(context), options.JiraPat);
            stats.JiraRequest(ok);
            if (!ok)
            {
                log.LogWarning("Jira request rejected: missing or wrong PAT.");
            }

            return ok;
        }
    }

    private static string? BearerToken(HttpContext context)
    {
        var header = context.Request.Headers.Authorization.ToString();
        return header.StartsWith("Bearer ", StringComparison.Ordinal) ? header["Bearer ".Length..].Trim() : null;
    }

    private static bool FixedTimeEquals(string? actual, string expected) =>
        actual is not null && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(actual), Encoding.UTF8.GetBytes(expected));
}
