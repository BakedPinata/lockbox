using ApiExportSample;
using ApiExportSample.Auth;
using JiraExportSample;
using Microsoft.Extensions.DependencyInjection;

namespace Samples.Tests;

/// <summary>The samples' HTTP code against the real mock server, over loopback.</summary>
[TestClass]
public sealed class ApiExportEndToEndTests
{
    private static readonly ApiCredentials Demo = new("demo", "demo-password");

    [TestMethod]
    public async Task ExportsEveryRecord()
    {
        await using var mock = await RunningMock.StartAsync();
        await using var services = ApiServices.Build(mock.BaseUrl, Demo, verbose: false, CapturingLoggerProvider.Replace(new()));

        var records = await services.GetRequiredService<RecordExporter>().ExportAsync(TimeSpan.Zero, default);

        Assert.HasCount(95, records);
        Assert.AreEqual(1, records[0].GetProperty("id").GetInt32());
        Assert.AreEqual(95, records[^1].GetProperty("id").GetInt32());
        Assert.AreEqual(1, mock.Stats.Logins);
    }

    [TestMethod]
    public async Task RenewsTheTokenBeforeItExpires()
    {
        // Mock and client share a clock that jumps forward whenever the exporter pauses between pages.
        // 10 pages, 9 pauses of 5 s = 45 s; tokens last 20 s and are renewed 4 s early (at 16 s).
        var time = new JumpingTimeProvider(DateTimeOffset.UtcNow);
        await using var mock = await RunningMock.StartAsync(o => o.TokenLifetime = TimeSpan.FromSeconds(20), time);
        var logs = new CapturingLoggerProvider();
        await using var services = ApiServices.Build(mock.BaseUrl, Demo, verbose: false, CapturingLoggerProvider.Replace(logs), time);

        var records = await services.GetRequiredService<RecordExporter>().ExportAsync(TimeSpan.FromSeconds(5), default);

        Assert.HasCount(95, records);
        Assert.AreEqual(3, mock.Stats.Logins, logs.AllText); // at 0 s, 20 s and 40 s
        Assert.AreEqual(0, mock.Stats.RejectedTokens, "Renewal should happen before the server sees an expired token.");
        Assert.HasCount(2, logs.Messages.Where(m => m.Contains("Signing in again", StringComparison.Ordinal)).ToList());
    }

    [TestMethod]
    public async Task On401SignsInAgainAndRetries()
    {
        // The mock rotates its signing key after every 3rd request, so the 4th, 7th and 10th requests get a 401.
        await using var mock = await RunningMock.StartAsync(o => o.InvalidateEvery = 3);
        var logs = new CapturingLoggerProvider();
        await using var services = ApiServices.Build(mock.BaseUrl, Demo, verbose: false, CapturingLoggerProvider.Replace(logs));

        var records = await services.GetRequiredService<RecordExporter>().ExportAsync(TimeSpan.Zero, default);

        Assert.HasCount(95, records);
        Assert.AreEqual(3, mock.Stats.RejectedTokens);
        Assert.AreEqual(4, mock.Stats.Logins);
        Assert.AreEqual(10, mock.Stats.ApiRequests);
        Assert.HasCount(3, logs.Messages.Where(m => m.Contains("retrying once", StringComparison.Ordinal)).ToList());
    }

    [TestMethod]
    public async Task WrongPasswordFailsClearly()
    {
        await using var mock = await RunningMock.StartAsync();
        await using var services = ApiServices.Build(mock.BaseUrl, new ApiCredentials("demo", "wrong"), verbose: false, CapturingLoggerProvider.Replace(new()));

        var ex = await Assert.ThrowsAsync<LoginFailedException>(() => services.GetRequiredService<RecordExporter>().ExportAsync(TimeSpan.Zero, default));

        Assert.Contains("run set-credentials again", ex.Message);
        Assert.AreEqual(1, mock.Stats.FailedLogins);
        Assert.AreEqual(0, mock.Stats.ApiRequests);
    }

    [TestMethod]
    public async Task VerboseLogsNeverContainThePasswordOrToken()
    {
        await using var mock = await RunningMock.StartAsync(o => o.InvalidateEvery = 4);
        var logs = new CapturingLoggerProvider();
        await using var services = ApiServices.Build(mock.BaseUrl, Demo, verbose: true, CapturingLoggerProvider.Replace(logs));

        await services.GetRequiredService<RecordExporter>().ExportAsync(TimeSpan.Zero, default);

        var text = logs.AllText;
        Assert.Contains("Authorization: *", text, "Header logging should be on and redacted.");
        Assert.DoesNotContain("demo-password", text);
        Assert.DoesNotContain("eyJ", text, "No JWT (they start with eyJ) should be logged.");
    }
}

[TestClass]
public sealed class JiraExportEndToEndTests
{
    private const string Pat = "demo-pat-0000";

    [TestMethod]
    public async Task GetsTheSignedInUser()
    {
        await using var mock = await RunningMock.StartAsync();
        await using var services = JiraServices.Build(mock.BaseUrl, Pat, verbose: false, CapturingLoggerProvider.Replace(new()));

        var user = await services.GetRequiredService<JiraClient>().GetMyselfAsync(default);

        Assert.AreEqual("Demo User", user.DisplayName);
    }

    [TestMethod]
    public async Task ExportsEveryIssueAcrossPages()
    {
        await using var mock = await RunningMock.StartAsync();
        await using var services = JiraServices.Build(mock.BaseUrl, Pat, verbose: false, CapturingLoggerProvider.Replace(new()));

        var issues = await services.GetRequiredService<JiraClient>().SearchAsync("order by key", TimeSpan.Zero, default);

        Assert.HasCount(120, issues);
        Assert.AreEqual("DEMO-1", issues[0].GetProperty("key").GetString());
        Assert.AreEqual("DEMO-120", issues[^1].GetProperty("key").GetString());
        Assert.AreEqual(3, mock.Stats.JiraRequests); // 50 + 50 + 20
    }

    [TestMethod]
    public async Task WrongPatFailsClearly()
    {
        await using var mock = await RunningMock.StartAsync();
        await using var services = JiraServices.Build(mock.BaseUrl, "revoked-pat", verbose: false, CapturingLoggerProvider.Replace(new()));

        var ex = await Assert.ThrowsAsync<JiraAuthorizationException>(() => services.GetRequiredService<JiraClient>().SearchAsync("x", TimeSpan.Zero, default));

        Assert.Contains("run set-credentials", ex.Message);
        Assert.AreEqual(1, mock.Stats.RejectedPats);
    }

    [TestMethod]
    public async Task VerboseLogsNeverContainThePat()
    {
        await using var mock = await RunningMock.StartAsync();
        var logs = new CapturingLoggerProvider();
        await using var services = JiraServices.Build(mock.BaseUrl, Pat, verbose: true, CapturingLoggerProvider.Replace(logs));

        await services.GetRequiredService<JiraClient>().SearchAsync("order by key", TimeSpan.Zero, default);

        Assert.Contains("Authorization: *", logs.AllText, "Header logging should be on and redacted.");
        Assert.DoesNotContain(Pat, logs.AllText);
    }
}
