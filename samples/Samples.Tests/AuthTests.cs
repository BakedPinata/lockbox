using System.Net;
using System.Text;
using ApiExportSample.Auth;
using Microsoft.Extensions.Logging.Abstractions;
using MockServer;

namespace Samples.Tests;

[TestClass]
public sealed class AccessTokenTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);

    [TestMethod]
    public void ReadsExpiryFromTheJwt()
    {
        var jwt = new MockJwt(new ManualTimeProvider(Now)).Issue("demo", TimeSpan.FromMinutes(5));

        Assert.AreEqual(Now.AddMinutes(5), AccessToken.ReadJwtExpiry(jwt));
    }

    [TestMethod]
    [DataRow("not-a-jwt")]
    [DataRow("a.b.c")]
    [DataRow("e30.e30.sig")] // {} payload: no exp
    [DataRow("e30.eyJleHAiOiJzb29uIn0.sig")] // exp is a string
    public void UnreadableExpiryIsNull(string token) => Assert.IsNull(AccessToken.ReadJwtExpiry(token));

    [TestMethod]
    public void FallsBackToExpiresIn()
    {
        Assert.AreEqual(Now.AddSeconds(30), AccessToken.Create("opaque-token", Now, 30).ExpiresAt);
        Assert.IsNull(AccessToken.Create("opaque-token", Now, null).ExpiresAt);
        Assert.IsNull(AccessToken.Create("opaque-token", Now, 0).ExpiresAt);
    }

    [TestMethod]
    public void JwtExpiryWinsOverExpiresIn()
    {
        var jwt = new MockJwt(new ManualTimeProvider(Now)).Issue("demo", TimeSpan.FromMinutes(5));

        Assert.AreEqual(Now.AddMinutes(5), AccessToken.Create(jwt, Now, 30).ExpiresAt);
    }

    [TestMethod]
    [DataRow(20, 4)]      // a fifth of the lifetime...
    [DataRow(3600, 60)]   // ...but at most a minute
    public void RenewalMargin(int lifetimeSeconds, int marginSeconds)
    {
        var token = new AccessToken("t", Now, Now.AddSeconds(lifetimeSeconds));

        Assert.AreEqual(TimeSpan.FromSeconds(marginSeconds), token.RenewalMargin);
        Assert.IsFalse(token.NeedsRenewal(Now.AddSeconds(lifetimeSeconds - marginSeconds - 1)));
        Assert.IsTrue(token.NeedsRenewal(Now.AddSeconds(lifetimeSeconds - marginSeconds)));
    }

    [TestMethod]
    public void TokenWithoutExpiryNeverNeedsRenewal() =>
        Assert.IsFalse(new AccessToken("t", Now, null).NeedsRenewal(Now.AddYears(1)));

    [TestMethod]
    public void ToStringHidesTheValue()
    {
        Assert.DoesNotContain("secret-jwt", new AccessToken("secret-jwt", Now, Now.AddHours(1)).ToString());
        Assert.DoesNotContain("hunter2", new ApiCredentials("alice", "hunter2").ToString());
    }
}

[TestClass]
public sealed class TokenProviderTests
{
    private readonly ManualTimeProvider _time = new(new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));
    private int _logins;

    private TokenProvider Provider(TimeSpan? lifetime = null, Func<Task>? beforeReturn = null) => new(
        async _ =>
        {
            var n = Interlocked.Increment(ref _logins);
            if (beforeReturn is not null)
            {
                await beforeReturn();
            }

            var now = _time.GetUtcNow();
            return new AccessToken($"token-{n}", now, now + (lifetime ?? TimeSpan.FromSeconds(100)));
        },
        _time,
        NullLogger<TokenProvider>.Instance);

    [TestMethod]
    public async Task LogsInOnceAndCaches()
    {
        using var provider = Provider();

        Assert.AreEqual("token-1", await provider.GetTokenAsync(default));
        Assert.AreEqual("token-1", await provider.GetTokenAsync(default));
        Assert.AreEqual(1, _logins);
    }

    [TestMethod]
    public async Task LogsInAgainShortlyBeforeExpiry()
    {
        using var provider = Provider(TimeSpan.FromSeconds(100)); // renewal margin 20 s
        await provider.GetTokenAsync(default);

        _time.Advance(TimeSpan.FromSeconds(79));
        Assert.AreEqual("token-1", await provider.GetTokenAsync(default));

        _time.Advance(TimeSpan.FromSeconds(1));
        Assert.AreEqual("token-2", await provider.GetTokenAsync(default));
    }

    [TestMethod]
    public async Task InvalidateForgetsTheRejectedToken()
    {
        using var provider = Provider();
        var first = await provider.GetTokenAsync(default);

        provider.Invalidate(first);

        Assert.AreEqual("token-2", await provider.GetTokenAsync(default));
    }

    [TestMethod]
    public async Task InvalidatingAnOldTokenKeepsTheNewOne()
    {
        using var provider = Provider();
        var first = await provider.GetTokenAsync(default);
        provider.Invalidate(first);
        var second = await provider.GetTokenAsync(default);

        provider.Invalidate(first); // A slow request reporting the old token's 401.

        Assert.AreEqual(second, await provider.GetTokenAsync(default));
        Assert.AreEqual(2, _logins);
    }

    [TestMethod]
    public async Task ConcurrentCallersShareOneLogin()
    {
        var release = new TaskCompletionSource();
        using var provider = Provider(beforeReturn: () => release.Task);

        var callers = Enumerable.Range(0, 20).Select(_ => Task.Run(() => provider.GetTokenAsync(default))).ToList();
        await Task.Delay(100);
        release.SetResult();
        var tokens = await Task.WhenAll(callers);

        Assert.AreEqual(1, _logins);
        Assert.IsTrue(tokens.All(t => t == "token-1"));
    }

    [TestMethod]
    public async Task FailedLoginIsRetriedOnTheNextCall()
    {
        var fail = true;
        using var provider = new TokenProvider(
            _ => fail ? throw new LoginFailedException("nope") : Task.FromResult(new AccessToken("ok", _time.GetUtcNow(), null)),
            _time,
            NullLogger<TokenProvider>.Instance);

        await Assert.ThrowsAsync<LoginFailedException>(() => provider.GetTokenAsync(default));
        fail = false;

        Assert.AreEqual("ok", await provider.GetTokenAsync(default));
    }
}

[TestClass]
public sealed class BearerTokenHandlerTests
{
    private int _logins;

    private (HttpClient Client, ScriptedHandler Inner, TokenProvider Tokens) Create(params HttpStatusCode[] responses)
    {
        var time = new ManualTimeProvider(DateTimeOffset.UnixEpoch);
        var tokens = new TokenProvider(
            _ => Task.FromResult(new AccessToken($"token-{Interlocked.Increment(ref _logins)}", time.GetUtcNow(), null)),
            time,
            NullLogger<TokenProvider>.Instance);
        var inner = new ScriptedHandler(responses);
        var handler = new BearerTokenHandler(tokens, NullLogger<BearerTokenHandler>.Instance) { InnerHandler = inner };
        return (new HttpClient(handler) { BaseAddress = new Uri("https://api.example/") }, inner, tokens);
    }

    [TestMethod]
    public async Task AddsTheBearerToken()
    {
        var (client, inner, tokens) = Create(HttpStatusCode.OK, HttpStatusCode.OK);
        using (client)
        using (tokens)
        {
            await client.GetAsync("a");
            await client.GetAsync("b");
        }

        CollectionAssert.AreEqual(new[] { "Bearer token-1", "Bearer token-1" }, inner.Sent.Select(s => s.Authorization).ToArray());
        Assert.AreEqual(1, _logins);
    }

    [TestMethod]
    public async Task On401LogsInAgainAndRetriesOnce()
    {
        var (client, inner, tokens) = Create(HttpStatusCode.Unauthorized, HttpStatusCode.OK);
        using (client)
        using (tokens)
        {
            using var response = await client.GetAsync("a");
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        }

        CollectionAssert.AreEqual(new[] { "Bearer token-1", "Bearer token-2" }, inner.Sent.Select(s => s.Authorization).ToArray());
    }

    [TestMethod]
    public async Task ASecond401IsReturnedWithoutLooping()
    {
        var (client, inner, tokens) = Create(HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized);
        using (client)
        using (tokens)
        {
            using var response = await client.GetAsync("a");
            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        Assert.HasCount(2, inner.Sent);
        Assert.AreEqual(2, _logins);
    }

    [TestMethod]
    public async Task OtherFailuresAreNotRetried()
    {
        var (client, inner, tokens) = Create(HttpStatusCode.Forbidden);
        using (client)
        using (tokens)
        {
            using var response = await client.GetAsync("a");
            Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
        }

        Assert.HasCount(1, inner.Sent);
    }

    [TestMethod]
    public async Task RequestBodiesAreSentAgainOnRetry()
    {
        var (client, inner, tokens) = Create(HttpStatusCode.Unauthorized, HttpStatusCode.OK);
        using (client)
        using (tokens)
        {
            using var content = new StringContent("{\"x\":1}", Encoding.UTF8, "application/json");
            using var response = await client.PostAsync("a", content);
        }

        CollectionAssert.AreEqual(new[] { "{\"x\":1}", "{\"x\":1}" }, inner.Sent.Select(s => s.Body).ToArray());
    }
}
