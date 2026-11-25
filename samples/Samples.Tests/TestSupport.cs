using System.Collections.Concurrent;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using MockServer;

namespace Samples.Tests;

/// <summary>Runs the mock server on a free loopback port for one test.</summary>
internal sealed class RunningMock : IAsyncDisposable
{
    private RunningMock(MockHost host, Uri baseUrl)
    {
        Host = host;
        BaseUrl = baseUrl;
    }

    public MockHost Host { get; }

    public MockStats Stats => Host.Stats;

    public Uri BaseUrl { get; }

    public static async Task<RunningMock> StartAsync(Action<MockOptions>? configure = null, TimeProvider? time = null)
    {
        var options = new MockOptions { Url = "http://127.0.0.1:0" };
        configure?.Invoke(options);
        var host = MockServerApp.Build(options, time);
        await host.App.StartAsync();
        var address = host.App.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        return new RunningMock(host, new Uri(address + "/"));
    }

    public async ValueTask DisposeAsync()
    {
        await Host.App.StopAsync();
        await Host.App.DisposeAsync();
    }
}

/// <summary>A clock that the test (or a timer wait) moves forward.</summary>
internal class ManualTimeProvider(DateTimeOffset start) : TimeProvider
{
    private readonly Lock _sync = new();
    private DateTimeOffset _now = start;

    public override DateTimeOffset GetUtcNow()
    {
        lock (_sync)
        {
            return _now;
        }
    }

    public void Advance(TimeSpan by)
    {
        lock (_sync)
        {
            _now += by;
        }
    }
}

/// <summary>
/// A clock where waiting is instant: a timer advances the clock by its due time and then fires. Lets a test run
/// an export with long pauses between pages, sharing the clock with the mock server so tokens really expire.
/// </summary>
internal sealed class JumpingTimeProvider(DateTimeOffset start) : ManualTimeProvider(start)
{
    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new JumpTimer();
        if (dueTime != Timeout.InfiniteTimeSpan)
        {
            Advance(dueTime);
            ThreadPool.QueueUserWorkItem(_ =>
            {
                if (!timer.Disposed)
                {
                    callback(state);
                }
            });
        }

        return timer;
    }

    private sealed class JumpTimer : ITimer
    {
        public bool Disposed { get; private set; }

        public bool Change(TimeSpan dueTime, TimeSpan period) => false;

        public void Dispose() => Disposed = true;

        public ValueTask DisposeAsync()
        {
            Disposed = true;
            return ValueTask.CompletedTask;
        }
    }
}

/// <summary>Collects every log message, for checking that secrets never reach the logs.</summary>
internal sealed class CapturingLoggerProvider : ILoggerProvider
{
    private readonly ConcurrentQueue<string> _messages = new();

    public IReadOnlyCollection<string> Messages => _messages;

    public string AllText => string.Join('\n', _messages);

    public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, _messages);

    public void Dispose()
    {
    }

    public static Action<ILoggingBuilder> Replace(CapturingLoggerProvider provider, LogLevel minimum = LogLevel.Trace) => logging =>
    {
        logging.ClearProviders();
        logging.AddProvider(provider);
        logging.SetMinimumLevel(minimum);
    };

    private sealed class CapturingLogger(string category, ConcurrentQueue<string> messages) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            messages.Enqueue($"{logLevel} {category}: {formatter(state, exception)}");
    }
}

/// <summary>An inner handler that returns scripted status codes and records what was sent.</summary>
internal sealed class ScriptedHandler(params System.Net.HttpStatusCode[] responses) : HttpMessageHandler
{
    private readonly Queue<System.Net.HttpStatusCode> _responses = new(responses);

    public List<(string? Authorization, string? Body)> Sent { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
        Sent.Add((request.Headers.Authorization?.ToString(), body));
        return new HttpResponseMessage(_responses.Dequeue()) { RequestMessage = request };
    }
}
