namespace SampleSupport;

/// <summary>A cancellation token that Ctrl+C triggers, so an export stops cleanly.</summary>
public sealed class ConsoleCancellation : IDisposable
{
    private readonly CancellationTokenSource _source = new();

    public ConsoleCancellation() => Console.CancelKeyPress += OnCancelKeyPress;

    public CancellationToken Token => _source.Token;

    public void Dispose()
    {
        Console.CancelKeyPress -= OnCancelKeyPress;
        _source.Dispose();
    }

    private void OnCancelKeyPress(object? sender, ConsoleCancelEventArgs e)
    {
        e.Cancel = true;
        _source.Cancel();
    }
}
