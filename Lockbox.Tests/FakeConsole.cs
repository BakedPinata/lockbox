using Lockbox.Cli;

namespace Lockbox.Tests;

/// <summary>
/// Scripted console input. Each input says whether it expects a visible or a masked read, so tests
/// fail if a secret would be read with echo on. Running out of input behaves like end of input.
/// </summary>
internal sealed class FakeConsole(params FakeConsole.Input[] inputs) : IConsoleIO
{
    private readonly Queue<Input> _inputs = new(inputs);

    public StringWriter OutWriter { get; } = new();

    public StringWriter ErrorWriter { get; } = new();

    public TextWriter Out => OutWriter;

    public TextWriter Error => ErrorWriter;

    public string Output => OutWriter.ToString();

    public string Errors => ErrorWriter.ToString();

    public string AllText => Output + Errors;

    public int Remaining => _inputs.Count;

    public string? ReadLine() => Next(masked: false);

    public string? ReadMasked() => Next(masked: true);

    private string? Next(bool masked)
    {
        if (!_inputs.TryDequeue(out var input))
        {
            return null;
        }

        if (input.Masked != masked)
        {
            throw new AssertFailedException(
                $"Expected a {(input.Masked ? "masked" : "visible")} read but the command did a {(masked ? "masked" : "visible")} one. Output so far:\n{Output}");
        }

        return input.Value;
    }

    public sealed record Input(string? Value, bool Masked);

    public static Input Line(string? value) => new(value, Masked: false);

    public static Input Masked(string? value) => new(value, Masked: true);
}
