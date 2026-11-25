using System.Text;

namespace Lockbox.Cli;

/// <summary>The console operations the commands need, so they can be tested without a terminal.</summary>
internal interface IConsoleIO
{
    TextWriter Out { get; }

    TextWriter Error { get; }

    /// <summary>Reads a visible line, or <see langword="null"/> at end of input.</summary>
    string? ReadLine();

    /// <summary>Reads a line without echoing it, or <see langword="null"/> if cancelled or at end of input.</summary>
    string? ReadMasked();
}

internal sealed class SystemConsoleIO : IConsoleIO
{
    public static readonly SystemConsoleIO Instance = new();

    private SystemConsoleIO()
    {
    }

    public TextWriter Out => Console.Out;

    public TextWriter Error => Console.Error;

    public string? ReadLine() => Console.ReadLine();

    // Redirected input (for example `--password-stdin`-style provisioning scripts) has no keys to read
    // and nothing is echoed, so a plain line read is used.
    public string? ReadMasked() =>
        Console.IsInputRedirected ? Console.ReadLine() : MaskedInput.Read(() => Console.ReadKey(intercept: true), Console.Out);
}

internal static class MaskedInput
{
    /// <summary>
    /// Reads keys until Enter, echoing <c>*</c> for each character. Backspace deletes, Escape cancels
    /// (returns <see langword="null"/>), and other control keys are ignored.
    /// </summary>
    public static string? Read(Func<ConsoleKeyInfo> readKey, TextWriter echo)
    {
        var value = new StringBuilder();
        while (true)
        {
            var key = readKey();
            switch (key.Key)
            {
                case ConsoleKey.Enter:
                    echo.WriteLine();
                    return value.ToString();

                case ConsoleKey.Escape:
                    echo.WriteLine();
                    return null;

                case ConsoleKey.Backspace:
                    if (value.Length > 0)
                    {
                        var remove = value.Length >= 2 && char.IsSurrogatePair(value[^2], value[^1]) ? 2 : 1;
                        value.Length -= remove;
                        echo.Write("\b \b");
                    }

                    break;

                default:
                    if (!char.IsControl(key.KeyChar) && key.KeyChar != '\0')
                    {
                        value.Append(key.KeyChar);

                        // One '*' per visible character: the high half of a surrogate pair echoes, the low half doesn't.
                        if (!char.IsLowSurrogate(key.KeyChar))
                        {
                            echo.Write('*');
                        }
                    }

                    break;
            }
        }
    }
}
