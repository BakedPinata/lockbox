using System.Globalization;

namespace SampleSupport;

/// <summary>Options for a sample's <c>export</c> command.</summary>
public sealed class ExportOptions
{
    /// <summary>Help text for the shared export options.</summary>
    public static string UsageText(string defaultOutput) => $"""
        Export options:
          --out <file>             Where to write the export (default: {defaultOutput})
          --delay-ms <n>           Pause between pages, to make a long export (default 0)
          --verbose                Log HTTP traffic (header values are redacted)
          --secrets-path <path>    Use this secrets file
        """;

    public required string OutputPath { get; init; }

    public TimeSpan Delay { get; init; }

    public bool Verbose { get; init; }

    /// <summary>Values of the app's own options, keyed by option name.</summary>
    public IReadOnlyDictionary<string, string> Extra { get; init; } = new Dictionary<string, string>();

    /// <summary>Parses the arguments after <c>export</c>.</summary>
    /// <param name="args">The arguments after the command name.</param>
    /// <param name="defaultOutput">The default for <c>--out</c>.</param>
    /// <param name="extraOptions">The app's own options that take a value, for example <c>--jql</c>.</param>
    /// <exception cref="ArgumentException">An option is unknown or missing its value.</exception>
    public static ExportOptions Parse(IReadOnlyList<string> args, string defaultOutput, params string[] extraOptions)
    {
        var output = defaultOutput;
        var delay = TimeSpan.Zero;
        var verbose = false;
        var extra = new Dictionary<string, string>(StringComparer.Ordinal);

        for (var i = 0; i < args.Count; i++)
        {
            var arg = args[i];
            string Value() => i + 1 < args.Count && !args[i + 1].StartsWith("--", StringComparison.Ordinal)
                ? args[++i]
                : throw new ArgumentException($"{arg} needs a value.");

            if (arg == "--out")
            {
                output = Value();
            }
            else if (arg == "--delay-ms")
            {
                var text = Value();
                delay = int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var ms)
                    ? TimeSpan.FromMilliseconds(ms)
                    : throw new ArgumentException("--delay-ms needs a whole number of milliseconds.");
            }
            else if (arg == "--verbose")
            {
                verbose = true;
            }
            else if (arg == "--secrets-path")
            {
                _ = Value(); // Read by CredentialCommands.CreateStore.
            }
            else if (arg.StartsWith("--secrets-path=", StringComparison.Ordinal))
            {
                // Read by CredentialCommands.CreateStore.
            }
            else if (extraOptions.Contains(arg))
            {
                extra[arg] = Value();
            }
            else
            {
                // Don't echo the argument: someone may have tried to pass a secret.
                throw new ArgumentException($"Unexpected argument at position {i + 2}. Run with --help for usage.");
            }
        }

        return new ExportOptions { OutputPath = Path.GetFullPath(output), Delay = delay, Verbose = verbose, Extra = extra };
    }
}
